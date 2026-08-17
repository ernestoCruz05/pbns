// pbns-attestation-fixturegen deterministically rebuilds public attestation fixtures.
package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	modern "github.com/google/go-tpm/tpm2"

	"pbns.local/gateway/internal/attestation"
	"pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/model"
)

const eventSeparator uint32 = 4

type metadata struct {
	Version         int                           `json:"version"`
	Domain          string                        `json:"domain"`
	ProtocolVersion uint64                        `json:"protocol_version"`
	Service         uint64                        `json:"service"`
	RequestID       string                        `json:"request_id_hex"`
	Nonce           string                        `json:"nonce_hex"`
	IssuedAt        uint64                        `json:"issued_at_unix_ns"`
	ExpiresAt       uint64                        `json:"expires_at_unix_ns"`
	IdentityCOSE    string                        `json:"identity_cose_hex"`
	BoardDigest     string                        `json:"board_model_digest_hex"`
	PCIDigest       string                        `json:"pci_digest_hex"`
	DBDigest        string                        `json:"db_digest_hex"`
	DBXDigest       string                        `json:"dbx_digest_hex"`
	FirmwareVendor  string                        `json:"firmware_vendor"`
	FirmwareVersion string                        `json:"firmware_version"`
	CPUClass        string                        `json:"cpu_class"`
	MemoryMiB       uint64                        `json:"memory_mib"`
	StorageGiB      uint64                        `json:"storage_gib"`
	BlockDevices    uint64                        `json:"block_devices"`
	SecureBoot      bool                          `json:"secure_boot"`
	SetupMode       bool                          `json:"setup_mode"`
	TPMPresent      bool                          `json:"tpm_present"`
	TPMManufacturer uint64                        `json:"tpm_manufacturer"`
	TPMFirmware     uint64                        `json:"tpm_firmware_version"`
	TPMActiveBanks  []uint64                      `json:"tpm_active_banks"`
	Versions        attestation.VersionsInventory `json:"versions"`
	Outcomes        map[uint64]uint64             `json:"outcomes"`
	Timings         map[uint64]uint64             `json:"timings"`
	PriorLoader     uint64                        `json:"prior_loader_status"`
	RecipientKID    string                        `json:"recipient_kid_hex"`
	AKReference     string                        `json:"ak_reference_hex"`
	EKPublic        string                        `json:"ek_public_hex"`
	Assurance       model.Assurance               `json:"assurance"`
	EnrolledAt      int64                         `json:"enrolled_at_unix"`
	BaselineVersion uint64                        `json:"baseline_version"`
	PCRSelection    []uint64                      `json:"pcr_selection"`
	Events          []eventDef                    `json:"events"`
	Inventory       baseline.InventoryRule        `json:"inventory_drift"`
}
type eventDef struct {
	PCR  uint64 `json:"pcr"`
	Type uint32 `json:"type"`
	Data string `json:"data_hex"`
}
type fixture struct {
	Host      model.HostRecord      `cbor:"1,keyasint"`
	Challenge attestation.Challenge `cbor:"2,keyasint"`
	Evidence  attestation.Evidence  `cbor:"3,keyasint"`
	Baseline  []byte                `cbor:"4,keyasint"`
}
type inputs struct {
	m                                    metadata
	source, out                          string
	selection                            model.PCRSelection
	eventlog                             []byte
	pcr                                  map[uint64][]byte
	request                              [16]byte
	nonce                                [32]byte
	identity                             []byte
	board, pci, db, dbx                  [32]byte
	inventory                            attestation.InventoryReport
	report, selectionDigest, eventDigest [32]byte
	qualifying                           []byte
}

func die(err error) { fmt.Fprintln(os.Stderr, "fixturegen:", err); os.Exit(1) }
func main() {
	source := flag.String("source", "", "metadata/input source directory")
	out := flag.String("out", "", "separate output directory")
	prepareOnly := flag.Bool("prepare", false, "emit pre-Quote deterministic inputs only")
	flag.Parse()
	if *source == "" || *out == "" {
		die(errors.New("-source and -out are required"))
	}
	var err error
	if *prepareOnly {
		err = prepare(*source, *out)
	} else {
		err = generate(*source, *out)
	}
	if err != nil {
		die(err)
	}
}

func hx(value string, n int) ([]byte, error) {
	b, e := hex.DecodeString(value)
	if e != nil || (n != 0 && len(b) != n) {
		return nil, fmt.Errorf("invalid %d-byte hex", n)
	}
	return b, nil
}
func d32(value string) ([32]byte, error) {
	var r [32]byte
	b, e := hx(value, 32)
	copy(r[:], b)
	return r, e
}
func pathExisting(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(filepath.Clean(absolute))
}
func canonicalOutput(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	if _, err = os.Lstat(absolute); err == nil {
		return pathExisting(absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	tail := []string{}
	cursor := absolute
	for {
		parent := filepath.Dir(cursor)
		if parent == cursor {
			return "", errors.New("no existing output ancestor")
		}
		tail = append([]string{filepath.Base(cursor)}, tail...)
		cursor = parent
		if _, err = os.Lstat(cursor); err == nil {
			base, err := pathExisting(cursor)
			if err != nil {
				return "", err
			}
			return filepath.Join(append([]string{base}, tail...)...), nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
}
func within(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
func separatePaths(source, out string) (string, string, error) {
	src, err := pathExisting(source)
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(src)
	if err != nil || !info.IsDir() {
		return "", "", errors.New("source must be an existing directory")
	}
	dst, err := canonicalOutput(out)
	if err != nil {
		return "", "", err
	}
	if src == dst || within(src, dst) || within(dst, src) {
		return "", "", errors.New("source and output must be separate sibling trees")
	}
	return src, dst, nil
}

func rejectDuplicateJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("metadata has multiple JSON values")
		}
		return fmt.Errorf("metadata trailing JSON: %w", err)
	}
	return nil
}
func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if seen[key] {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			seen[key] = true
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
func decodeMetadata(source string) (metadata, error) {
	raw, err := os.ReadFile(filepath.Join(source, "metadata.json"))
	if err != nil {
		return metadata{}, err
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return metadata{}, err
	}
	var m metadata
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return metadata{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return metadata{}, errors.New("metadata has multiple JSON values")
		}
		return metadata{}, fmt.Errorf("metadata trailing JSON: %w", err)
	}
	if err := validateMetadata(m); err != nil {
		return metadata{}, err
	}
	return m, nil
}
func validateMetadata(m metadata) error {
	expected := []uint64{0, 2, 4, 7}
	if m.Version != 1 || m.Domain != attestation.Domain || m.ProtocolVersion != 1 || m.Service != attestation.ServiceAttestation || !equalU64(m.PCRSelection, expected) || len(m.Events) != len(expected) || m.IssuedAt == 0 || m.ExpiresAt <= m.IssuedAt || m.ExpiresAt > math.MaxInt64 || !m.SecureBoot || m.SetupMode || !m.TPMPresent || m.BaselineVersion != 1 || m.Assurance != model.AssuranceTPMUnverified || m.EnrolledAt <= 0 || m.TPMManufacturer > 0xffffffff || m.TPMFirmware > 0xffffffff {
		return errors.New("invalid fixed fixture metadata")
	}
	if len(m.TPMActiveBanks) == 0 || len(m.TPMActiveBanks) > 8 {
		return errors.New("invalid active banks")
	}
	var previousBank uint64
	hasSHA256 := false
	for i, bank := range m.TPMActiveBanks {
		if bank > 0xffffffff || (i > 0 && bank <= previousBank) {
			return errors.New("invalid active banks")
		}
		if bank == 11 {
			hasSHA256 = true
		}
		previousBank = bank
	}
	if !hasSHA256 {
		return errors.New("fixture requires SHA-256 active bank")
	}
	if _, err := hx(m.RequestID, 16); err != nil {
		return err
	}
	if _, err := hx(m.Nonce, 32); err != nil {
		return err
	}
	for _, v := range []string{m.IdentityCOSE, m.RecipientKID, m.AKReference, m.EKPublic} {
		if b, e := hx(v, 0); e != nil || len(b) == 0 {
			return errors.New("invalid mandatory metadata hex")
		}
	}
	for _, v := range []string{m.BoardDigest, m.PCIDigest, m.DBDigest, m.DBXDigest} {
		b, e := d32(v)
		if e != nil || zero32(b) {
			return errors.New("invalid mandatory digest")
		}
	}
	for _, value := range []string{m.FirmwareVendor, m.FirmwareVersion, m.CPUClass} {
		if !validInventoryText(value) {
			return errors.New("invalid inventory text")
		}
	}
	if m.BlockDevices > 64 || len(m.Outcomes) != 5 || m.Timings == nil || len(m.Timings) > 8 || m.Versions.PBNS > 0xffffffff || m.Versions.Pico > 0xffffffff || m.Versions.Gateway > 0xffffffff {
		return errors.New("invalid inventory ranges")
	}
	for i := uint64(1); i <= 5; i++ {
		value, found := m.Outcomes[i]
		if !found || value > 5 {
			return errors.New("invalid outcomes")
		}
	}
	for key := range m.Outcomes {
		if key == 0 || key > 5 {
			return errors.New("invalid outcomes")
		}
	}
	for key := range m.Timings {
		if key == 0 {
			return errors.New("invalid timing")
		}
	}
	for i, pcr := range expected {
		e := m.Events[i]
		data, err := hx(e.Data, 0)
		if err != nil || e.PCR != pcr || len(data) == 0 {
			return errors.New("invalid event selection/order")
		}
		if pcr == 2 && (e.Type != eventSeparator || !bytes.Equal(data, []byte{0, 0, 0, 0})) {
			return errors.New("invalid PCR2 separator")
		}
		if pcr != 2 && e.Type == eventSeparator {
			return errors.New("unexpected separator")
		}
	}
	return nil
}
func validInventoryText(value string) bool {
	if len(value) == 0 || len(value) > 96 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x20 || character > 0x7e || (character == ' ' && (index == 0 || index+1 == len(value) || value[index-1] == ' ')) {
			return false
		}
	}
	return true
}
func equalU64(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func zero32(v [32]byte) bool {
	var x byte
	for _, b := range v {
		x |= b
	}
	return x == 0
}
func selectionFor(m metadata) model.PCRSelection {
	return model.PCRSelection{{Algorithm: 0x000b, Indices: append([]uint64(nil), m.PCRSelection...)}}
}

func load(source, out string) (inputs, error) {
	src, dst, err := separatePaths(source, out)
	if err != nil {
		return inputs{}, err
	}
	m, err := decodeMetadata(src)
	if err != nil {
		return inputs{}, err
	}
	eventlog, pcr, err := buildLog(m)
	if err != nil {
		return inputs{}, err
	}
	req, err := hx(m.RequestID, 16)
	if err != nil {
		return inputs{}, err
	}
	nonce, err := hx(m.Nonce, 32)
	if err != nil {
		return inputs{}, err
	}
	identity, err := hx(m.IdentityCOSE, 0)
	if err != nil {
		return inputs{}, err
	}
	board, err := d32(m.BoardDigest)
	if err != nil {
		return inputs{}, err
	}
	pci, err := d32(m.PCIDigest)
	if err != nil {
		return inputs{}, err
	}
	db, err := d32(m.DBDigest)
	if err != nil {
		return inputs{}, err
	}
	dbx, err := d32(m.DBXDigest)
	if err != nil {
		return inputs{}, err
	}
	var request [16]byte
	copy(request[:], req)
	var n [32]byte
	copy(n[:], nonce)
	selection := selectionFor(m)
	canonical, _ := cbor.CanonicalEncOptions().EncMode()
	selectionBytes, _ := canonical.Marshal(selection)
	sd := sha256.Sum256(selectionBytes)
	ed := sha256.Sum256(eventlog)
	fingerprint := sha256.Sum256(identity)
	inventory := attestation.InventoryReport{HostFingerprint: fingerprint, BoardModelDigest: board, FirmwareVendor: m.FirmwareVendor, FirmwareVersion: m.FirmwareVersion, CPUClass: m.CPUClass, MemoryMiB: m.MemoryMiB, PCIDigest: pci, Storage: attestation.StorageInventory{BlockDeviceCount: m.BlockDevices, CapacityGiB: m.StorageGiB}, SecureBoot: m.SecureBoot, SetupMode: m.SetupMode, DBDigest: db, DBXDigest: dbx, TPM: attestation.TPMInventory{Present: m.TPMPresent, Manufacturer: m.TPMManufacturer, FirmwareVersion: m.TPMFirmware, ActiveBanks: append([]uint64(nil), m.TPMActiveBanks...)}, Versions: m.Versions, Outcomes: m.Outcomes, Timings: m.Timings, PriorLoaderStatus: m.PriorLoader}
	encodedInventory, _ := canonical.Marshal(inventory)
	rd := sha256.Sum256(encodedInventory)
	return inputs{m: m, source: src, out: dst, selection: selection, eventlog: eventlog, pcr: pcr, request: request, nonce: n, identity: identity, board: board, pci: pci, db: db, dbx: dbx, inventory: inventory, report: rd, selectionDigest: sd, eventDigest: ed, qualifying: qualifying(request, n, rd, sd, ed)}, nil
}
func prepare(source, out string) error {
	in, err := load(source, out)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(in.out, 0700); err != nil {
		return err
	}
	return writeOutputs(in, false, nil, nil, nil)
}
func generate(source, out string) error {
	in, err := load(source, out)
	if err != nil {
		return err
	}
	ak, err := readCanonicalAK(filepath.Join(in.source, "ak.pub"), false)
	if err != nil {
		return err
	}
	rsa, err := readCanonicalAK(filepath.Join(in.source, "ak-rsa.pub"), true)
	if err != nil {
		return err
	}
	_ = rsa
	name, err := os.ReadFile(filepath.Join(in.source, "ak.name"))
	if err != nil {
		return err
	}
	quote, err := os.ReadFile(filepath.Join(in.source, "quote.bin"))
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(filepath.Join(in.source, "signature.bin"))
	if err != nil {
		return err
	}
	if !canonicalQuoteEncoding(quote) {
		return errors.New("noncanonical quote")
	}
	if !canonicalSignatureEncoding(signature) {
		return errors.New("noncanonical signature")
	}
	computed, err := ak.public.Name()
	if err != nil {
		return err
	}
	encodedName, err := computed.Digest.Encode()
	if err != nil || !bytes.Equal(encodedName, name) {
		return errors.New("AK name mismatch")
	}
	att, err := tpm2.DecodeAttestationData(quote)
	if err != nil || att.AttestedQuoteInfo == nil || att.Type != tpm2.TagAttestQuote || !bytes.Equal(att.ExtraData, in.qualifying) {
		return errors.New("quote metadata binding mismatch")
	}
	if !selectionMatch(att.AttestedQuoteInfo.PCRSelection, in.selection) {
		return errors.New("quote selection mismatch")
	}
	submitted, pcrs, joined := submittedPCRs(in)
	digest := sha256.Sum256(joined)
	if !bytes.Equal(att.AttestedQuoteInfo.PCRDigest, digest[:]) {
		return errors.New("quote PCR digest mismatch")
	}
	akVerifier, err := attest.ParseAKPublic(ak.inner)
	if err != nil {
		return err
	}
	if err = akVerifier.Verify(attest.Quote{Quote: quote, Signature: signature}, pcrs, in.qualifying); err != nil {
		return fmt.Errorf("quote signature: %w", err)
	}
	recipient, err := hx(in.m.RecipientKID, 0)
	if err != nil {
		return err
	}
	reference, err := hx(in.m.AKReference, 0)
	if err != nil {
		return err
	}
	ek, err := hx(in.m.EKPublic, 0)
	if err != nil {
		return err
	}
	evidence := attestation.Evidence{Context: attestation.Context{Domain: in.m.Domain, Version: in.m.ProtocolVersion, Service: in.m.Service, RequestID: in.request, HostFingerprint: sha256.Sum256(in.identity), Nonce: in.nonce, IssuedAtUnixNS: in.m.IssuedAt, ExpiresAtUnixNS: in.m.ExpiresAt, Body: []byte{}}, Inventory: in.inventory, Quote: quote, QuoteSignature: signature, PCRValues: submitted, EventLog: in.eventlog, AKName: name, AKReference: reference, ReportDigest: in.report, SelectionDigest: in.selectionDigest, EventLogDigest: in.eventDigest}
	controlled := baseline.Controlled{Record: baseline.Record{Version: in.m.BaselineVersion, MeasurementDigest: in.eventDigest, SecureBoot: in.m.SecureBoot, SetupMode: in.m.SetupMode, DBDigest: in.db, DBXDigest: in.dbx, FirmwareDigest: baseline.FirmwareIdentity(in.m.FirmwareVendor, in.m.FirmwareVersion), Inventory: in.m.Inventory}, MemoryMiB: in.m.MemoryMiB, StorageGiB: in.m.StorageGiB, BlockDevices: in.m.BlockDevices}
	base, err := baseline.Encode(controlled)
	if err != nil {
		return err
	}
	baselineID := sha256.Sum256(base)
	host := model.HostRecord{Fingerprint: sha256.Sum256(in.identity), IdentityCOSEKey: in.identity, AKPublic: ak.full, AKName: name, EKPublic: ek, Assurance: in.m.Assurance, BaselineID: baselineID, EnrolledAtUnix: in.m.EnrolledAt}
	challenge := attestation.Challenge{Context: evidence.Context, VerifierNonce: in.nonce, Selection: in.selection, RecipientKID: recipient, ExpiresAtUnixNS: int64(in.m.ExpiresAt)}
	canonical, _ := cbor.CanonicalEncOptions().EncMode()
	final, err := canonical.Marshal(fixture{host, challenge, evidence, base})
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Join(in.out, "invalid"), 0700); err != nil {
		return err
	}
	return writeOutputs(in, true, final, nil, nil)
}

func canonicalQuoteEncoding(encoded []byte) bool {
	value, err := modern.Unmarshal[modern.TPMSAttest](encoded)
	return err == nil && bytes.Equal(modern.Marshal(*value), encoded)
}

func canonicalSignatureEncoding(encoded []byte) bool {
	value, err := modern.Unmarshal[modern.TPMTSignature](encoded)
	return err == nil && bytes.Equal(modern.Marshal(*value), encoded)
}

type publicArtifact struct {
	full, inner []byte
	public      tpm2.Public
}

func unwrapCanonicalTPM2B(encoded []byte) (tpm2.Public, []byte, error) {
	if len(encoded) < 3 {
		return tpm2.Public{}, nil, errors.New("short TPM2B_PUBLIC")
	}
	wrapped, err := modern.Unmarshal[modern.TPM2BPublic](encoded)
	if err != nil || !bytes.Equal(modern.Marshal(*wrapped), encoded) {
		return tpm2.Public{}, nil, errors.New("noncanonical TPM2B_PUBLIC")
	}
	contents, err := wrapped.Contents()
	if err != nil {
		return tpm2.Public{}, nil, err
	}
	inner := wrapped.Bytes()
	if !bytes.Equal(modern.Marshal(*contents), inner) {
		return tpm2.Public{}, nil, errors.New("noncanonical TPMT_PUBLIC")
	}
	legacy, err := tpm2.DecodePublic(inner)
	if err != nil {
		return tpm2.Public{}, nil, err
	}
	return legacy, append([]byte(nil), inner...), nil
}
func readCanonicalAK(path string, rsa bool) (publicArtifact, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return publicArtifact{}, err
	}
	legacy, inner, err := unwrapCanonicalTPM2B(encoded)
	if err != nil {
		return publicArtifact{}, err
	}
	if rsa {
		if !validRSAProfile(legacy) {
			return publicArtifact{}, errors.New("invalid RSA AK profile")
		}
	} else if !validECCProfile(legacy) {
		return publicArtifact{}, errors.New("invalid ECC AK profile")
	}
	return publicArtifact{full: append([]byte(nil), encoded...), inner: inner, public: legacy}, nil
}
func validECCProfile(p tpm2.Public) bool {
	q := p.ECCParameters
	return p.Type == tpm2.AlgECC && p.NameAlg == tpm2.AlgSHA256 && p.Attributes == tpm2.FlagSignerDefault && len(p.AuthPolicy) == 0 && q != nil && q.Symmetric == nil && q.KDF == nil && q.CurveID == tpm2.CurveNISTP256 && q.Sign != nil && q.Sign.Alg == tpm2.AlgECDSA && q.Sign.Hash == tpm2.AlgSHA256 && len(q.Point.XRaw) == 32 && len(q.Point.YRaw) == 32
}
func validRSAProfile(p tpm2.Public) bool {
	q := p.RSAParameters
	return p.Type == tpm2.AlgRSA && p.NameAlg == tpm2.AlgSHA256 && p.Attributes == tpm2.FlagSignerDefault && len(p.AuthPolicy) == 0 && q != nil && q.Symmetric == nil && q.Sign != nil && q.Sign.Alg == tpm2.AlgRSASSA && q.Sign.Hash == tpm2.AlgSHA256 && q.KeyBits == 2048 && len(q.ModulusRaw) == 256
}
func submittedPCRs(in inputs) ([]attestation.PCRValue, []attest.PCR, []byte) {
	values := make([]attestation.PCRValue, 0, len(in.m.PCRSelection))
	pcrs := make([]attest.PCR, 0, len(in.m.PCRSelection))
	joined := []byte{}
	for _, index := range in.m.PCRSelection {
		value := in.pcr[index]
		values = append(values, attestation.PCRValue{Algorithm: 0x000b, Index: index, Value: value})
		pcrs = append(pcrs, attest.PCR{Index: int(index), Digest: value, DigestAlg: crypto.SHA256})
		joined = append(joined, value...)
	}
	return values, pcrs, joined
}
func writeOutputs(in inputs, complete bool, final []byte, _, _ any) error {
	if complete {
		if err := write(in.out, "valid-swtpm-evidence.cbor", final); err != nil {
			return err
		}
	}
	if err := write(in.out, "eventlog.bin", in.eventlog); err != nil {
		return err
	}
	if err := write(in.out, "extend-digests.hex", eventDigestText(in.m.Events)); err != nil {
		return err
	}
	if err := write(in.out, "pcrvals.hex", pcrText(in.m.PCRSelection, in.pcr)); err != nil {
		return err
	}
	if err := write(in.out, "qual.hex", append([]byte(hex.EncodeToString(in.qualifying)), '\n')); err != nil {
		return err
	}
	if complete {
		return writeInvalid(in)
	}
	return nil
}
func write(root, name string, value []byte) error {
	return os.WriteFile(filepath.Join(root, name), value, 0600)
}
func qualifying(r [16]byte, n [32]byte, a, b, c [32]byte) []byte {
	x := append([]byte("PBNS-ATTESTATION-v1"), r[:]...)
	x = append(x, n[:]...)
	x = append(x, a[:]...)
	x = append(x, b[:]...)
	x = append(x, c[:]...)
	d := sha256.Sum256(x)
	return d[:]
}
func selectionMatch(actual tpm2.PCRSelection, selection model.PCRSelection) bool {
	if len(selection) != 1 || uint64(actual.Hash) != selection[0].Algorithm || len(actual.PCRs) != len(selection[0].Indices) {
		return false
	}
	for i, v := range actual.PCRs {
		if uint64(v) != selection[0].Indices[i] {
			return false
		}
	}
	return true
}
func buildLog(m metadata) ([]byte, map[uint64][]byte, error) {
	spec := append([]byte("Spec ID Event03\x00"), make([]byte, 0)...)
	word := make([]byte, 4)
	binary.LittleEndian.PutUint32(word, 0)
	spec = append(spec, word...)
	spec = append(spec, 0, 2, 0, 2)
	binary.LittleEndian.PutUint32(word, 1)
	spec = append(spec, word...)
	spec = append(spec, 0x0b, 0, 32, 0, 0)
	out := legacyEvent(0, 3, make([]byte, 20), spec)
	pcr := map[uint64][]byte{}
	for _, event := range m.Events {
		data, _ := hx(event.Data, 0)
		digest := sha256.Sum256(data)
		out = append(out, agileEvent(event.PCR, event.Type, digest[:], data)...)
		state := sha256.Sum256(append(make([]byte, 32), digest[:]...))
		pcr[event.PCR] = state[:]
	}
	return out, pcr, nil
}
func legacyEvent(p uint64, t uint32, d, data []byte) []byte {
	x := make([]byte, 0, 32+len(data))
	word := make([]byte, 4)
	binary.LittleEndian.PutUint32(word, uint32(p))
	x = append(x, word...)
	binary.LittleEndian.PutUint32(word, t)
	x = append(x, word...)
	x = append(x, d...)
	binary.LittleEndian.PutUint32(word, uint32(len(data)))
	return append(x, append(word, data...)...)
}
func agileEvent(p uint64, t uint32, d, data []byte) []byte {
	x := make([]byte, 0, 50+len(data))
	word := make([]byte, 4)
	binary.LittleEndian.PutUint32(word, uint32(p))
	x = append(x, word...)
	binary.LittleEndian.PutUint32(word, t)
	x = append(x, word...)
	binary.LittleEndian.PutUint32(word, 1)
	x = append(x, word...)
	x = append(x, 0x0b, 0)
	x = append(x, d...)
	binary.LittleEndian.PutUint32(word, uint32(len(data)))
	return append(x, append(word, data...)...)
}
func pcrText(selection []uint64, values map[uint64][]byte) []byte {
	var output bytes.Buffer
	for _, index := range selection {
		fmt.Fprintf(&output, "%d:%x\n", index, values[index])
	}
	return output.Bytes()
}
func eventDigestText(events []eventDef) []byte {
	var output bytes.Buffer
	for _, event := range events {
		data, _ := hx(event.Data, 0)
		digest := sha256.Sum256(data)
		fmt.Fprintf(&output, "%d:%x\n", event.PCR, digest)
	}
	return output.Bytes()
}
func writeInvalid(in inputs) error {
	log := in.eventlog
	first := 32 + int(binary.LittleEndian.Uint32(log[28:32]))
	off := first
	type part struct {
		pcr   uint64
		value []byte
	}
	parts := []part{}
	for off < len(log) {
		start := off
		pcr := uint64(binary.LittleEndian.Uint32(log[off:]))
		off += 12 + 2 + 32
		length := int(binary.LittleEndian.Uint32(log[off : off+4]))
		off += 4 + length
		parts = append(parts, part{pcr, log[start:off]})
	}
	keep := func(skip uint64) []byte {
		result := append([]byte{}, log[:first]...)
		for _, part := range parts {
			if part.pcr != skip {
				result = append(result, part.value...)
			}
		}
		return result
	}
	if err := write(in.out, "invalid/not-an-event-log.bin", []byte("not an Event2 log")); err != nil {
		return err
	}
	if err := write(in.out, "invalid/truncated-final-event.bin", log[:len(log)-1]); err != nil {
		return err
	}
	if err := write(in.out, "invalid/unsupported-algorithm.bin", bytes.ReplaceAll(log, []byte{0x0b, 0}, []byte{0x0c, 0})); err != nil {
		return err
	}
	for _, event := range in.m.Events {
		if event.PCR == 2 {
			if err := write(in.out, "invalid/missing-separator.bin", keep(event.PCR)); err != nil {
				return err
			}
		}
		if event.PCR == 4 || event.PCR == 7 {
			if err := write(in.out, fmt.Sprintf("invalid/missing-pcr%d-event.bin", event.PCR), keep(event.PCR)); err != nil {
				return err
			}
		}
	}
	return nil
}
