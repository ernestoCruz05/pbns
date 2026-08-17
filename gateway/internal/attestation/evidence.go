package attestation

import (
	"bytes"
	"crypto/sha256"
	"maps"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/enrollment"
	"pbns.local/gateway/internal/model"
)

const (
	maxEventLogSize          = 4 * 1024 * 1024
	maxInventorySize         = 64 * 1024
	maxEvidenceSize          = maxEventLogSize + maxInventorySize + 8192
	maxSignedEvidenceSize    = maxEvidenceSize + 256
	maxEncryptedEvidenceSize = maxSignedEvidenceSize + 512
)

type PCRValue struct {
	Algorithm uint64 `cbor:"1,keyasint"`
	Index     uint64 `cbor:"2,keyasint"`
	Value     []byte `cbor:"3,keyasint"`
}

type StorageInventory struct {
	BlockDeviceCount uint64 `cbor:"1,keyasint"`
	CapacityGiB      uint64 `cbor:"2,keyasint"`
}

type TPMInventory struct {
	Present         bool     `cbor:"1,keyasint"`
	Manufacturer    uint64   `cbor:"2,keyasint"`
	FirmwareVersion uint64   `cbor:"3,keyasint"`
	ActiveBanks     []uint64 `cbor:"4,keyasint"`
}

type VersionsInventory struct {
	PBNS    uint64 `cbor:"1,keyasint"`
	Pico    uint64 `cbor:"2,keyasint"`
	Gateway uint64 `cbor:"3,keyasint"`
}

// InventoryReport is the exact privacy-preserving inventory schema. It intentionally contains no raw identifiers.
type InventoryReport struct {
	HostFingerprint   [32]byte          `cbor:"1,keyasint"`
	BoardModelDigest  [32]byte          `cbor:"2,keyasint"`
	FirmwareVendor    string            `cbor:"3,keyasint"`
	FirmwareVersion   string            `cbor:"4,keyasint"`
	CPUClass          string            `cbor:"5,keyasint"`
	MemoryMiB         uint64            `cbor:"6,keyasint"`
	PCIDigest         [32]byte          `cbor:"7,keyasint"`
	Storage           StorageInventory  `cbor:"8,keyasint"`
	SecureBoot        bool              `cbor:"9,keyasint"`
	SetupMode         bool              `cbor:"10,keyasint"`
	DBDigest          [32]byte          `cbor:"11,keyasint"`
	DBXDigest         [32]byte          `cbor:"12,keyasint"`
	TPM               TPMInventory      `cbor:"13,keyasint"`
	Versions          VersionsInventory `cbor:"14,keyasint"`
	Outcomes          map[uint64]uint64 `cbor:"15,keyasint"`
	Timings           map[uint64]uint64 `cbor:"16,keyasint"`
	PriorLoaderStatus uint64            `cbor:"17,keyasint"`
}

type Evidence struct {
	Context         Context         `cbor:"1,keyasint"`
	Inventory       InventoryReport `cbor:"20,keyasint"`
	Quote           []byte          `cbor:"21,keyasint"`
	QuoteSignature  []byte          `cbor:"22,keyasint"`
	PCRValues       []PCRValue      `cbor:"23,keyasint"`
	EventLog        []byte          `cbor:"24,keyasint"`
	AKName          []byte          `cbor:"25,keyasint"`
	AKReference     []byte          `cbor:"26,keyasint"`
	ReportDigest    [32]byte        `cbor:"27,keyasint"`
	SelectionDigest [32]byte        `cbor:"28,keyasint"`
	EventLogDigest  [32]byte        `cbor:"29,keyasint"`
}

// VerifiedEvidence is the immutable (defensively copied) handoff to TPM verification.
type VerifiedEvidence struct {
	Host      model.HostRecord
	Challenge Challenge
	Evidence  Evidence
	Digest    [32]byte
}

type EvidenceConsumer interface{ Verify(VerifiedEvidence) error }

var (
	canonicalMode cbor.EncMode
	strictMode    cbor.DecMode
)

func init() {
	var err error
	options := cbor.CanonicalEncOptions()
	options.NilContainers = cbor.NilContainerAsEmpty
	canonicalMode, err = options.EncMode()
	if err != nil {
		panic(err)
	}
	strictMode, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 12, MaxArrayElements: 64, MaxMapPairs: 32,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}).DecMode()
	if err != nil {
		panic(err)
	}
}

func decodeSign1(encoded []byte, destination any, maximum int) (*cose.Sign1Message, error) {
	if len(encoded) == 0 || len(encoded) > maximum || destination == nil {
		return nil, ErrInvalid
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(encoded); err != nil || len(message.Payload) == 0 || !canonicalSign1(encoded, message) || decodeCanonical(message.Payload, destination) != nil {
		return nil, ErrInvalid
	}
	return message, nil
}

func decodeCanonical(encoded []byte, destination any) error {
	if len(encoded) == 0 || destination == nil || strictMode.Unmarshal(encoded, destination) != nil {
		return ErrInvalid
	}
	canonical, err := canonicalMode.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalid
	}
	return nil
}

func canonicalSign1(encoded []byte, message *cose.Sign1Message) bool {
	if message == nil || len(message.Headers.Unprotected) != 0 || len(message.Headers.Protected) == 0 || len(message.Headers.Protected) > 1 {
		return false
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmES256 {
		return false
	}
	for label := range message.Headers.Protected {
		if label != cose.HeaderLabelAlgorithm {
			return false
		}
	}
	protected, err := message.Headers.Protected.MarshalCBOR()
	if err != nil || !bytes.Equal(protected, message.Headers.RawProtected) {
		return false
	}
	unprotected, err := canonicalMode.Marshal(message.Headers.Unprotected)
	if err != nil || !bytes.Equal(unprotected, message.Headers.RawUnprotected) {
		return false
	}
	canonical, err := message.MarshalCBOR()
	return err == nil && bytes.Equal(canonical, encoded)
}

func validEvidence(evidence Evidence, challenge Challenge, host model.HostRecord) bool {
	if !validContext(evidence.Context) || evidence.Context.RequestID != challenge.Context.RequestID || evidence.Context.HostFingerprint != challenge.Context.HostFingerprint ||
		evidence.Context.Nonce != challenge.VerifierNonce || evidence.Context.IssuedAtUnixNS != challenge.Context.IssuedAtUnixNS || evidence.Context.ExpiresAtUnixNS != challenge.Context.ExpiresAtUnixNS ||
		len(evidence.Quote) == 0 || len(evidence.Quote) > 4096 || len(evidence.QuoteSignature) == 0 || len(evidence.QuoteSignature) > 1024 ||
		len(evidence.EventLog) == 0 || len(evidence.EventLog) > maxEventLogSize || len(evidence.AKName) == 0 || len(evidence.AKName) > 128 || len(evidence.AKReference) == 0 || len(evidence.AKReference) > 4096 || !bytes.Equal(evidence.AKName, host.AKName) {
		return false
	}
	inventory, err := canonicalMode.Marshal(evidence.Inventory)
	if err != nil || !validInventory(evidence.Inventory, challenge.Context.HostFingerprint) || sha256.Sum256(inventory) != evidence.ReportDigest || sha256.Sum256(evidence.EventLog) != evidence.EventLogDigest || !evidencePCRMatches(evidence.PCRValues, challenge.Selection) {
		return false
	}
	selectionDigest, valid := canonicalSelectionDigest(challenge.Selection)
	return valid && selectionDigest == evidence.SelectionDigest
}

func canonicalSelectionDigest(selection model.PCRSelection) ([32]byte, bool) {
	var digest [32]byte
	if !selection.Valid() {
		return digest, false
	}
	hash := sha256.New()
	for _, bank := range selection {
		if bank.Algorithm > 0xffff {
			return digest, false
		}
		for _, index := range bank.Indices {
			if index > 0xff {
				return digest, false
			}
			tuple := [3]byte{byte(bank.Algorithm >> 8), byte(bank.Algorithm), byte(index)}
			written, err := hash.Write(tuple[:])
			if err != nil || written != len(tuple) {
				return digest, false
			}
		}
	}
	copy(digest[:], hash.Sum(nil))
	return digest, true
}

func evidencePCRMatches(values []PCRValue, selection model.PCRSelection) bool {
	count := 0
	for _, bank := range selection {
		count += len(bank.Indices)
	}
	if len(values) != count {
		return false
	}
	position := 0
	for _, bank := range selection {
		for _, index := range bank.Indices {
			value := values[position]
			if value.Algorithm != bank.Algorithm || value.Index != index || len(value.Value) != 32 {
				return false
			}
			position++
		}
	}
	return true
}

func verifyEvidence(signed []byte, challenge Challenge, host model.HostRecord) (VerifiedEvidence, error) {
	message, evidence, err := func() (*cose.Sign1Message, Evidence, error) {
		var evidence Evidence
		message, err := decodeSign1(signed, &evidence, maxSignedEvidenceSize)
		return message, evidence, err
	}()
	if err != nil || !validEvidence(evidence, challenge, host) {
		return VerifiedEvidence{}, ErrContext
	}
	verifier, _, err := enrollment.IdentityVerifier(host.IdentityCOSEKey)
	if err != nil || message.Verify(signAAD(challenge, evidence.AKName), verifier) != nil {
		return VerifiedEvidence{}, ErrAuthentication
	}
	return cloneVerifiedEvidence(VerifiedEvidence{Host: host.Clone(), Challenge: cloneChallenge(challenge), Evidence: cloneEvidence(evidence), Digest: sha256.Sum256(signed)}), nil
}

func validInventory(inventory InventoryReport, host [32]byte) bool {
	if inventory.HostFingerprint != host || !validInventoryText(inventory.FirmwareVendor) || !validInventoryText(inventory.FirmwareVersion) || !validInventoryText(inventory.CPUClass) || inventory.Storage.BlockDeviceCount > 64 || len(inventory.TPM.ActiveBanks) > 8 || len(inventory.Outcomes) != 5 || len(inventory.Timings) > 8 {
		return false
	}
	var previous uint64
	for index, bank := range inventory.TPM.ActiveBanks {
		if bank > 0xffffffff || (index > 0 && bank <= previous) {
			return false
		}
		previous = bank
	}
	for key, outcome := range inventory.Outcomes {
		if key == 0 || key > 5 || outcome > 5 {
			return false
		}
	}
	for key := uint64(1); key <= 5; key++ {
		if _, found := inventory.Outcomes[key]; !found {
			return false
		}
	}
	for key := range inventory.Timings {
		if key == 0 {
			return false
		}
	}
	return inventory.TPM.Manufacturer <= 0xffffffff && inventory.TPM.FirmwareVersion <= 0xffffffff && inventory.Versions.PBNS <= 0xffffffff && inventory.Versions.Pico <= 0xffffffff && inventory.Versions.Gateway <= 0xffffffff
}
func validInventoryText(value string) bool {
	if len(value) > 96 {
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
func cloneInventory(value InventoryReport) InventoryReport {
	clone := value
	clone.TPM.ActiveBanks = append([]uint64(nil), value.TPM.ActiveBanks...)
	clone.Outcomes = maps.Clone(value.Outcomes)
	clone.Timings = maps.Clone(value.Timings)
	return clone
}

func cloneEvidence(evidence Evidence) Evidence {
	clone := evidence
	clone.Context.Body = append([]byte(nil), evidence.Context.Body...)
	clone.Inventory = cloneInventory(evidence.Inventory)
	clone.Quote = append([]byte(nil), evidence.Quote...)
	clone.QuoteSignature = append([]byte(nil), evidence.QuoteSignature...)
	clone.EventLog = append([]byte(nil), evidence.EventLog...)
	clone.AKName = append([]byte(nil), evidence.AKName...)
	clone.AKReference = append([]byte(nil), evidence.AKReference...)
	clone.PCRValues = make([]PCRValue, len(evidence.PCRValues))
	for index := range evidence.PCRValues {
		clone.PCRValues[index] = evidence.PCRValues[index]
		clone.PCRValues[index].Value = append([]byte(nil), evidence.PCRValues[index].Value...)
	}
	return clone
}

func cloneVerifiedEvidence(value VerifiedEvidence) VerifiedEvidence {
	value.Host = value.Host.Clone()
	value.Challenge = cloneChallenge(value.Challenge)
	value.Evidence = cloneEvidence(value.Evidence)
	return value
}
