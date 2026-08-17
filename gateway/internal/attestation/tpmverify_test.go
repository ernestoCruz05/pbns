package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/model"
)

type swtpmFixture struct {
	Host      model.HostRecord `cbor:"1,keyasint"`
	Challenge Challenge        `cbor:"2,keyasint"`
	Evidence  Evidence         `cbor:"3,keyasint"`
	Baseline  []byte           `cbor:"4,keyasint"`
}
type baselineMap map[[32]byte][]byte

func (m baselineMap) GetBaseline(id [32]byte) ([]byte, error) {
	return append([]byte(nil), m[id]...), nil
}

func loadSwtpmFixture(t *testing.T) swtpmFixture {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", "attestation", "valid-swtpm-evidence.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture swtpmFixture
	if err := cbor.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
func fixtureInput(f swtpmFixture) VerifiedEvidence {
	return VerifiedEvidence{Host: f.Host, Challenge: f.Challenge, Evidence: f.Evidence}
}
func fixtureVerifier(t *testing.T, f swtpmFixture) *Verifier {
	t.Helper()
	v, err := NewVerifier(baselineMap{f.Host.BaselineID: f.Baseline})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifierRequiresTPMQuote(t *testing.T) {
	if _, err := NewVerifier(nil); err == nil {
		t.Fatal("NewVerifier accepted nil baseline provider")
	}
}
func TestSwtpmFixtureTrusted(t *testing.T) {
	f := loadSwtpmFixture(t)
	verdict := fixtureVerifier(t, f).Assess(fixtureInput(f))
	if !verdict.Trusted() {
		t.Fatalf("fixture verdict: %#v", verdict)
	}
}
func TestQuoteReasons(t *testing.T) {
	f := loadSwtpmFixture(t)
	cases := map[string]struct {
		mutate func(*swtpmFixture)
		want   Reason
	}{
		"identity-association": {func(f *swtpmFixture) { f.Host.Fingerprint[0] ^= 1 }, ReasonSkipped},
		"ak-name":              {func(f *swtpmFixture) { f.Evidence.AKName[0] ^= 1 }, ReasonAKName},
		"quote-magic":          {func(f *swtpmFixture) { f.Evidence.Quote[0] ^= 1 }, ReasonQuoteMalformed},
		"quote-trailing-byte":  {func(f *swtpmFixture) { f.Evidence.Quote = append(f.Evidence.Quote, 0xaa) }, ReasonQuoteMalformed},
		"signature":            {func(f *swtpmFixture) { f.Evidence.QuoteSignature[len(f.Evidence.QuoteSignature)-1] ^= 1 }, ReasonQuoteSignature},
		"signature-trailing-byte": {func(f *swtpmFixture) {
			f.Evidence.QuoteSignature = append(f.Evidence.QuoteSignature, 0xaa)
		}, ReasonQuoteSignature},
		"qualifying-data":      {func(f *swtpmFixture) { f.Challenge.VerifierNonce[0] ^= 1 }, ReasonQualifyingData},
		"pcr-selection":        {func(f *swtpmFixture) { f.Challenge.Selection[0].Indices[0] = 1 }, ReasonPCRSelection},
		"submitted-pcr-digest": {func(f *swtpmFixture) { f.Evidence.PCRValues[0].Value[0] ^= 1 }, ReasonPCRDigest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			copy := cloneFixture(f)
			tc.mutate(&copy)
			got := fixtureVerifier(t, copy).Assess(fixtureInput(copy)).Quote.Reason
			if got != tc.want {
				t.Fatalf("quote reason=%q want %q", got, tc.want)
			}
		})
	}
	identity := cloneFixture(f)
	identity.Host.Fingerprint[0] ^= 1
	if got := fixtureVerifier(t, identity).Assess(fixtureInput(identity)).Capability.Reason; got != ReasonIdentityAssociation {
		t.Fatalf("identity association capability=%q", got)
	}
}
func TestAKProfileAndCanonicalPublicEncoding(t *testing.T) {
	f := loadSwtpmFixture(t)
	rsa, err := os.ReadFile(filepath.Join("..", "..", "testdata", "attestation", "source", "ak-rsa.pub"))
	if err != nil {
		t.Fatal(err)
	}
	f.Host.AKPublic = rsa
	if got := fixtureVerifier(t, f).Assess(fixtureInput(f)).Quote.Reason; got != ReasonAKProfile {
		t.Fatalf("RSA AK reason=%q", got)
	}

	valid := loadSwtpmFixture(t).Host.AKPublic
	bare := append([]byte(nil), valid[2:]...)
	if _, inner, err := decodeAKPublic(bare); err != nil || !bytes.Equal(inner, bare) {
		t.Fatalf("bare public: %x, %v", inner, err)
	}
	if _, _, err := decodeAKPublic(append(valid, 0)); err == nil {
		t.Fatal("accepted TPM2B_PUBLIC trailing byte")
	}
	if _, _, err := decodeAKPublic([]byte{0, 1, 0}); err == nil {
		t.Fatal("accepted malformed TPM2B_PUBLIC size")
	}
	if _, _, err := decodeAKPublic(append(bare, 0)); err == nil {
		t.Fatal("accepted TPMT_PUBLIC trailing byte")
	}
}

func parseManifestLine(line string) (string, string, error) {
	if len(line) < 67 || line[64:66] != "  " {
		return "", "", fmt.Errorf("invalid manifest line %q", line)
	}
	digest, path := line[:64], line[66:]
	if _, err := hex.DecodeString(digest); err != nil || len(path) == 0 {
		return "", "", fmt.Errorf("invalid manifest line %q", line)
	}
	// This policy runs before any lossy field splitting: sha256sum's
	// line-oriented verifier must never receive an ambiguous fixture path.
	if strings.ContainsAny(path, " \t\r\n\\") {
		return "", "", fmt.Errorf("fixture manifest path violates whitespace-free policy: %q", path)
	}
	return digest, path, nil
}
func TestFixtureManifestPathPolicy(t *testing.T) {
	digest := strings.Repeat("0", 64)
	for _, line := range []string{digest + "  regular/path", digest + "  white space", digest + "  back\\slash"} {
		_, path, err := parseManifestLine(line)
		if strings.Contains(line, "regular") && (err != nil || path != "regular/path") {
			t.Fatalf("regular path: %v", err)
		}
		if !strings.Contains(line, "regular") && err == nil {
			t.Fatalf("accepted ambiguous path %q", line)
		}
	}
}
func TestFixtureManifestIntegrity(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "attestation")
	manifest, err := os.ReadFile(filepath.Join(root, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		digest, path, err := parseManifestLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if listed[path] {
			t.Fatalf("duplicate manifest entry %s", path)
		}
		listed[path] = true
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != digest {
			t.Fatalf("hash %s", path)
		}
	}
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "SHA256SUMS" {
			return nil
		} // The manifest cannot hash itself.
		if !listed[filepath.ToSlash(rel)] {
			return fmt.Errorf("unmanifested fixture file %s", rel)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := rejectTautologicalSource(root); err != nil {
		t.Fatal(err)
	}
}

func rejectTautologicalSource(root string) error {
	if _, err := os.Stat(filepath.Join(root, "source", "assembly-input.cbor")); !os.IsNotExist(err) {
		return fmt.Errorf("tautological completed CBOR source is forbidden")
	}
	return nil
}
func TestFixtureSourceRejectsOldTautologicalCBOR(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "source"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source", "assembly-input.cbor"), []byte{0xa0}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := rejectTautologicalSource(root); err == nil {
		t.Fatal("old duplicate fixture source was accepted")
	}
}

func TestQuoteTypeRejected(t *testing.T) {
	f := loadSwtpmFixture(t)
	f.Evidence.Quote[5] ^= 1 // TPMI_ST_ATTEST is the two bytes after TPM_GENERATED.
	if got := fixtureVerifier(t, f).Assess(fixtureInput(f)).Quote.Reason; got == ReasonTrusted {
		t.Fatal("changed TPM attestation type was accepted")
	}
}

func TestQualifyingDataTask3FixedVector(t *testing.T) {
	var request [16]byte
	var nonce, report, selection, log [32]byte
	for i := range request {
		request[i] = byte(i)
	}
	for i := range nonce {
		nonce[i] = byte(0x10 + i)
		report[i] = byte(0x30 + i)
		selection[i] = byte(0x50 + i)
		log[i] = byte(0x70 + i)
	}
	// Independently assembled from C reference fixed-width concatenation.
	material := append([]byte("PBNS-ATTESTATION-v1"), request[:]...)
	material = append(material, nonce[:]...)
	material = append(material, report[:]...)
	material = append(material, selection[:]...)
	material = append(material, log[:]...)
	want := sha256.Sum256(material)
	got := qualifyingData(request, nonce, report, selection, log)
	if string(got) != string(want[:]) {
		t.Fatalf("qualifying data %x want %x", got, want)
	}
}
func cloneFixture(f swtpmFixture) swtpmFixture {
	return swtpmFixture{Host: f.Host.Clone(), Challenge: cloneChallenge(f.Challenge), Evidence: cloneEvidence(f.Evidence), Baseline: append([]byte(nil), f.Baseline...)}
}

func TestBaselineAndInventorySeparation(t *testing.T) {
	f := loadSwtpmFixture(t)
	cases := map[string]struct {
		mutate func(*swtpmFixture)
		field  func(Verdict) Reason
		want   Reason
	}{
		"firmware-measurement-change": {func(f *swtpmFixture) { f.Evidence.Inventory.FirmwareVersion = "3.0" }, func(v Verdict) Reason { return v.MeasurementBaseline.Reason }, ReasonMeasurementBaseline},
		"secure-boot-off":             {func(f *swtpmFixture) { f.Evidence.Inventory.SecureBoot = false }, func(v Verdict) Reason { return v.MeasurementBaseline.Reason }, ReasonMeasurementBaseline},
		"db-change":                   {func(f *swtpmFixture) { f.Evidence.Inventory.DBDigest[0] ^= 1 }, func(v Verdict) Reason { return v.MeasurementBaseline.Reason }, ReasonMeasurementBaseline},
		"permitted-memory-drift":      {func(f *swtpmFixture) { f.Evidence.Inventory.MemoryMiB += 64 }, func(v Verdict) Reason { return v.InventoryDrift.Reason }, ReasonTrusted},
		"permitted-storage-drift":     {func(f *swtpmFixture) { f.Evidence.Inventory.Storage.CapacityGiB += 2 }, func(v Verdict) Reason { return v.InventoryDrift.Reason }, ReasonTrusted},
		"inventory-drift":             {func(f *swtpmFixture) { f.Evidence.Inventory.MemoryMiB += 129 }, func(v Verdict) Reason { return v.InventoryDrift.Reason }, ReasonInventoryDrift},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			copy := cloneFixture(f)
			tc.mutate(&copy)
			verdict := fixtureVerifier(t, copy).Assess(fixtureInput(copy))
			if got := tc.field(verdict); got != tc.want {
				t.Fatalf("reason=%q want %q verdict=%#v", got, tc.want, verdict)
			}
		})
	}
}

func TestNormalVerificationDoesNotWriteBaseline(t *testing.T) {
	f := loadSwtpmFixture(t)
	source := baselineMap{f.Host.BaselineID: f.Baseline}
	verifier, err := NewVerifier(source)
	if err != nil {
		t.Fatal(err)
	}
	_ = verifier.Assess(fixtureInput(f))
	if len(source) != 1 {
		t.Fatal("verification changed baseline source")
	}
}
func TestBaselineDigestMatchesControlledEnrollment(t *testing.T) {
	f := loadSwtpmFixture(t)
	if _, err := baseline.Decode(f.Baseline); err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(f.Baseline) != f.Host.BaselineID {
		t.Fatal("fixture baseline ID mismatch")
	}
}
