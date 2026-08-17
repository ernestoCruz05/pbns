package recovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
)

func recoveryTestPrivateKey(t *testing.T, name string) *ecdsa.PrivateKey {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "keys", name))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid test private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key
	}
	parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("test key is not ECDSA")
	}
	return key
}

func validTestManifest() Manifest {
	manifest := Manifest{
		Context: CommonContext{
			Domain: Domain, Version: Version, Service: ServiceRecoveryArtifact,
			IssuedAtNS: 1_000, ExpiresAtNS: 2_000, Body: []byte{},
		},
		ArtifactVersion: 7, Architecture: ArchitectureX8664,
		Format: FormatUKIPECOFF, ImageSize: 16_385, ChunkSize: ChunkSize,
		MinimumVersion: 5, NotBeforeNS: 1_000, NotAfterNS: 2_000,
		PolicyAuthorization: []byte{0xa1, 0x01, 0x02},
		PolicyKeyID:         []byte("policy-key-2026"),
	}
	for i := range manifest.Context.RequestID {
		manifest.Context.RequestID[i] = byte(0x10 + i)
	}
	for i := range manifest.Context.HostBinding {
		manifest.Context.HostBinding[i] = byte(0x20 + i)
	}
	for i := range manifest.Context.Nonce {
		manifest.Context.Nonce[i] = byte(0x40 + i)
	}
	for i := range manifest.ArtifactDigest {
		manifest.ArtifactDigest[i] = byte(0x60 + i)
	}
	return manifest
}

func validTestExpectation(manifest Manifest) Expectation {
	return Expectation{
		RequestID: manifest.Context.RequestID, HostBinding: manifest.Context.HostBinding,
		Nonce: manifest.Context.Nonce, RecoverySigningKeyID: []byte("recovery-key-2026"),
		ExpectedPolicyKeyID: append([]byte(nil), manifest.PolicyKeyID...), CurrentVersion: 6,
		TrustedEarliestNS: 1_100, TrustedLatestNS: 1_900,
	}
}

func testRecoverySigner(t *testing.T) (*keys.AuthorizedSigner, cose.Verifier) {
	t.Helper()
	privateKey := recoveryTestPrivateKey(t, "service-signing-test-private.pem")
	signer, err := keys.NewPinnedOnlineSigner(
		keys.RoleRecoveryManifest, []byte("recovery-key-2026"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

func TestManifestCanonicalSignAndVerify(t *testing.T) {
	manifest := validTestManifest()
	expectation := validTestExpectation(manifest)
	signer, verifier := testRecoverySigner(t)

	signed, err := SignManifest(manifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := VerifyManifest(signed, verifier, expectation)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(manifest) {
		t.Fatalf("decoded manifest differs: %#v", decoded)
	}

	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(signed); err != nil {
		t.Fatal(err)
	}
	if got, ok := message.Headers.Protected[cose.HeaderLabelKeyID].([]byte); !ok ||
		!bytes.Equal(got, expectation.RecoverySigningKeyID) {
		t.Fatal("protected recovery key id missing")
	}
}

func TestManifestRejectsBindingTimeVersionAndProfileChanges(t *testing.T) {
	manifest := validTestManifest()
	expectation := validTestExpectation(manifest)
	signer, verifier := testRecoverySigner(t)
	signed, err := SignManifest(manifest, signer)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		change func(*Expectation)
	}{
		{"request", func(value *Expectation) { value.RequestID[0] ^= 1 }},
		{"host", func(value *Expectation) { value.HostBinding[0] ^= 1 }},
		{"nonce", func(value *Expectation) { value.Nonce[0] ^= 1 }},
		{"signing key id", func(value *Expectation) { value.RecoverySigningKeyID[0] ^= 1 }},
		{"policy key id", func(value *Expectation) { value.ExpectedPolicyKeyID[0] ^= 1 }},
		{"version", func(value *Expectation) { value.CurrentVersion = 8 }},
		{"partially early", func(value *Expectation) { value.TrustedEarliestNS = 999 }},
		{"partially late", func(value *Expectation) { value.TrustedLatestNS = 2_001 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := expectation.Clone()
			test.change(&changed)
			if _, err := VerifyManifest(signed, verifier, changed); err == nil {
				t.Fatal("changed expectation accepted")
			}
		})
	}

	invalid := []Manifest{manifest, manifest, manifest, manifest, manifest, manifest, manifest}
	invalid[0].ImageSize = 0
	invalid[1].ImageSize = MaximumImageSize + 1
	invalid[2].ChunkSize = ChunkSize - 1
	invalid[3].Architecture = "aarch64"
	invalid[4].Format = "pe-coff"
	invalid[5].ArtifactVersion = invalid[5].MinimumVersion - 1
	invalid[6].ArtifactDigest = [32]byte{}
	for index, value := range invalid {
		if _, err := SignManifest(value, signer); err == nil {
			t.Fatalf("invalid profile %d accepted", index)
		}
	}
}

func TestManifestRejectsUnsignedTamperedAndNonCanonicalData(t *testing.T) {
	manifest := validTestManifest()
	expectation := validTestExpectation(manifest)
	signer, verifier := testRecoverySigner(t)
	signed, err := SignManifest(manifest, signer)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := VerifyManifest(tampered, verifier, expectation); err == nil {
		t.Fatal("tampered signature accepted")
	}
	payload, err := encodeMode.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(payload, verifier, expectation); err == nil {
		t.Fatal("unsigned payload accepted")
	}

	var generic map[uint64]any
	if err := decodeMode.Unmarshal(payload, &generic); err != nil {
		t.Fatal(err)
	}
	generic[99] = uint64(1)
	nonProfile, err := encodeMode.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = expectation.RecoverySigningKeyID
	message.Payload = nonProfile
	if err := message.Sign(rand.Reader, manifestAAD(expectation), signer.COSESigner()); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(encoded, verifier, expectation); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
}

func TestPublisherRejectsWrongRoleAndSecureBootKeyReuse(t *testing.T) {
	repository, err := OpenRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	recoveryKey := recoveryTestPrivateKey(t, "service-signing-test-private.pem")
	wrongRole, err := keys.NewPinnedOnlineSigner(
		keys.RoleTrustedTime, []byte("recovery-key-2026"), recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(repository, wrongRole, &recoveryKey.PublicKey); !errors.Is(err, keys.ErrRole) {
		t.Fatalf("wrong role: %v", err)
	}

	reused, err := keys.NewPinnedOnlineSigner(
		keys.RoleRecoveryManifest, []byte("reused-key"), recoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPublisher(repository, reused, &recoveryKey.PublicKey); !errors.Is(err, ErrKeyReuse) {
		t.Fatalf("key reuse: %v", err)
	}
}

func TestCheckedInManifestVector(t *testing.T) {
	manifest := validTestManifest()
	expectation := validTestExpectation(manifest)
	_, verifier := testRecoverySigner(t)
	path := filepath.Join("..", "..", "..", "tests", "vectors", "recovery-manifest-v1")
	payload, err := os.ReadFile(filepath.Join(path, "payload.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := encodeMode.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, canonical) {
		t.Fatalf("payload differs: got %s", hex.EncodeToString(canonical))
	}
	signed, err := os.ReadFile(filepath.Join(path, "signed.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(signed, verifier, expectation); err != nil {
		t.Fatal(err)
	}
}
