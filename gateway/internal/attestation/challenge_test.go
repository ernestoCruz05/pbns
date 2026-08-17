package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"crypto/rand"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/store"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestIssueRejectsEntropyFailureAndUnknownHost(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(bytes.Repeat([]byte{1}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), bytes.NewReader(bytes.Repeat([]byte{2}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.NewPinnedOnlineSigner(keys.RoleAttestation, []byte("kid"), signing)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{Store: value, RecipientKey: recipient, RecipientKID: []byte("recipient"), Signer: signer, Clock: func() time.Time { return now }, Random: failingReader{}, Verifier: &countVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Issue([32]byte{1}); !errors.Is(err, ErrChallenge) {
		t.Fatalf("unknown host: %v", err)
	}
	host, _ := enrolledHost(t, value, now)
	if _, err := service.Issue(host.Fingerprint); !errors.Is(err, ErrInvalid) {
		t.Fatalf("entropy failure: %v", err)
	}
}

func TestSignAADInteropOracle(t *testing.T) {
	challenge := Challenge{Context: Context{RequestID: [16]byte{1}, HostFingerprint: [32]byte{2}}, VerifierNonce: [32]byte{3}}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	// This oracle intentionally spells out the canonical six-element array and does not call signAAD.
	want, err := mode.Marshal([]any{"PBNS-ATTESTATION-SIGN-v1", uint64(1), challenge.Context.RequestID[:], challenge.Context.HostFingerprint[:], challenge.VerifierNonce[:], []byte("ak")})
	if err != nil {
		t.Fatal(err)
	}
	if got := signAAD(challenge, []byte("ak")); !bytes.Equal(got, want) {
		t.Fatalf("Sign AAD drift\ngot  %x\nwant %x", got, want)
	}
}

func TestIssueToVerifyChallengeUsesExactCanonicalProfile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, _ := enrolledHost(t, value, now)
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challengeKID := []byte("challenge-exact")
	recipientKID := []byte("recipient-exact")
	signer, err := keys.NewPinnedOnlineSigner(keys.RoleAttestation, challengeKID, signing)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{Store: value, RecipientKey: recipient, RecipientKID: recipientKID, Signer: signer, Clock: func() time.Time { return now }, Random: rand.Reader, Verifier: &countVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Issue(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(issued.Signed); err != nil {
		t.Fatal(err)
	}
	var payload Challenge
	if err := decodeCanonical(message.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &signing.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyChallenge(issued.Signed, verifier, issued.RequestID, host.Fingerprint, payload.VerifierNonce, recipientKID, challengeKID)
	if err != nil {
		t.Fatalf("Issue challenge failed exact verification: %v", err)
	}
	if verified.Context.RequestID != issued.RequestID {
		t.Fatal("verified challenge request ID changed")
	}

	protected := func(value map[int64]any) []byte {
		t.Helper()
		encoded, encodeErr := canonicalMode.Marshal(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return encoded
	}
	envelope := func(protectedBytes []byte, unprotected map[int64]any, payloadBytes, signature []byte) []byte {
		t.Helper()
		encoded, encodeErr := canonicalMode.Marshal(cbor.Tag{Number: 18, Content: []any{protectedBytes, unprotected, payloadBytes, signature}})
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return encoded
	}
	nonminimalBstr := func(encoded, content []byte) []byte {
		t.Helper()
		canonicalBstr, encodeErr := canonicalMode.Marshal(content)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		headerOffset := bytes.Index(encoded, canonicalBstr)
		if headerOffset < 0 {
			t.Fatal("CBOR byte string not found")
		}
		headerSize := len(canonicalBstr) - len(content)
		var replacement []byte
		switch headerSize {
		case 1:
			replacement = []byte{0x58, byte(len(content))}
		case 2:
			replacement = []byte{0x59, byte(len(content) >> 8), byte(len(content))}
		case 3:
			replacement = []byte{0x5a, 0, 0, byte(len(content) >> 8), byte(len(content))}
		default:
			t.Fatalf("unsupported canonical bstr header size %d", headerSize)
		}
		mutant := make([]byte, 0, len(encoded)+len(replacement)-headerSize)
		mutant = append(mutant, encoded[:headerOffset]...)
		mutant = append(mutant, replacement...)
		mutant = append(mutant, encoded[headerOffset+headerSize:]...)
		return mutant
	}
	canonicalProtected := protected(map[int64]any{1: int64(-7), 4: challengeKID})
	malformed := []byte{0xff}
	for name, expectedKID := range map[string][]byte{
		"empty expected KID":   nil,
		"65-byte expected KID": bytes.Repeat([]byte{0x41}, 65),
	} {
		t.Run(name+" before decode", func(t *testing.T) {
			allocations := testing.AllocsPerRun(100, func() {
				if _, _, decodeErr := decodeChallenge(malformed, expectedKID); decodeErr == nil {
					t.Fatal("accepted invalid expected KID with malformed challenge bytes")
				}
			})
			if allocations != 0 {
				t.Fatalf("decoded malformed challenge before expected KID validation: %.0f allocations", allocations)
			}
		})
	}
	profileMutants := map[string][]byte{
		"missing KID":               envelope(protected(map[int64]any{1: int64(-7)}), map[int64]any{}, message.Payload, message.Signature),
		"wrong KID":                 envelope(protected(map[int64]any{1: int64(-7), 4: []byte("other-challenge")}), map[int64]any{}, message.Payload, message.Signature),
		"wrong algorithm":           envelope(protected(map[int64]any{1: int64(-8), 4: challengeKID}), map[int64]any{}, message.Payload, message.Signature),
		"extra protected":           envelope(protected(map[int64]any{1: int64(-7), 4: challengeKID, 99: int64(1)}), map[int64]any{}, message.Payload, message.Signature),
		"nonempty unprotected":      envelope(protected(map[int64]any{1: int64(-7), 4: challengeKID}), map[int64]any{5: int64(1)}, message.Payload, message.Signature),
		"malformed payload":         envelope(protected(map[int64]any{1: int64(-7), 4: challengeKID}), map[int64]any{}, []byte{0xff}, message.Signature),
		"wrong payload":             envelope(protected(map[int64]any{1: int64(-7), 4: challengeKID}), map[int64]any{}, []byte{0xa0}, message.Signature),
		"wrong signature length":    envelope(protected(map[int64]any{1: int64(-7), 4: challengeKID}), map[int64]any{}, message.Payload, message.Signature[:63]),
		"missing tag":               append([]byte(nil), issued.Signed[1:]...),
		"wrong tag":                 append([]byte{0xd1}, issued.Signed[1:]...),
		"trailing data":             append(append([]byte(nil), issued.Signed...), 0x00),
		"nonminimal tag":            append([]byte{0xd8, 0x12}, issued.Signed[1:]...),
		"nonminimal array":          append(append([]byte{issued.Signed[0], 0x98, 0x04}, issued.Signed[2:]...), []byte{}...),
		"nonminimal protected bstr": nonminimalBstr(issued.Signed, canonicalProtected),
		"nonminimal payload bstr":   nonminimalBstr(issued.Signed, message.Payload),
		"nonminimal signature bstr": nonminimalBstr(issued.Signed, message.Signature),
	}
	profileMutants["noncanonical protected key"] = envelope(append([]byte{0xa2, 0x18, 0x01, 0x26}, canonicalProtected[3:]...), map[int64]any{}, message.Payload, message.Signature)
	profileMutants["noncanonical protected value"] = envelope(append([]byte{0xa2, 0x01, 0x38, 0x06}, canonicalProtected[3:]...), map[int64]any{}, message.Payload, message.Signature)
	profileMutants["noncanonical protected length"] = envelope(append([]byte{0xb8, 0x02}, canonicalProtected[1:]...), map[int64]any{}, message.Payload, message.Signature)
	noncanonicalPayload := append([]byte{0xb8, message.Payload[0] & 0x1f}, message.Payload[1:]...)
	profileMutants["noncanonical payload"] = envelope(canonicalProtected, map[int64]any{}, noncanonicalPayload, message.Signature)
	for name, mutant := range profileMutants {
		t.Run(name, func(t *testing.T) {
			if _, _, decodeErr := decodeChallenge(mutant, challengeKID); decodeErr == nil {
				t.Fatal("exact challenge profile accepted mutant")
			}
		})
	}

	badSignature := append([]byte(nil), issued.Signed...)
	badSignature[len(badSignature)-1] ^= 1
	if _, _, err := decodeChallenge(badSignature, challengeKID); err != nil {
		t.Fatalf("canonical bad-signature envelope rejected before authentication: %v", err)
	}
	contextMutants := []struct {
		name      string
		requestID [16]byte
		host      [32]byte
		nonce     [32]byte
		recipient []byte
		encoded   []byte
	}{
		{name: "wrong request", requestID: [16]byte{0xff}, host: host.Fingerprint, nonce: payload.VerifierNonce, recipient: recipientKID, encoded: issued.Signed},
		{name: "wrong host", requestID: issued.RequestID, host: [32]byte{0xff}, nonce: payload.VerifierNonce, recipient: recipientKID, encoded: issued.Signed},
		{name: "wrong nonce", requestID: issued.RequestID, host: host.Fingerprint, nonce: [32]byte{0xff}, recipient: recipientKID, encoded: issued.Signed},
		{name: "wrong recipient", requestID: issued.RequestID, host: host.Fingerprint, nonce: payload.VerifierNonce, recipient: []byte("other-recipient"), encoded: issued.Signed},
		{name: "bad signature", requestID: issued.RequestID, host: host.Fingerprint, nonce: payload.VerifierNonce, recipient: recipientKID, encoded: badSignature},
	}
	for _, mutant := range contextMutants {
		t.Run(mutant.name, func(t *testing.T) {
			if _, err := VerifyChallenge(mutant.encoded, verifier, mutant.requestID, mutant.host, mutant.nonce, mutant.recipient, challengeKID); err == nil {
				t.Fatal("challenge context/signature mutant accepted")
			}
		})
	}
}

func TestIssueChallengeUsesExactTaggedProtectedKIDProfile(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, _ := enrolledHost(t, value, now)
	service, _ := testService(t, value, now, &countVerifier{})
	issued, err := service.Issue(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.Signed) == 0 || issued.Signed[0] != 0xd2 {
		t.Fatalf("challenge is not tag-18 Sign1: %x", issued.Signed)
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(issued.Signed); err != nil {
		t.Fatal(err)
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := mode.Marshal(map[int64]any{1: int64(-7), 4: []byte("attestation-key")})
	if err != nil {
		t.Fatal(err)
	}
	wantProtected, err := mode.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Headers.RawProtected, wantProtected) {
		t.Fatalf("protected=%x want=%x", message.Headers.RawProtected, wantProtected)
	}
	if !bytes.Equal(message.Headers.RawUnprotected, []byte{0xa0}) {
		t.Fatalf("unprotected=%x want empty canonical map", message.Headers.RawUnprotected)
	}
	if len(message.Signature) != 64 {
		t.Fatalf("signature size=%d", len(message.Signature))
	}
}

func TestChallengeCVectorRebuild(t *testing.T) {
	generated := t.TempDir()
	command := exec.Command("go", "run", "./testdata/generate_challenge.go", generated)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate challenge vector: %v\n%s", err, output)
	}
	committed := filepath.Clean(filepath.Join("..", "..", "..", "tests", "vectors", "attestation-challenge-v1"))
	for _, name := range []string{"challenge_vector.inc", "provenance.txt"} {
		want, err := os.ReadFile(filepath.Join(committed, name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(generated, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generated %s differs from committed vector", name)
		}
	}
}

func TestIssueSigningFailureLeavesNoChallenge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, _ := enrolledHost(t, value, now)
	recipient, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signing, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := keys.NewPinnedOnlineSigner(keys.RoleAttestation, []byte("kid"), signing)
	reader := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{1}, 48)), failingReader{})
	service, err := NewService(Config{Store: value, RecipientKey: recipient, RecipientKID: []byte("recipient"), Signer: signer, Clock: func() time.Time { return now }, Random: reader, Verifier: &countVerifier{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Issue(host.Fingerprint); err == nil {
		t.Fatal("accepted signing entropy failure")
	}
	if _, err := value.GetAttestationChallenge([16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sign failure stored challenge: %v", err)
	}
}
