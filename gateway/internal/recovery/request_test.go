package recovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type recoveryRequestVector struct {
	Domain             string `json:"domain"`
	Version            uint64 `json:"version"`
	Service            uint64 `json:"service"`
	Operation          uint64 `json:"operation"`
	RequestIDHex       string `json:"request_id_hex"`
	HostFingerprintHex string `json:"host_fingerprint_hex"`
	NonceHex           string `json:"nonce_hex"`
	ArtifactDigestHex  string `json:"artifact_digest_hex"`
	EncodedHex         string `json:"encoded_hex"`
}

type fixedHostResolver struct {
	fingerprint [32]byte
	verifier    cose.Verifier
	err         error
}

func (resolver fixedHostResolver) ResolveHost(fingerprint [32]byte) (cose.Verifier, error) {
	if resolver.err != nil {
		return nil, resolver.err
	}
	if fingerprint != resolver.fingerprint {
		return nil, errors.New("unknown host")
	}
	return resolver.verifier, nil
}

func loadRecoveryRequestVector(t *testing.T, name string) (Request, []byte) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "vectors", "recovery-request-v1", name)
	encodedJSON, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector recoveryRequestVector
	decoder := json.NewDecoder(bytes.NewReader(encodedJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	request := Request{
		Domain: vector.Domain, Version: vector.Version, Service: vector.Service,
		Operation: Operation(vector.Operation),
	}
	decodeFixedRequestHex(t, vector.RequestIDHex, request.RequestID[:])
	decodeFixedRequestHex(t, vector.HostFingerprintHex, request.HostFingerprint[:])
	decodeFixedRequestHex(t, vector.NonceHex, request.Nonce[:])
	decodeFixedRequestHex(t, vector.ArtifactDigestHex, request.ArtifactDigest[:])
	payload, err := hex.DecodeString(vector.EncodedHex)
	if err != nil {
		t.Fatal(err)
	}
	return request, payload
}

func decodeFixedRequestHex(t *testing.T, encoded string, destination []byte) {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(destination) {
		t.Fatalf("invalid vector field %q", encoded)
	}
	copy(destination, decoded)
}

func requestKeys(t *testing.T) (*ecdsa.PrivateKey, cose.Signer, cose.Verifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer, verifier
}

func signedRecoveryPayload(t *testing.T, payload []byte, signer cose.Signer,
	protected map[any]any, unprotected map[any]any) []byte {
	t.Helper()
	message := cose.NewSign1Message()
	for label, value := range protected {
		message.Headers.Protected[label] = value
	}
	for label, value := range unprotected {
		message.Headers.Unprotected[label] = value
	}
	message.Payload = append([]byte(nil), payload...)
	if err := message.Sign(rand.Reader, []byte(RequestAAD), signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestRecoveryRequestPayloadMatchesPortableVectors(t *testing.T) {
	_, signer, _ := requestKeys(t)
	for _, name := range []string{"manifest-request.json", "artifact-request.json"} {
		t.Run(name, func(t *testing.T) {
			request, expected := loadRecoveryRequestVector(t, name)
			signed, err := SignRequest(request, signer)
			if err != nil {
				t.Fatal(err)
			}
			message := cose.NewSign1Message()
			if err := message.UnmarshalCBOR(signed); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(message.Payload, expected) {
				t.Fatalf("payload=%x, want %x", message.Payload, expected)
			}
		})
	}
}

func TestRecoveryRequestAuthenticatesEnrolledHost(t *testing.T) {
	_, signer, verifier := requestKeys(t)
	request, _ := loadRecoveryRequestVector(t, "artifact-request.json")
	signed, err := SignRequest(request, signer)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRequest(signed, fixedHostResolver{
		fingerprint: request.HostFingerprint, verifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verified != request {
		t.Fatalf("verified=%#v, want %#v", verified, request)
	}
}

func TestRecoveryRequestRejectsShapeAndResolverFailures(t *testing.T) {
	_, signer, verifier := requestKeys(t)
	manifest, manifestPayload := loadRecoveryRequestVector(t, "manifest-request.json")
	artifact, _ := loadRecoveryRequestVector(t, "artifact-request.json")

	invalid := []Request{manifest, artifact}
	invalid = append(invalid, artifact, artifact, artifact, artifact, artifact)
	invalid[0].Domain = "wrong"
	invalid[1].Version = 2
	invalid[2].Service = 3
	invalid[3].Operation = 3
	invalid[4].RequestID = [16]byte{}
	invalid[5].HostFingerprint = [32]byte{}
	invalid[6].Nonce = [32]byte{}
	for index, request := range invalid {
		if _, err := SignRequest(request, signer); !errors.Is(err, ErrRequest) {
			t.Fatalf("invalid[%d] got %v", index, err)
		}
	}
	badManifest := manifest
	badManifest.ArtifactDigest[0] = 1
	if _, err := SignRequest(badManifest, signer); !errors.Is(err, ErrRequest) {
		t.Fatalf("manifest digest got %v", err)
	}
	badArtifact := artifact
	badArtifact.ArtifactDigest = [32]byte{}
	if _, err := SignRequest(badArtifact, signer); !errors.Is(err, ErrRequest) {
		t.Fatalf("artifact digest got %v", err)
	}
	if _, err := SignRequest(artifact, nil); !errors.Is(err, ErrRequest) {
		t.Fatalf("nil signer got %v", err)
	}

	signed, err := SignRequest(artifact, signer)
	if err != nil {
		t.Fatal(err)
	}
	resolverFailure := errors.New("resolver failed")
	unknownFingerprint := artifact.HostFingerprint
	unknownFingerprint[0] ^= 1
	for name, resolver := range map[string]HostResolver{
		"unknown":      fixedHostResolver{fingerprint: unknownFingerprint, verifier: verifier},
		"failure":      fixedHostResolver{err: resolverFailure},
		"nil-verifier": fixedHostResolver{fingerprint: artifact.HostFingerprint},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRequest(signed, resolver); !errors.Is(err, ErrRequestAuthentication) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := VerifyRequest(signed, nil); !errors.Is(err, ErrRequest) {
		t.Fatalf("nil resolver got %v", err)
	}
	if _, err := VerifyRequest(make([]byte, 64*1024+1), fixedHostResolver{}); !errors.Is(err, ErrRequest) {
		t.Fatalf("oversize got %v", err)
	}
	if _, err := VerifyRequest(manifestPayload, fixedHostResolver{}); !errors.Is(err, ErrRequestAuthentication) {
		t.Fatalf("unsigned CBOR got %v", err)
	}
}

func TestRecoveryRequestRejectsNoncanonicalAndHeaderSubstitution(t *testing.T) {
	_, signer, verifier := requestKeys(t)
	request, canonical := loadRecoveryRequestVector(t, "artifact-request.json")
	resolver := fixedHostResolver{fingerprint: request.HostFingerprint, verifier: verifier}

	noncanonical := append([]byte{0xb8, 0x08}, canonical[1:]...)
	cases := map[string][]byte{
		"noncanonical-payload": signedRecoveryPayload(t, noncanonical, signer,
			map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}, nil),
		"protected-kid": signedRecoveryPayload(t, canonical, signer,
			map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256,
				cose.HeaderLabelKeyID: []byte("unexpected")}, nil),
		"unprotected": signedRecoveryPayload(t, canonical, signer,
			map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256},
			map[any]any{int64(99): uint64(1)}),
	}
	for name, signed := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRequest(signed, resolver); !errors.Is(err, ErrRequestAuthentication) {
				t.Fatalf("got %v", err)
			}
		})
	}

	valid, err := SignRequest(request, signer)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(valid); err != nil {
		t.Fatal(err)
	}
	message.Payload[len(message.Payload)-1] ^= 1
	tampered, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(tampered, resolver); !errors.Is(err, ErrRequestAuthentication) {
		t.Fatalf("tampered payload got %v", err)
	}

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongVerifier, err := cose.NewVerifier(cose.AlgorithmES256, &wrongKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRequest(valid, fixedHostResolver{
		fingerprint: request.HostFingerprint, verifier: wrongVerifier,
	}); !errors.Is(err, ErrRequestAuthentication) {
		t.Fatalf("wrong key got %v", err)
	}
}

func TestRecoveryRequestStrictUnknownAndDuplicateFields(t *testing.T) {
	_, signer, verifier := requestKeys(t)
	request, _ := loadRecoveryRequestVector(t, "artifact-request.json")
	resolver := fixedHostResolver{fingerprint: request.HostFingerprint, verifier: verifier}
	options := cbor.CanonicalEncOptions()
	mode, err := options.EncMode()
	if err != nil {
		t.Fatal(err)
	}
	unknownPayload, err := mode.Marshal(map[uint64]any{
		1: RequestDomain, 2: uint64(1), 3: uint64(2), 4: uint64(2),
		5: request.RequestID[:], 6: request.HostFingerprint[:], 7: request.Nonce[:],
		8: request.ArtifactDigest[:], 9: uint64(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := signedRecoveryPayload(t, unknownPayload, signer,
		map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}, nil)
	if _, err := VerifyRequest(unknown, resolver); !errors.Is(err, ErrRequestAuthentication) {
		t.Fatalf("unknown field got %v", err)
	}

	_, canonical := loadRecoveryRequestVector(t, "artifact-request.json")
	duplicate := append([]byte{0xa9}, canonical[1:]...)
	duplicate = append(duplicate, 0x08, 0x58, 0x20)
	duplicate = append(duplicate, request.ArtifactDigest[:]...)
	duplicateSigned := signedRecoveryPayload(t, duplicate, signer,
		map[any]any{cose.HeaderLabelAlgorithm: cose.AlgorithmES256}, nil)
	if _, err := VerifyRequest(duplicateSigned, resolver); !errors.Is(err, ErrRequestAuthentication) {
		t.Fatalf("duplicate field got %v", err)
	}
}
