package time

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	stdtime "time"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
)

type fakeClock struct {
	now         stdtime.Time
	monotonic   stdtime.Duration
	advance     stdtime.Duration
	uncertainty stdtime.Duration
	quality     string
}

func (clock *fakeClock) Now() stdtime.Time { return clock.now }
func (clock *fakeClock) MonotonicNow() stdtime.Duration {
	result := clock.monotonic
	clock.monotonic += clock.advance
	return result
}
func (clock *fakeClock) Uncertainty() stdtime.Duration { return clock.uncertainty }
func (clock *fakeClock) Quality() string               { return clock.quality }

type hostMap map[[32]byte]cose.Verifier

func (hosts hostMap) ResolveHost(fingerprint [32]byte) (cose.Verifier, error) {
	verifier, found := hosts[fingerprint]
	if !found {
		return nil, errors.New("unknown host")
	}
	return verifier, nil
}

func makeSigner(t *testing.T) (*ecdsa.PrivateKey, cose.Signer, cose.Verifier) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, signer, verifier
}

func signUnchecked(t *testing.T, request Request, signer cose.Signer) []byte {
	t.Helper()
	payload, err := encodeMode.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Payload = payload
	if err := message.Sign(rand.Reader, requestExternalAAD, signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func baseRequest() Request {
	request := Request{Domain: Domain, Version: 1, Service: ServiceTrustedTime, MaxAgeMS: 100}
	for index := range request.RequestID {
		request.RequestID[index] = byte(index + 1)
	}
	for index := range request.HostFingerprint {
		request.HostFingerprint[index] = 0x22
		request.Nonce[index] = 0x33
	}
	return request
}

func newTestService(t *testing.T, clock Clock, hosts HostResolver) (*Service, cose.Verifier) {
	t.Helper()
	privateKey, _, verifier := makeSigner(t)
	online, err := keys.NewPinnedOnlineSigner(keys.RoleTrustedTime, []byte("time-key-1"), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(clock, hosts, online)
	if err != nil {
		t.Fatal(err)
	}
	return service, verifier
}

func TestServiceSignsBoundAssertion(t *testing.T) {
	_, hostSigner, hostVerifier := makeSigner(t)
	request := baseRequest()
	clock := &fakeClock{
		now:         stdtime.Unix(1_800_000_000, 1234),
		monotonic:   stdtime.Second,
		advance:     2 * stdtime.Millisecond,
		uncertainty: 25 * stdtime.Millisecond,
		quality:     "chrony-synchronized",
	}
	service, timeVerifier := newTestService(t, clock, hostMap{request.HostFingerprint: hostVerifier})
	signedRequest, err := SignRequest(request, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	signedAssertion, err := service.Handle(signedRequest)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := VerifyAssertion(signedAssertion, timeVerifier, []byte("time-key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if assertion.RequestID != request.RequestID || assertion.HostFingerprint != request.HostFingerprint ||
		assertion.Nonce != request.Nonce {
		t.Fatal("request binding was not echoed")
	}
	if assertion.UnixSeconds != clock.now.Unix() || assertion.Nanoseconds != uint32(clock.now.Nanosecond()) ||
		assertion.UncertaintyNS != uint64((25*stdtime.Millisecond).Nanoseconds()) ||
		assertion.Quality != "chrony-synchronized" || assertion.MaxAgeMS != request.MaxAgeMS {
		t.Fatalf("unexpected assertion: %+v", assertion)
	}
}

func TestServiceRejectsInvalidHostAndContext(t *testing.T) {
	_, hostSigner, hostVerifier := makeSigner(t)
	request := baseRequest()
	clock := &fakeClock{now: stdtime.Unix(1_800_000_000, 0), uncertainty: stdtime.Millisecond, quality: "test"}
	service, _ := newTestService(t, clock, hostMap{request.HostFingerprint: hostVerifier})

	wrongRequest := request
	wrongRequest.Domain = "OTHER"
	signed := signUnchecked(t, wrongRequest, hostSigner)
	if _, err := service.Handle(signed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong domain: %v", err)
	}

	_, otherSigner, _ := makeSigner(t)
	signed, err := SignRequest(request, otherSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Handle(signed); !errors.Is(err, ErrHostAuthentication) {
		t.Fatalf("wrong host signature: %v", err)
	}

	request.Service = 2
	signed = signUnchecked(t, request, hostSigner)
	if _, err := service.Handle(signed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("wrong service: %v", err)
	}

	request = baseRequest()
	signed, err = SignRequest(request, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(signed); err != nil {
		t.Fatal(err)
	}
	message.Headers.RawUnprotected = nil
	message.Headers.Unprotected[int64(42)] = "not-signed"
	nonCanonical, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Handle(nonCanonical); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unprotected metadata accepted: %v", err)
	}
}

func TestServiceUsesOnlyMonotonicRequestDeadline(t *testing.T) {
	_, hostSigner, hostVerifier := makeSigner(t)
	request := baseRequest()
	request.MaxAgeMS = 5
	clock := &fakeClock{
		now:         stdtime.Unix(1, 0),
		monotonic:   10 * stdtime.Second,
		advance:     10 * stdtime.Millisecond,
		uncertainty: 0,
		quality:     "test",
	}
	service, _ := newTestService(t, clock, hostMap{request.HostFingerprint: hostVerifier})
	signed, err := SignRequest(request, hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Handle(signed); !errors.Is(err, ErrExpiredRequest) {
		t.Fatalf("expired request: %v", err)
	}

	request.MaxAgeMS = 0
	if _, err := SignRequest(request, hostSigner); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("zero deadline accepted: %v", err)
	}
}

func TestTrustedTimeVectorVerifiesWithGoCOSE(t *testing.T) {
	encoded, err := os.ReadFile("../../../tests/vectors/trusted-time-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		COSESign1       string `json:"cose_sign1_hex"`
		ExternalAAD     string `json:"external_aad_hex"`
		RequestID       string `json:"request_id"`
		HostFingerprint string `json:"host_fingerprint"`
		Nonce           string `json:"nonce"`
		KeyID           string `json:"key_id"`
	}
	if err := json.Unmarshal(encoded, &fixture); err != nil {
		t.Fatal(err)
	}
	message, err := hex.DecodeString(fixture.COSESign1)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile("../../../tests/fixtures/keys/service-signing-test-public.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid fixture public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("fixture is not an EC public key")
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := VerifyAssertion(message, verifier, []byte(fixture.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(assertion.RequestID[:]) != fixture.RequestID ||
		hex.EncodeToString(assertion.HostFingerprint[:]) != fixture.HostFingerprint ||
		hex.EncodeToString(assertion.Nonce[:]) != fixture.Nonce {
		t.Fatal("fixture context mismatch")
	}
	expectedAAD := assertionExternalAAD(assertion)
	if hex.EncodeToString(expectedAAD) != fixture.ExternalAAD {
		t.Fatal("fixture external AAD mismatch")
	}
}

func TestAssertionRejectsWrongKeyIDAndSignature(t *testing.T) {
	_, hostSigner, hostVerifier := makeSigner(t)
	request := baseRequest()
	clock := &fakeClock{now: stdtime.Unix(1_800_000_000, 0), uncertainty: stdtime.Millisecond, quality: "test"}
	service, verifier := newTestService(t, clock, hostMap{request.HostFingerprint: hostVerifier})
	signed, _ := SignRequest(request, hostSigner)
	response, err := service.Handle(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAssertion(response, verifier, []byte("wrong")); !errors.Is(err, ErrTimeAuthentication) {
		t.Fatalf("wrong kid: %v", err)
	}
	_, _, wrongVerifier := makeSigner(t)
	if _, err := VerifyAssertion(response, wrongVerifier, []byte("time-key-1")); !errors.Is(err, ErrTimeAuthentication) {
		t.Fatalf("wrong signing key: %v", err)
	}
}
