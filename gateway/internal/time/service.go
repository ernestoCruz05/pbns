package time

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math"
	stdtime "time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
)

const (
	Domain             = "PBNS-TIME-v1"
	ServiceTrustedTime = uint64(1)
	maximumMessageSize = 64 * 1024
)

var (
	ErrInvalidRequest     = errors.New("invalid trusted-time request")
	ErrHostAuthentication = errors.New("trusted-time host authentication failed")
	ErrExpiredRequest     = errors.New("trusted-time request expired")
	ErrTimeAuthentication = errors.New("trusted-time assertion authentication failed")
	requestExternalAAD    = []byte("PBNS-TIME-REQUEST-v1")
)

type Request struct {
	Domain          string   `cbor:"1,keyasint"`
	Version         uint64   `cbor:"2,keyasint"`
	Service         uint64   `cbor:"3,keyasint"`
	RequestID       [16]byte `cbor:"4,keyasint"`
	HostFingerprint [32]byte `cbor:"5,keyasint"`
	Nonce           [32]byte `cbor:"6,keyasint"`
	MaxAgeMS        uint32   `cbor:"7,keyasint"`
}

type Assertion struct {
	Domain          string   `cbor:"1,keyasint"`
	Version         uint64   `cbor:"2,keyasint"`
	Service         uint64   `cbor:"3,keyasint"`
	RequestID       [16]byte `cbor:"4,keyasint"`
	HostFingerprint [32]byte `cbor:"5,keyasint"`
	Nonce           [32]byte `cbor:"6,keyasint"`
	UnixSeconds     int64    `cbor:"7,keyasint"`
	Nanoseconds     uint32   `cbor:"8,keyasint"`
	UncertaintyNS   uint64   `cbor:"9,keyasint"`
	Quality         string   `cbor:"10,keyasint"`
	KeyID           []byte   `cbor:"11,keyasint"`
	MaxAgeMS        uint32   `cbor:"12,keyasint"`
}

type HostResolver interface {
	ResolveHost(fingerprint [32]byte) (cose.Verifier, error)
}

type Service struct {
	clock  Clock
	hosts  HostResolver
	signer *keys.AuthorizedSigner
}

var (
	encodeMode cbor.EncMode
	decodeMode cbor.DecMode
)

func init() {
	var err error
	encodeMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decodeMode, err = (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func NewService(clock Clock, hosts HostResolver, signer *keys.AuthorizedSigner) (*Service, error) {
	if clock == nil || hosts == nil || signer == nil {
		return nil, ErrInvalidRequest
	}
	if err := signer.RequireRole(keys.RoleTrustedTime); err != nil {
		return nil, err
	}
	if signer.COSESigner() == nil || len(signer.KeyID()) == 0 {
		return nil, ErrInvalidRequest
	}
	return &Service{clock: clock, hosts: hosts, signer: signer}, nil
}

func SignRequest(request Request, signer cose.Signer) ([]byte, error) {
	if signer == nil || !request.valid() {
		return nil, ErrInvalidRequest
	}
	payload, err := encodeMode.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode trusted-time request: %w", err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Payload = payload
	if err := message.Sign(rand.Reader, requestExternalAAD, signer); err != nil {
		return nil, fmt.Errorf("sign trusted-time request: %w", err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal trusted-time request: %w", err)
	}
	return encoded, nil
}

func (service *Service) Handle(signedRequest []byte) ([]byte, error) {
	if service == nil || len(signedRequest) == 0 || len(signedRequest) > maximumMessageSize {
		return nil, ErrInvalidRequest
	}
	started := service.clock.MonotonicNow()
	if started < 0 {
		return nil, ErrExpiredRequest
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(signedRequest); err != nil || len(message.Payload) == 0 ||
		!canonicalSign1(signedRequest, message) {
		return nil, ErrInvalidRequest
	}
	var request Request
	if err := decodeMode.Unmarshal(message.Payload, &request); err != nil || !request.valid() ||
		!canonicalPayload(message.Payload, request) {
		return nil, ErrInvalidRequest
	}
	log.Printf("[PBNS-TIME] Received trusted time query from host %x", request.HostFingerprint[:8])
	verifier, err := service.hosts.ResolveHost(request.HostFingerprint)
	if err != nil || verifier == nil {
		log.Printf("[PBNS-TIME] ResolveHost failed: %v", err)
		return nil, ErrHostAuthentication
	}
	if err := message.Verify(requestExternalAAD, verifier); err != nil {
		log.Printf("[PBNS-TIME] Request signature verification failed: %v", err)
		return nil, ErrHostAuthentication
	}
	log.Printf("[PBNS-TIME] Host signature verified successfully, issuing time assertion")
	now := service.clock.Now().UTC()
	uncertainty := service.clock.Uncertainty()
	quality := service.clock.Quality()
	if now.Unix() < 0 || uncertainty < 0 || quality == "" || len(quality) > 64 {
		return nil, ErrInvalidClock
	}
	keyID := service.signer.KeyID()
	assertion := Assertion{
		Domain: Domain, Version: 1, Service: ServiceTrustedTime,
		RequestID: request.RequestID, HostFingerprint: request.HostFingerprint, Nonce: request.Nonce,
		UnixSeconds: now.Unix(), Nanoseconds: uint32(now.Nanosecond()),
		UncertaintyNS: uint64(uncertainty.Nanoseconds()), Quality: quality,
		KeyID: keyID, MaxAgeMS: request.MaxAgeMS,
	}
	response, err := signAssertion(assertion, service.signer.COSESigner())
	if err != nil {
		return nil, err
	}
	finished := service.clock.MonotonicNow()
	maximumAge := stdtime.Duration(request.MaxAgeMS) * stdtime.Millisecond
	if finished < started || finished-started > maximumAge {
		return nil, ErrExpiredRequest
	}
	return response, nil
}

func VerifyAssertion(signedAssertion []byte, verifier cose.Verifier, expectedKeyID []byte) (Assertion, error) {
	if verifier == nil || len(expectedKeyID) == 0 || len(signedAssertion) == 0 || len(signedAssertion) > maximumMessageSize {
		return Assertion{}, ErrTimeAuthentication
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(signedAssertion); err != nil || len(message.Payload) == 0 ||
		!canonicalSign1(signedAssertion, message) {
		return Assertion{}, ErrTimeAuthentication
	}
	var assertion Assertion
	if err := decodeMode.Unmarshal(message.Payload, &assertion); err != nil || !assertion.valid() ||
		!canonicalPayload(message.Payload, assertion) ||
		!bytes.Equal(assertion.KeyID, expectedKeyID) || !protectedKeyIDEqual(message, expectedKeyID) {
		return Assertion{}, ErrTimeAuthentication
	}
	if err := message.Verify(assertionExternalAAD(assertion), verifier); err != nil {
		return Assertion{}, ErrTimeAuthentication
	}
	return assertion, nil
}

func signAssertion(assertion Assertion, signer cose.Signer) ([]byte, error) {
	payload, err := encodeMode.Marshal(assertion)
	if err != nil {
		return nil, fmt.Errorf("encode trusted-time assertion: %w", err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = append([]byte(nil), assertion.KeyID...)
	message.Payload = payload
	if err := message.Sign(rand.Reader, assertionExternalAAD(assertion), signer); err != nil {
		return nil, fmt.Errorf("sign trusted-time assertion: %w", err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal trusted-time assertion: %w", err)
	}
	return encoded, nil
}

func canonicalSign1(encoded []byte, message *cose.Sign1Message) bool {
	if message == nil || len(message.Headers.Unprotected) != 0 ||
		len(message.Headers.Protected) == 0 || len(message.Headers.Protected) > 2 {
		return false
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmES256 {
		return false
	}
	for label := range message.Headers.Protected {
		if label != cose.HeaderLabelAlgorithm && label != cose.HeaderLabelKeyID {
			return false
		}
	}
	protected, err := message.Headers.Protected.MarshalCBOR()
	if err != nil || !bytes.Equal(protected, message.Headers.RawProtected) {
		return false
	}
	unprotected, err := encodeMode.Marshal(message.Headers.Unprotected)
	if err != nil || !bytes.Equal(unprotected, message.Headers.RawUnprotected) {
		return false
	}
	canonical, err := message.MarshalCBOR()
	return err == nil && bytes.Equal(canonical, encoded)
}

func canonicalPayload(encoded []byte, value any) bool {
	canonical, err := encodeMode.Marshal(value)
	return err == nil && bytes.Equal(canonical, encoded)
}

func assertionExternalAAD(assertion Assertion) []byte {
	result := make([]byte, 0, len("PBNS-TIME-ASSERTION-v1")+len(assertion.RequestID)+
		len(assertion.HostFingerprint)+len(assertion.Nonce)+len(assertion.KeyID))
	result = append(result, []byte("PBNS-TIME-ASSERTION-v1")...)
	result = append(result, assertion.RequestID[:]...)
	result = append(result, assertion.HostFingerprint[:]...)
	result = append(result, assertion.Nonce[:]...)
	result = append(result, assertion.KeyID...)
	return result
}

func protectedKeyIDEqual(message *cose.Sign1Message, expected []byte) bool {
	value, found := message.Headers.Protected[cose.HeaderLabelKeyID]
	if !found {
		return false
	}
	keyID, ok := value.([]byte)
	return ok && bytes.Equal(keyID, expected)
}

func (request Request) valid() bool {
	return request.Domain == Domain && request.Version == 1 && request.Service == ServiceTrustedTime &&
		request.MaxAgeMS > 0 && request.MaxAgeMS <= 60_000 && !allZero(request.RequestID[:]) &&
		!allZero(request.HostFingerprint[:]) && !allZero(request.Nonce[:])
}

func (assertion Assertion) valid() bool {
	return assertion.Domain == Domain && assertion.Version == 1 && assertion.Service == ServiceTrustedTime &&
		assertion.UnixSeconds >= 0 && assertion.Nanoseconds < 1_000_000_000 &&
		assertion.UncertaintyNS <= math.MaxInt64 && utf8.ValidString(assertion.Quality) &&
		assertion.Quality != "" && len(assertion.Quality) <= 64 && len(assertion.KeyID) > 0 &&
		len(assertion.KeyID) <= 64 && assertion.MaxAgeMS > 0 && assertion.MaxAgeMS <= 60_000 &&
		!allZero(assertion.RequestID[:]) && !allZero(assertion.HostFingerprint[:]) && !allZero(assertion.Nonce[:])
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
