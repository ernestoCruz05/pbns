package recovery

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/veraison/go-cose"
)

const (
	RequestDomain  = "PBNS-RECOVERY-REQUEST-v1"
	RequestAAD     = "PBNS-RECOVERY-REQUEST-AAD-v1"
	RequestVersion = uint64(1)

	OperationManifest Operation = 1
	OperationArtifact Operation = 2
)

var (
	ErrRequest               = errors.New("invalid recovery request")
	ErrRequestAuthentication = errors.New("recovery request authentication failed")
)

type Operation uint64

type Request struct {
	Domain          string    `cbor:"1,keyasint"`
	Version         uint64    `cbor:"2,keyasint"`
	Service         uint64    `cbor:"3,keyasint"`
	Operation       Operation `cbor:"4,keyasint"`
	RequestID       [16]byte  `cbor:"5,keyasint"`
	HostFingerprint [32]byte  `cbor:"6,keyasint"`
	Nonce           [32]byte  `cbor:"7,keyasint"`
	ArtifactDigest  [32]byte  `cbor:"8,keyasint"`
}

type HostResolver interface {
	ResolveHost([32]byte) (cose.Verifier, error)
}

func SignRequest(request Request, signer cose.Signer) ([]byte, error) {
	if signer == nil || !request.valid() {
		return nil, ErrRequest
	}
	payload, err := encodeMode.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode recovery request: %w", err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Payload = payload
	if err := message.Sign(rand.Reader, []byte(RequestAAD), signer); err != nil {
		return nil, fmt.Errorf("sign recovery request: %w", err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal recovery request: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumSignedSize {
		return nil, ErrRequest
	}
	return encoded, nil
}

func VerifyRequest(signed []byte, hosts HostResolver) (Request, error) {
	if hosts == nil || len(signed) == 0 || len(signed) > maximumSignedSize {
		return Request{}, ErrRequest
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(signed); err != nil || len(message.Payload) == 0 ||
		!canonicalRequestSign1(signed, message) {
		return Request{}, ErrRequestAuthentication
	}
	var request Request
	if err := decodeMode.Unmarshal(message.Payload, &request); err != nil ||
		!request.valid() || !canonicalPayload(message.Payload, request) {
		return Request{}, ErrRequestAuthentication
	}
	verifier, err := hosts.ResolveHost(request.HostFingerprint)
	if err != nil || verifier == nil {
		return Request{}, ErrRequestAuthentication
	}
	if err := message.Verify([]byte(RequestAAD), verifier); err != nil {
		return Request{}, ErrRequestAuthentication
	}
	return request, nil
}

func canonicalRequestSign1(encoded []byte, message *cose.Sign1Message) bool {
	if !canonicalSign1WithHeaderCount(encoded, message, 1) {
		return false
	}
	_, hasKeyID := message.Headers.Protected[cose.HeaderLabelKeyID]
	return !hasKeyID
}

func (request Request) valid() bool {
	if request.Domain != RequestDomain || request.Version != RequestVersion ||
		request.Service != ServiceRecoveryArtifact ||
		allZero(request.RequestID[:]) || allZero(request.HostFingerprint[:]) ||
		allZero(request.Nonce[:]) {
		return false
	}
	digestZero := allZero(request.ArtifactDigest[:])
	return request.Operation == OperationManifest && digestZero ||
		request.Operation == OperationArtifact && !digestZero
}
