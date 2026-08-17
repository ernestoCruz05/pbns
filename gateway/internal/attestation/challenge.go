// Package attestation issues one-use attestation challenges and authenticates evidence.
package attestation

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/model"
)

const (
	Domain               = "PBNS-ATTESTATION-v1"
	ServiceAttestation   = uint64(3)
	challengeAADDomain   = "PBNS-ATTESTATION-CHALLENGE-SIGN-v1"
	signAADDomain        = "PBNS-ATTESTATION-SIGN-v1"
	encryptAADDomain     = "PBNS-ATTESTATION-ENCRYPT-v1"
	maxChallengeLifetime = 10 * time.Minute
)

var (
	ErrInvalid        = errors.New("invalid attestation object")
	ErrChallenge      = errors.New("attestation challenge unavailable")
	ErrDecryption     = errors.New("attestation evidence decryption failed")
	ErrAuthentication = errors.New("attestation evidence authentication failed")
	ErrContext        = errors.New("attestation evidence context mismatch")
	ErrVerification   = errors.New("attestation TPM verification failed")
)

type Context struct {
	Domain          string   `cbor:"1,keyasint"`
	Version         uint64   `cbor:"2,keyasint"`
	Service         uint64   `cbor:"3,keyasint"`
	RequestID       [16]byte `cbor:"4,keyasint"`
	HostFingerprint [32]byte `cbor:"5,keyasint"`
	Nonce           [32]byte `cbor:"6,keyasint"`
	IssuedAtUnixNS  uint64   `cbor:"7,keyasint"`
	ExpiresAtUnixNS uint64   `cbor:"8,keyasint"`
	Body            []byte   `cbor:"9,keyasint"`
}

type Challenge struct {
	Context         Context            `cbor:"1,keyasint"`
	VerifierNonce   [32]byte           `cbor:"10,keyasint"`
	Selection       model.PCRSelection `cbor:"11,keyasint"`
	RecipientKID    []byte             `cbor:"12,keyasint"`
	ExpiresAtUnixNS int64              `cbor:"13,keyasint"`
}

type IssuedChallenge struct {
	RequestID [16]byte
	Signed    []byte
	ExpiresAt time.Time
}

func challengeAAD(requestID [16]byte, host [32]byte, nonce [32]byte, kid []byte) []byte {
	return mustCanonical([]any{challengeAADDomain, uint64(1), ServiceAttestation, requestID[:], host[:], nonce[:], kid})
}

func signAAD(challenge Challenge, akName []byte) []byte {
	return mustCanonical([]any{signAADDomain, uint64(1), challenge.Context.RequestID[:], challenge.Context.HostFingerprint[:], challenge.VerifierNonce[:], akName})
}

func encryptAAD(challenge Challenge) []byte {
	return mustCanonical([]any{encryptAADDomain, uint64(1), ServiceAttestation, challenge.Context.RequestID[:], challenge.Context.HostFingerprint[:], challenge.VerifierNonce[:], challenge.RecipientKID})
}

func validContext(context Context) bool {
	return context.Domain == Domain && context.Version == 1 && context.Service == ServiceAttestation &&
		!allZero(context.RequestID[:]) && !allZero(context.HostFingerprint[:]) && !allZero(context.Nonce[:]) &&
		context.IssuedAtUnixNS > 0 && context.ExpiresAtUnixNS > context.IssuedAtUnixNS && len(context.Body) == 0
}

func validChallenge(challenge Challenge) bool {
	return validContext(challenge.Context) && challenge.Context.Nonce == challenge.VerifierNonce &&
		challenge.ExpiresAtUnixNS > 0 && uint64(challenge.ExpiresAtUnixNS) == challenge.Context.ExpiresAtUnixNS &&
		challenge.Selection.Valid() && len(challenge.RecipientKID) > 0 && len(challenge.RecipientKID) <= 64
}

func canonicalChallengeSign1(encoded []byte, message *cose.Sign1Message, expectedKID []byte) bool {
	if message == nil || len(expectedKID) == 0 || len(expectedKID) > 64 || len(message.Payload) == 0 || len(message.Signature) != 64 ||
		len(message.Headers.Protected) != 2 || len(message.Headers.Unprotected) != 0 {
		return false
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmES256 || !bytes.Equal(messageKeyID(message), expectedKID) {
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
	unprotected, err := canonicalMode.Marshal(message.Headers.Unprotected)
	if err != nil || !bytes.Equal(unprotected, message.Headers.RawUnprotected) {
		return false
	}
	canonical, err := message.MarshalCBOR()
	return err == nil && bytes.Equal(canonical, encoded)
}

func decodeChallenge(encoded, expectedKID []byte) (*cose.Sign1Message, Challenge, error) {
	if len(expectedKID) == 0 || len(expectedKID) > 64 || len(encoded) == 0 || len(encoded) > 4096 {
		return nil, Challenge{}, ErrInvalid
	}
	message := cose.NewSign1Message()
	var challenge Challenge
	if message.UnmarshalCBOR(encoded) != nil || !canonicalChallengeSign1(encoded, message, expectedKID) ||
		decodeCanonical(message.Payload, &challenge) != nil || !validChallenge(challenge) {
		return nil, Challenge{}, ErrInvalid
	}
	return message, challenge, nil
}

// VerifyChallenge verifies a gateway-issued challenge for a caller that knows its fixed context.
func VerifyChallenge(encoded []byte, verifier cose.Verifier, requestID [16]byte, host [32]byte, nonce [32]byte, recipientKID, challengeKID []byte) (Challenge, error) {
	message, challenge, err := decodeChallenge(encoded, challengeKID)
	algorithm, algorithmErr := messageAlgorithm(message)
	if err != nil || verifier == nil || algorithmErr != nil || algorithm != cose.AlgorithmES256 ||
		!bytes.Equal(messageKeyID(message), challengeKID) || challenge.Context.RequestID != requestID || challenge.Context.HostFingerprint != host ||
		challenge.VerifierNonce != nonce || !bytes.Equal(challenge.RecipientKID, recipientKID) || message.Verify(challengeAAD(requestID, host, nonce, recipientKID), verifier) != nil {
		return Challenge{}, ErrAuthentication
	}
	return cloneChallenge(challenge), nil
}

func messageAlgorithm(message *cose.Sign1Message) (cose.Algorithm, error) {
	if message == nil {
		return 0, ErrInvalid
	}
	return message.Headers.Protected.Algorithm()
}

func messageKeyID(message *cose.Sign1Message) []byte {
	if message == nil {
		return nil
	}
	value, ok := message.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	if !ok {
		return nil
	}
	return value
}

func cloneChallenge(challenge Challenge) Challenge {
	clone := challenge
	clone.Context.Body = append([]byte(nil), challenge.Context.Body...)
	clone.Selection = challenge.Selection.Clone()
	clone.RecipientKID = append([]byte(nil), challenge.RecipientKID...)
	return clone
}

func mustCanonical(value any) []byte {
	encoded, err := canonicalMode.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("canonical CBOR: %v", err))
	}
	return encoded
}

func allZero(value []byte) bool {
	var combined byte
	for _, value := range value {
		combined |= value
	}
	return combined == 0
}
