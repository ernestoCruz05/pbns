package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/cosebridge"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/store"
)

var defaultSelection = model.PCRSelection{{Algorithm: 0x000b, Indices: []uint64{0, 2, 4, 7}}}

type Config struct {
	Store        *store.Store
	RecipientKey *ecdsa.PrivateKey
	RecipientKID []byte
	Signer       *keys.AuthorizedSigner
	Clock        func() time.Time
	Random       io.Reader
	ChallengeTTL time.Duration
	Selection    model.PCRSelection
	Verifier     EvidenceConsumer
}

type Service struct {
	store        *store.Store
	recipient    *ecdsa.PrivateKey
	recipientKID []byte
	signer       *keys.AuthorizedSigner
	clock        func() time.Time
	random       io.Reader
	ttl          time.Duration
	selection    model.PCRSelection
	verifier     EvidenceConsumer
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || !validPrivateKey(config.RecipientKey) || len(config.RecipientKID) == 0 || len(config.RecipientKID) > 64 || config.Signer == nil || config.Clock == nil || config.Random == nil || config.Verifier == nil {
		return nil, ErrInvalid
	}
	if err := config.Signer.RequireRole(keys.RoleAttestation); err != nil || config.Signer.COSESigner() == nil || len(config.Signer.KeyID()) == 0 {
		return nil, ErrInvalid
	}
	if config.ChallengeTTL == 0 {
		config.ChallengeTTL = 5 * time.Minute
	}
	if config.ChallengeTTL <= 0 || config.ChallengeTTL > maxChallengeLifetime {
		return nil, ErrInvalid
	}
	if config.Selection == nil {
		config.Selection = defaultSelection
	}
	if !sameSelection(config.Selection, defaultSelection) {
		return nil, ErrInvalid
	}
	return &Service{store: config.Store, recipient: config.RecipientKey, recipientKID: append([]byte(nil), config.RecipientKID...), signer: config.Signer, clock: config.Clock, random: config.Random, ttl: config.ChallengeTTL, selection: config.Selection.Clone(), verifier: config.Verifier}, nil
}

func (service *Service) Issue(hostFingerprint [32]byte) (IssuedChallenge, error) {
	if service == nil || allZero(hostFingerprint[:]) {
		return IssuedChallenge{}, ErrInvalid
	}
	if host, err := service.store.GetHost(hostFingerprint); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return IssuedChallenge{}, ErrChallenge
		}
		return IssuedChallenge{}, err
	} else if sha256.Sum256(host.IdentityCOSEKey) != hostFingerprint {
		return IssuedChallenge{}, ErrChallenge
	}
	now := service.clock().UTC()
	if now.UnixNano() <= 0 {
		return IssuedChallenge{}, ErrInvalid
	}
	expires := now.Add(service.ttl)
	if expires.UnixNano() <= now.UnixNano() {
		return IssuedChallenge{}, ErrInvalid
	}
	for range 4 {
		requestID, err := random16(service.random)
		if err != nil {
			return IssuedChallenge{}, err
		}
		nonce, err := random32(service.random)
		if err != nil {
			return IssuedChallenge{}, err
		}
		challenge := Challenge{Context: Context{Domain: Domain, Version: 1, Service: ServiceAttestation, RequestID: requestID, HostFingerprint: hostFingerprint, Nonce: nonce, IssuedAtUnixNS: uint64(now.UnixNano()), ExpiresAtUnixNS: uint64(expires.UnixNano()), Body: []byte{}}, VerifierNonce: nonce, Selection: service.selection.Clone(), RecipientKID: append([]byte(nil), service.recipientKID...), ExpiresAtUnixNS: expires.UnixNano()}
		if !validChallenge(challenge) {
			return IssuedChallenge{}, ErrInvalid
		}
		signed, err := signChallenge(challenge, service.signer.COSESigner(), service.signer.KeyID(), service.random)
		if err != nil {
			return IssuedChallenge{}, err
		}
		if err := service.store.CreateAttestationChallenge(store.AttestationChallenge{RequestID: requestID, HostFingerprint: hostFingerprint, VerifierNonce: nonce, Selection: challenge.Selection.Clone(), RecipientKID: challenge.RecipientKID, IssuedAtUnixNS: now.UnixNano(), ExpiresAtUnixNS: expires.UnixNano()}); err != nil {
			if errors.Is(err, store.ErrChallengeExists) {
				continue
			}
			return IssuedChallenge{}, err
		}
		return IssuedChallenge{RequestID: requestID, Signed: signed, ExpiresAt: expires}, nil
	}
	return IssuedChallenge{}, store.ErrChallengeExists
}

// Submit authenticates ciphertext bound to requestID. It never stores or logs plaintext evidence.
func (service *Service) Submit(ctx context.Context, requestID [16]byte, ciphertext []byte) (result VerifiedEvidence, err error) {
	if service == nil || ctx == nil || allZero(requestID[:]) {
		return VerifiedEvidence{}, ErrInvalid
	}
	challengeRecord, beginErr := service.store.BeginAttestationChallenge(requestID)
	if beginErr != nil {
		if errors.Is(beginErr, store.ErrChallengeExpired) || errors.Is(beginErr, store.ErrChallengeConsumed) || errors.Is(beginErr, store.ErrNotFound) {
			return VerifiedEvidence{}, ErrChallenge
		}
		return VerifiedEvidence{}, beginErr
	}
	reason := store.AttestationAccepted
	defer func() {
		if finishErr := service.store.FinishAttestationChallenge(requestID, reason); finishErr != nil {
			result = VerifiedEvidence{}
			err = errors.Join(err, fmt.Errorf("finish attestation challenge: %w", finishErr))
		}
	}()
	challenge := challengeFromStore(challengeRecord)
	if len(ciphertext) == 0 || len(ciphertext) > maxEncryptedEvidenceSize {
		reason = store.AttestationFailureInvalid
		return VerifiedEvidence{}, ErrInvalid
	}
	host, getErr := service.store.GetHost(challenge.Context.HostFingerprint)
	if getErr != nil || sha256.Sum256(host.IdentityCOSEKey) != challenge.Context.HostFingerprint {
		reason = store.AttestationFailureHost
		return VerifiedEvidence{}, ErrChallenge
	}
	plaintext, decryptErr := cosebridge.DecryptBounded(service.recipient, challenge.RecipientKID, ciphertext, encryptAAD(challenge), maxEncryptedEvidenceSize)
	if decryptErr != nil {
		reason = store.AttestationFailureDecrypt
		return VerifiedEvidence{}, ErrDecryption
	}
	defer clear(plaintext)
	verified, verifyErr := verifyEvidence(plaintext, challenge, host)
	if verifyErr != nil {
		reason = reasonFor(verifyErr)
		return VerifiedEvidence{}, verifyErr
	}
	if err := ctx.Err(); err != nil {
		reason = store.AttestationFailureCancelled
		return VerifiedEvidence{}, err
	}
	if verifyErr := service.verifier.Verify(cloneVerifiedEvidence(verified)); verifyErr != nil {
		reason = store.AttestationFailureVerification
		return VerifiedEvidence{}, fmt.Errorf("%w: %w", ErrVerification, verifyErr)
	}
	return cloneVerifiedEvidence(verified), nil
}

func challengeFromStore(record store.AttestationChallenge) Challenge {
	return Challenge{Context: Context{Domain: Domain, Version: 1, Service: ServiceAttestation, RequestID: record.RequestID, HostFingerprint: record.HostFingerprint, Nonce: record.VerifierNonce, IssuedAtUnixNS: uint64(record.IssuedAtUnixNS), ExpiresAtUnixNS: uint64(record.ExpiresAtUnixNS), Body: []byte{}}, VerifierNonce: record.VerifierNonce, Selection: record.Selection.Clone(), RecipientKID: append([]byte(nil), record.RecipientKID...), ExpiresAtUnixNS: record.ExpiresAtUnixNS}
}
func signChallenge(challenge Challenge, signer cose.Signer, keyID []byte, random io.Reader) ([]byte, error) {
	payload, err := canonicalMode.Marshal(challenge)
	if err != nil {
		return nil, ErrInvalid
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = append([]byte(nil), keyID...)
	message.Payload = payload
	if err := message.Sign(random, challengeAAD(challenge.Context.RequestID, challenge.Context.HostFingerprint, challenge.VerifierNonce, challenge.RecipientKID), signer); err != nil {
		return nil, ErrAuthentication
	}
	return message.MarshalCBOR()
}
func random16(random io.Reader) ([16]byte, error) {
	var value [16]byte
	if _, err := io.ReadFull(random, value[:]); err != nil || allZero(value[:]) {
		clear(value[:])
		return [16]byte{}, ErrInvalid
	}
	return value, nil
}
func random32(random io.Reader) ([32]byte, error) {
	var value [32]byte
	if _, err := io.ReadFull(random, value[:]); err != nil || allZero(value[:]) {
		clear(value[:])
		return [32]byte{}, ErrInvalid
	}
	return value, nil
}
func sameSelection(left, right model.PCRSelection) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Algorithm != right[index].Algorithm || len(left[index].Indices) != len(right[index].Indices) {
			return false
		}
		for pcr := range left[index].Indices {
			if left[index].Indices[pcr] != right[index].Indices[pcr] {
				return false
			}
		}
	}
	return true
}
func validPrivateKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve != nil && key.Curve.Params() != nil && key.Curve.Params().Name == "P-256" && key.D != nil && key.D.Sign() > 0 && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}
func reasonFor(err error) store.AttestationFailureReason {
	switch {
	case errors.Is(err, ErrAuthentication):
		return store.AttestationFailureAuthentication
	case errors.Is(err, ErrContext):
		return store.AttestationFailureContext
	default:
		return store.AttestationFailureInvalid
	}
}
