package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	controlledbaseline "pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/cosebridge"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/store"
)

const (
	Domain            = "PBNS-ENROLLMENT-v1"
	ServiceEnrollment = uint64(4)
	StageInit         = uint64(1)
	StageChallenge    = uint64(2)
	StageProof        = uint64(3)
	StageReceipt      = uint64(4)
	FlowSoftware      = uint64(1)
	FlowTPM           = uint64(2)

	maximumEnvelopeSize = 65536
	maximumBaselineSize = 60 * 1024
	maximumPublicSize   = 16 * 1024
	maximumCertCount    = 8
)

var (
	ErrInvalid        = errors.New("invalid enrollment object")
	ErrDecryption     = errors.New("enrollment decryption failed")
	ErrAuthentication = errors.New("enrollment authentication failed")
	ErrTranscript     = errors.New("enrollment transcript mismatch")
	ErrState          = errors.New("enrollment state unavailable")
)

type CommonContext struct {
	Domain          string   `cbor:"1,keyasint"`
	Version         uint64   `cbor:"2,keyasint"`
	Service         uint64   `cbor:"3,keyasint"`
	RequestID       [16]byte `cbor:"4,keyasint"`
	HostFingerprint [32]byte `cbor:"5,keyasint"`
	Nonce           [32]byte `cbor:"6,keyasint"`
	Stage           uint64   `cbor:"7,keyasint"`
	Sequence        uint64   `cbor:"8,keyasint"`
	KeyID           []byte   `cbor:"9,keyasint"`
}

type Init struct {
	Context               CommonContext `cbor:"1,keyasint"`
	Token                 [32]byte      `cbor:"10,keyasint"`
	EKPublic              []byte        `cbor:"11,keyasint"`
	EKCertificateChain    [][]byte      `cbor:"12,keyasint"`
	AKPublic              []byte        `cbor:"13,keyasint"`
	AKName                []byte        `cbor:"14,keyasint"`
	IdentityCOSEKey       []byte        `cbor:"15,keyasint"`
	InitialEvidenceDigest [32]byte      `cbor:"16,keyasint"`
	HostNonce             [32]byte      `cbor:"17,keyasint"`
	Flow                  uint64        `cbor:"18,keyasint"`
	AKCreateData          []byte        `cbor:"19,keyasint"`
	AKCreateAttestation   []byte        `cbor:"20,keyasint"`
	AKCreateSignature     []byte        `cbor:"21,keyasint"`
	IdentityTPMPublic     []byte        `cbor:"22,keyasint"`
}

func (Init) String() string {
	return "PBNS enrollment init [redacted]"
}

func (initObject Init) GoString() string {
	return initObject.String()
}

func (initObject Init) LogValue() slog.Value {
	return slog.StringValue(initObject.String())
}

type Challenge struct {
	Context         CommonContext `cbor:"1,keyasint"`
	HostNonce       [32]byte      `cbor:"20,keyasint"`
	ServerNonce     [32]byte      `cbor:"21,keyasint"`
	InitDigest      [32]byte      `cbor:"22,keyasint"`
	CredentialBlob  []byte        `cbor:"23,keyasint"`
	EncryptedSecret []byte        `cbor:"24,keyasint"`
	Flow            uint64        `cbor:"25,keyasint"`
}

type Proof struct {
	Context             CommonContext `cbor:"1,keyasint"`
	ServerNonce         [32]byte      `cbor:"30,keyasint"`
	InitDigest          [32]byte      `cbor:"31,keyasint"`
	ActivatedCredential []byte        `cbor:"32,keyasint"`
	CertifyAttestation  []byte        `cbor:"33,keyasint"`
	CertifySignature    []byte        `cbor:"34,keyasint"`
	BaselineDigest      [32]byte      `cbor:"35,keyasint"`
	BaselineEvidence    []byte        `cbor:"36,keyasint"`
	Flow                uint64        `cbor:"37,keyasint"`
}

type Receipt struct {
	Context        CommonContext   `cbor:"1,keyasint"`
	Fingerprint    [32]byte        `cbor:"40,keyasint"`
	Assurance      model.Assurance `cbor:"41,keyasint"`
	BaselineDigest [32]byte        `cbor:"42,keyasint"`
	EnrolledAtUnix int64           `cbor:"43,keyasint"`
	KeyID          []byte          `cbor:"44,keyasint"`
}

type EncryptedEnvelope struct {
	RequestID    [16]byte `cbor:"1,keyasint"`
	HostNonce    [32]byte `cbor:"2,keyasint"`
	RecipientKID []byte   `cbor:"3,keyasint"`
	Ciphertext   []byte   `cbor:"4,keyasint"`
}

type activationRequest struct {
	EKPublic            []byte
	AKPublic            []byte
	AKName              []byte
	AKCreateData        []byte
	AKCreateAttestation []byte
	AKCreateSignature   []byte
}

type activationChallenge struct {
	Secret          [32]byte
	CredentialBlob  []byte
	EncryptedSecret []byte
}

type Activator interface {
	Generate(request activationRequest) (activationChallenge, error)
}

type Certifier interface {
	Verify(session certificationSession, proof Proof) error
}

type certificationSession struct {
	AKPublic          []byte
	IdentityTPMPublic []byte
	RequestID         [16]byte
	ServerNonce       [32]byte
	InitDigest        [32]byte
	BaselineDigest    [32]byte
	IdentityPublic    *ecdsa.PublicKey
}

type Config struct {
	Store        *store.Store
	RecipientKey *ecdsa.PrivateKey
	RecipientKID []byte
	Signer       *keys.AuthorizedSigner
	Clock        func() time.Time
	Random       io.Reader
	Activator    Activator
	Certifier    Certifier
	EKRoots      *x509.CertPool
}

type pendingSession struct {
	pendingID         [16]byte
	requestID         [16]byte
	hostNonce         [32]byte
	serverNonce       [32]byte
	initDigest        [32]byte
	baselineDigest    [32]byte
	flow              uint64
	identityCOSEKey   []byte
	identityPublic    *ecdsa.PublicKey
	fingerprint       [32]byte
	activationSecret  [32]byte
	akPublic          []byte
	akName            []byte
	ekPublic          []byte
	ekChainDigest     [32]byte
	identityTPMPublic []byte
	assurance         model.Assurance
}

type Service struct {
	store        *store.Store
	recipient    *ecdsa.PrivateKey
	recipientKID []byte
	signer       *keys.AuthorizedSigner
	clock        func() time.Time
	random       io.Reader
	activator    Activator
	certifier    Certifier
	ekRoots      *x509.CertPool
	mutex        sync.Mutex
	sessions     map[[16]byte]*pendingSession
}

var (
	encodeMode cbor.EncMode
	decodeMode cbor.DecMode
)

func init() {
	var err error
	options := cbor.CanonicalEncOptions()
	options.NilContainers = cbor.NilContainerAsEmpty
	encodeMode, err = options.EncMode()
	if err != nil {
		panic(err)
	}
	decodeMode, err = (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 8, MaxArrayElements: 16,
		MaxMapPairs: 32, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || !validPrivateKey(config.RecipientKey) ||
		len(config.RecipientKID) == 0 || len(config.RecipientKID) > 64 ||
		config.Signer == nil || config.Clock == nil || config.Random == nil {
		return nil, ErrInvalid
	}
	if err := config.Signer.RequireRole(keys.RoleEnrollment); err != nil {
		return nil, err
	}
	if config.Signer.COSESigner() == nil || len(config.Signer.KeyID()) == 0 {
		return nil, ErrInvalid
	}
	return &Service{
		store: config.Store, recipient: config.RecipientKey,
		recipientKID: append([]byte(nil), config.RecipientKID...),
		signer:       config.Signer, clock: config.Clock, random: config.Random,
		activator: config.Activator, certifier: config.Certifier, ekRoots: config.EKRoots,
		sessions: make(map[[16]byte]*pendingSession),
	}, nil
}

func (service *Service) Begin(encodedEnvelope []byte) ([]byte, error) {
	envelope, plaintext, err := service.openEnvelope(encodedEnvelope)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	var initObject Init
	if err := decodeCanonical(plaintext, &initObject); err != nil ||
		!validInit(initObject, envelope, service.recipientKID) {
		clear(initObject.Token[:])
		return nil, ErrInvalid
	}
	defer clear(initObject.Token[:])
	identityPublic, err := parseIdentityCOSEKey(initObject.IdentityCOSEKey)
	if err != nil {
		return nil, ErrAuthentication
	}
	fingerprint := sha256.Sum256(initObject.IdentityCOSEKey)
	if fingerprint != initObject.Context.HostFingerprint {
		return nil, ErrAuthentication
	}
	initDigest := sha256.Sum256(plaintext)

	serverNonce, err := random32(service.random)
	if err != nil {
		return nil, err
	}
	session := &pendingSession{
		requestID: initObject.Context.RequestID,
		hostNonce: initObject.HostNonce, serverNonce: serverNonce,
		initDigest: initDigest, baselineDigest: initObject.InitialEvidenceDigest,
		flow: initObject.Flow, identityCOSEKey: append([]byte(nil), initObject.IdentityCOSEKey...),
		identityPublic: identityPublic, fingerprint: fingerprint,
		assurance: model.AssuranceSoftware,
	}
	challenge := Challenge{
		Context: CommonContext{
			Domain: Domain, Version: 1, Service: ServiceEnrollment,
			RequestID: session.requestID, HostFingerprint: session.fingerprint,
			Nonce: session.hostNonce, Stage: StageChallenge, Sequence: 0,
			KeyID: service.signer.KeyID(),
		},
		HostNonce: session.hostNonce, ServerNonce: session.serverNonce,
		InitDigest: session.initDigest, Flow: session.flow,
	}
	if session.flow == FlowSoftware {
		if !softwareInitFieldsEmpty(initObject) {
			return nil, ErrInvalid
		}
	} else {
		if service.activator == nil || service.certifier == nil {
			return nil, ErrState
		}
		activation, activationErr := service.activator.Generate(activationRequest{
			EKPublic: initObject.EKPublic, AKPublic: initObject.AKPublic,
			AKName: initObject.AKName, AKCreateData: initObject.AKCreateData,
			AKCreateAttestation: initObject.AKCreateAttestation,
			AKCreateSignature:   initObject.AKCreateSignature,
		})
		if activationErr != nil {
			return nil, errors.Join(ErrAuthentication, activationErr)
		}
		session.activationSecret = activation.Secret
		clear(activation.Secret[:])
		session.akPublic = append([]byte(nil), initObject.AKPublic...)
		session.akName = append([]byte(nil), initObject.AKName...)
		session.ekPublic = append([]byte(nil), initObject.EKPublic...)
		session.identityTPMPublic = append([]byte(nil), initObject.IdentityTPMPublic...)
		assurance, chainDigest, verifyErr := VerifyEKCertificateChain(
			initObject.EKPublic, initObject.EKCertificateChain, service.ekRoots, service.clock().UTC(),
		)
		if verifyErr != nil {
			clear(session.activationSecret[:])
			return nil, ErrAuthentication
		}
		session.assurance = assurance
		session.ekChainDigest = chainDigest
		challenge.CredentialBlob = append([]byte(nil), activation.CredentialBlob...)
		challenge.EncryptedSecret = append([]byte(nil), activation.EncryptedSecret...)
	}

	service.mutex.Lock()
	defer service.mutex.Unlock()
	pending, err := service.store.BeginEnrollmentSecret(initObject.Token[:], initDigest)
	if err != nil {
		clear(session.activationSecret[:])
		if errors.Is(err, store.ErrTranscriptMismatch) || errors.Is(err, store.ErrRateLimited) {
			return nil, ErrTranscript
		}
		return nil, err
	}
	session.pendingID = pending.ID
	signed, err := signChallenge(challenge, service.signer, service.random)
	if err != nil {
		clear(session.activationSecret[:])
		return nil, err
	}
	if previous := service.sessions[session.requestID]; previous != nil {
		clear(previous.activationSecret[:])
	}
	service.sessions[session.requestID] = session
	return signed, nil
}

func (service *Service) Complete(encodedEnvelope []byte) ([]byte, error) {
	envelopeDigest := sha256.Sum256(encodedEnvelope)
	envelope, signedProof, err := service.openEnvelope(encodedEnvelope)
	if err != nil {
		return nil, err
	}
	defer clear(signedProof)
	message, proof, err := decodeSignedProof(signedProof)
	if err != nil {
		return nil, err
	}

	service.mutex.Lock()
	defer service.mutex.Unlock()
	session := service.sessions[envelope.RequestID]
	if session == nil {
		receipt, retryErr := service.store.GetCompletedEnrollment(
			envelope.RequestID, envelopeDigest,
		)
		if retryErr == nil {
			return receipt, nil
		}
		return nil, ErrState
	}
	if !proofMatchesSession(proof, envelope, session, service.recipientKID) {
		return nil, ErrTranscript
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, session.identityPublic)
	if err != nil || message.Verify(proofExternalAAD(proof), verifier) != nil {
		return nil, ErrAuthentication
	}
	if sha256.Sum256(proof.BaselineEvidence) != proof.BaselineDigest ||
		proof.BaselineDigest != session.baselineDigest ||
		len(proof.BaselineEvidence) == 0 || len(proof.BaselineEvidence) > maximumBaselineSize {
		return nil, ErrAuthentication
	}
	if _, err := controlledbaseline.Decode(proof.BaselineEvidence); err != nil {
		return nil, ErrAuthentication
	}
	if session.flow == FlowSoftware {
		if len(proof.ActivatedCredential) != 0 || len(proof.CertifyAttestation) != 0 ||
			len(proof.CertifySignature) != 0 {
			return nil, ErrAuthentication
		}
	} else {
		if !constantTimeEqual(proof.ActivatedCredential, session.activationSecret[:]) {
			return nil, ErrAuthentication
		}
		if err := service.certifier.Verify(certificationSession{
			AKPublic: session.akPublic, IdentityTPMPublic: session.identityTPMPublic,
			RequestID: session.requestID, ServerNonce: session.serverNonce,
			InitDigest: session.initDigest, BaselineDigest: session.baselineDigest,
			IdentityPublic: session.identityPublic,
		}, proof); err != nil {
			return nil, errors.Join(ErrAuthentication, err)
		}
	}
	now := service.clock().UTC()
	if now.Unix() <= 0 {
		return nil, ErrInvalid
	}
	receipt := Receipt{
		Context: CommonContext{
			Domain: Domain, Version: 1, Service: ServiceEnrollment,
			RequestID: session.requestID, HostFingerprint: session.fingerprint,
			Nonce: session.hostNonce, Stage: StageReceipt, Sequence: 2,
			KeyID: service.signer.KeyID(),
		},
		Fingerprint: session.fingerprint, Assurance: session.assurance,
		BaselineDigest: session.baselineDigest, EnrolledAtUnix: now.Unix(),
		KeyID: service.signer.KeyID(),
	}
	signedReceipt, err := signReceipt(receipt, service.signer, service.random, session.serverNonce)
	if err != nil {
		return nil, err
	}
	host := model.HostRecord{
		Fingerprint:     session.fingerprint,
		IdentityCOSEKey: append([]byte(nil), session.identityCOSEKey...),
		AKPublic:        append([]byte(nil), session.akPublic...),
		AKName:          append([]byte(nil), session.akName...),
		EKPublic:        append([]byte(nil), session.ekPublic...),
		EKChainDigest:   session.ekChainDigest, Assurance: session.assurance,
		BaselineID: session.baselineDigest, EnrolledAtUnix: now.Unix(),
	}
	if err := service.store.CompleteEnrollmentTranscript(
		session.pendingID, host, proof.BaselineEvidence, signedReceipt,
		session.requestID, envelopeDigest,
	); err != nil {
		return nil, err
	}
	clear(session.activationSecret[:])
	delete(service.sessions, session.requestID)
	return signedReceipt, nil
}

func (service *Service) openEnvelope(encoded []byte) (EncryptedEnvelope, []byte, error) {
	if service == nil || len(encoded) == 0 || len(encoded) > maximumEnvelopeSize {
		return EncryptedEnvelope{}, nil, ErrInvalid
	}
	var envelope EncryptedEnvelope
	if err := decodeCanonical(encoded, &envelope); err != nil ||
		allZero(envelope.RequestID[:]) || allZero(envelope.HostNonce[:]) ||
		!bytes.Equal(envelope.RecipientKID, service.recipientKID) ||
		len(envelope.Ciphertext) == 0 {
		return EncryptedEnvelope{}, nil, ErrInvalid
	}
	plaintext, err := cosebridge.Decrypt(
		service.recipient, service.recipientKID, envelope.Ciphertext,
		envelopeAAD(envelope.RequestID, envelope.HostNonce, envelope.RecipientKID),
	)
	if err != nil {
		return EncryptedEnvelope{}, nil, ErrDecryption
	}
	return envelope, plaintext, nil
}

func SignProof(proof Proof, signer cose.Signer) ([]byte, error) {
	if signer == nil || !validProofShape(proof) {
		return nil, ErrInvalid
	}
	payload, err := encodeCanonical(proof)
	if err != nil {
		return nil, err
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Payload = payload
	if err := message.Sign(cryptorand.Reader, proofExternalAAD(proof), signer); err != nil {
		return nil, ErrAuthentication
	}
	return message.MarshalCBOR()
}

func VerifyChallenge(
	encoded []byte,
	verifier cose.Verifier,
	expectedKeyID []byte,
	requestID [16]byte,
	hostNonce [32]byte,
) (Challenge, error) {
	var challenge Challenge
	message, err := decodeSign1(encoded, &challenge)
	if err != nil || verifier == nil || !validChallenge(challenge) ||
		challenge.Context.RequestID != requestID || challenge.HostNonce != hostNonce ||
		challenge.Context.Nonce != hostNonce ||
		!bytes.Equal(challenge.Context.KeyID, expectedKeyID) ||
		!protectedKeyIDEqual(message, expectedKeyID) ||
		message.Verify(challengeExternalAAD(challenge), verifier) != nil {
		return Challenge{}, ErrAuthentication
	}
	return challenge, nil
}

func VerifyReceipt(
	encoded []byte,
	verifier cose.Verifier,
	expectedKeyID []byte,
	requestID [16]byte,
	hostNonce [32]byte,
	serverNonce [32]byte,
) (Receipt, error) {
	var receipt Receipt
	message, err := decodeSign1(encoded, &receipt)
	if err != nil || verifier == nil || !validReceipt(receipt) ||
		receipt.Context.RequestID != requestID || receipt.Context.Nonce != hostNonce ||
		!bytes.Equal(receipt.KeyID, expectedKeyID) ||
		!bytes.Equal(receipt.Context.KeyID, expectedKeyID) ||
		!protectedKeyIDEqual(message, expectedKeyID) ||
		message.Verify(receiptExternalAAD(receipt, serverNonce), verifier) != nil {
		return Receipt{}, ErrAuthentication
	}
	return receipt, nil
}

func signChallenge(
	challenge Challenge,
	signer *keys.AuthorizedSigner,
	random io.Reader,
) ([]byte, error) {
	payload, err := encodeCanonical(challenge)
	if err != nil {
		return nil, err
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = signer.KeyID()
	message.Payload = payload
	if err := message.Sign(random, challengeExternalAAD(challenge), signer.COSESigner()); err != nil {
		return nil, ErrAuthentication
	}
	return message.MarshalCBOR()
}

func signReceipt(
	receipt Receipt,
	signer *keys.AuthorizedSigner,
	random io.Reader,
	serverNonce [32]byte,
) ([]byte, error) {
	payload, err := encodeCanonical(receipt)
	if err != nil {
		return nil, err
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = signer.KeyID()
	message.Payload = payload
	if err := message.Sign(random, receiptExternalAAD(receipt, serverNonce), signer.COSESigner()); err != nil {
		return nil, ErrAuthentication
	}
	return message.MarshalCBOR()
}

func decodeSignedProof(encoded []byte) (*cose.Sign1Message, Proof, error) {
	var proof Proof
	message, err := decodeSign1(encoded, &proof)
	if err != nil || !validProofShape(proof) {
		return nil, Proof{}, ErrInvalid
	}
	return message, proof, nil
}

func decodeSign1(encoded []byte, destination any) (*cose.Sign1Message, error) {
	if len(encoded) == 0 || len(encoded) > maximumEnvelopeSize || destination == nil {
		return nil, ErrInvalid
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(encoded); err != nil || len(message.Payload) == 0 ||
		!canonicalSign1(encoded, message) || decodeCanonical(message.Payload, destination) != nil {
		return nil, ErrInvalid
	}
	return message, nil
}

func encodeCanonical(value any) ([]byte, error) {
	encoded, err := encodeMode.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode enrollment object: %w", ErrInvalid)
	}
	return encoded, nil
}

func decodeCanonical(encoded []byte, destination any) error {
	if len(encoded) == 0 || destination == nil || decodeMode.Unmarshal(encoded, destination) != nil {
		return ErrInvalid
	}
	canonical, err := encodeCanonical(destination)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return ErrInvalid
	}
	return nil
}

func IdentityVerifier(encoded []byte) (cose.Verifier, [32]byte, error) {
	public, err := parseIdentityCOSEKey(encoded)
	if err != nil {
		return nil, [32]byte{}, err
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, public)
	if err != nil {
		return nil, [32]byte{}, ErrAuthentication
	}
	return verifier, sha256.Sum256(encoded), nil
}

func parseIdentityCOSEKey(encoded []byte) (*ecdsa.PublicKey, error) {
	if len(encoded) == 0 || len(encoded) > maximumPublicSize {
		return nil, ErrInvalid
	}
	var fields map[int64]cbor.RawMessage
	if err := decodeCanonical(encoded, &fields); err != nil || len(fields) != 4 {
		return nil, ErrInvalid
	}
	var keyType, curve int64
	var xBytes, yBytes []byte
	if decodeMode.Unmarshal(fields[1], &keyType) != nil || keyType != 2 ||
		decodeMode.Unmarshal(fields[-1], &curve) != nil || curve != 1 ||
		decodeMode.Unmarshal(fields[-2], &xBytes) != nil || len(xBytes) != 32 ||
		decodeMode.Unmarshal(fields[-3], &yBytes) != nil || len(yBytes) != 32 {
		return nil, ErrInvalid
	}
	public := &ecdsa.PublicKey{
		Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes),
	}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, ErrInvalid
	}
	return public, nil
}

func validPrivateKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.D != nil &&
		key.D.Sign() > 0 && key.D.Cmp(key.Curve.Params().N) < 0 &&
		key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

func validInit(initObject Init, envelope EncryptedEnvelope, recipientKID []byte) bool {
	return validContext(initObject.Context, StageInit, 0) &&
		initObject.Context.RequestID == envelope.RequestID &&
		initObject.Context.Nonce == envelope.HostNonce && initObject.HostNonce == envelope.HostNonce &&
		!allZero(initObject.Token[:]) && !allZero(initObject.InitialEvidenceDigest[:]) &&
		len(initObject.IdentityCOSEKey) > 0 && len(initObject.IdentityCOSEKey) <= maximumPublicSize &&
		(initObject.Flow == FlowSoftware || initObject.Flow == FlowTPM) &&
		bytes.Equal(initObject.Context.KeyID, recipientKID) &&
		len(initObject.EKCertificateChain) <= maximumCertCount
}

func softwareInitFieldsEmpty(initObject Init) bool {
	return len(initObject.EKPublic) == 0 && len(initObject.EKCertificateChain) == 0 &&
		len(initObject.AKPublic) == 0 && len(initObject.AKName) == 0 &&
		len(initObject.AKCreateData) == 0 && len(initObject.AKCreateAttestation) == 0 &&
		len(initObject.AKCreateSignature) == 0 && len(initObject.IdentityTPMPublic) == 0
}

func validChallenge(challenge Challenge) bool {
	return validContext(challenge.Context, StageChallenge, 0) &&
		challenge.HostNonce == challenge.Context.Nonce && !allZero(challenge.ServerNonce[:]) &&
		!allZero(challenge.InitDigest[:]) &&
		(challenge.Flow == FlowSoftware || challenge.Flow == FlowTPM)
}

func validProofShape(proof Proof) bool {
	return validContext(proof.Context, StageProof, 1) && !allZero(proof.ServerNonce[:]) &&
		!allZero(proof.InitDigest[:]) && !allZero(proof.BaselineDigest[:]) &&
		len(proof.BaselineEvidence) > 0 && len(proof.BaselineEvidence) <= maximumBaselineSize &&
		(proof.Flow == FlowSoftware || proof.Flow == FlowTPM)
}

func validReceipt(receipt Receipt) bool {
	return validContext(receipt.Context, StageReceipt, 2) && !allZero(receipt.Fingerprint[:]) &&
		receipt.Assurance.Valid() && !allZero(receipt.BaselineDigest[:]) &&
		receipt.EnrolledAtUnix > 0 && len(receipt.KeyID) > 0 && len(receipt.KeyID) <= 64
}

func validContext(context CommonContext, stage, sequence uint64) bool {
	return context.Domain == Domain && context.Version == 1 && context.Service == ServiceEnrollment &&
		!allZero(context.RequestID[:]) && !allZero(context.HostFingerprint[:]) &&
		!allZero(context.Nonce[:]) && context.Stage == stage && context.Sequence == sequence &&
		len(context.KeyID) > 0 && len(context.KeyID) <= 64
}

func proofMatchesSession(
	proof Proof,
	envelope EncryptedEnvelope,
	session *pendingSession,
	recipientKID []byte,
) bool {
	return proof.Context.RequestID == session.requestID && envelope.RequestID == session.requestID &&
		proof.Context.HostFingerprint == session.fingerprint && proof.Context.Nonce == session.hostNonce &&
		envelope.HostNonce == session.hostNonce && proof.ServerNonce == session.serverNonce &&
		proof.InitDigest == session.initDigest && proof.BaselineDigest == session.baselineDigest &&
		proof.Flow == session.flow && bytes.Equal(proof.Context.KeyID, recipientKID)
}

func envelopeAAD(requestID [16]byte, hostNonce [32]byte, keyID []byte) []byte {
	result := make([]byte, 0, len("PBNS-ENROLLMENT-ENVELOPE-v1")+len(requestID)+len(hostNonce)+len(keyID))
	result = append(result, []byte("PBNS-ENROLLMENT-ENVELOPE-v1")...)
	result = append(result, requestID[:]...)
	result = append(result, hostNonce[:]...)
	result = append(result, keyID...)
	return result
}

func challengeExternalAAD(challenge Challenge) []byte {
	result := make([]byte, 0, len("PBNS-ENROLLMENT-CHALLENGE-v1")+
		len(challenge.Context.RequestID)+len(challenge.HostNonce)+len(challenge.ServerNonce)+
		len(challenge.InitDigest)+len(challenge.Context.KeyID))
	result = append(result, []byte("PBNS-ENROLLMENT-CHALLENGE-v1")...)
	result = append(result, challenge.Context.RequestID[:]...)
	result = append(result, challenge.HostNonce[:]...)
	result = append(result, challenge.ServerNonce[:]...)
	result = append(result, challenge.InitDigest[:]...)
	result = append(result, challenge.Context.KeyID...)
	return result
}

func proofExternalAAD(proof Proof) []byte {
	result := make([]byte, 0, len("PBNS-ENROLLMENT-PROOF-v1")+
		len(proof.Context.RequestID)+len(proof.Context.Nonce)+len(proof.ServerNonce)+
		len(proof.InitDigest)+len(proof.Context.KeyID))
	result = append(result, []byte("PBNS-ENROLLMENT-PROOF-v1")...)
	result = append(result, proof.Context.RequestID[:]...)
	result = append(result, proof.Context.Nonce[:]...)
	result = append(result, proof.ServerNonce[:]...)
	result = append(result, proof.InitDigest[:]...)
	result = append(result, proof.Context.KeyID...)
	return result
}

func receiptExternalAAD(receipt Receipt, serverNonce [32]byte) []byte {
	result := make([]byte, 0, len("PBNS-ENROLLMENT-RECEIPT-v1")+
		len(receipt.Context.RequestID)+len(receipt.Context.Nonce)+len(serverNonce)+
		len(receipt.Fingerprint)+len(receipt.KeyID))
	result = append(result, []byte("PBNS-ENROLLMENT-RECEIPT-v1")...)
	result = append(result, receipt.Context.RequestID[:]...)
	result = append(result, receipt.Context.Nonce[:]...)
	result = append(result, serverNonce[:]...)
	result = append(result, receipt.Fingerprint[:]...)
	result = append(result, receipt.KeyID...)
	return result
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

func protectedKeyIDEqual(message *cose.Sign1Message, expected []byte) bool {
	value, found := message.Headers.Protected[cose.HeaderLabelKeyID]
	if !found {
		return false
	}
	keyID, ok := value.([]byte)
	return ok && bytes.Equal(keyID, expected)
}

func random32(random io.Reader) ([32]byte, error) {
	var result [32]byte
	if _, err := io.ReadFull(random, result[:]); err != nil || allZero(result[:]) {
		clear(result[:])
		return [32]byte{}, ErrInvalid
	}
	return result, nil
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func constantTimeEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
