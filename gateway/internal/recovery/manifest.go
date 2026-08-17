package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
)

const (
	Domain                  = "PBNS-RECOVERY-MANIFEST-v1"
	manifestAADDomain       = "PBNS-RECOVERY-MANIFEST-AAD-v1"
	Version                 = uint64(1)
	ServiceRecoveryArtifact = uint64(2)
	ArchitectureX8664       = "x86_64"
	FormatUKIPECOFF         = "uki-pe-coff"
	ChunkSize               = uint32(16_384)
	MaximumImageSize        = uint64(268_435_456)
	maximumPolicySize       = 4096
	maximumKeyIDSize        = 64
	maximumSignedSize       = 64 * 1024
)

var (
	ErrManifest       = errors.New("invalid recovery manifest")
	ErrManifestAuth   = errors.New("recovery manifest authentication failed")
	ErrManifestPolicy = errors.New("recovery manifest policy rejected")
	ErrKeyReuse       = errors.New("recovery manifest key equals Secure Boot image key")
	encodeMode        cbor.EncMode
	decodeMode        cbor.DecMode
)

type CommonContext struct {
	Domain      string   `cbor:"1,keyasint"`
	Version     uint64   `cbor:"2,keyasint"`
	Service     uint64   `cbor:"3,keyasint"`
	RequestID   [16]byte `cbor:"4,keyasint"`
	HostBinding [32]byte `cbor:"5,keyasint"`
	Nonce       [32]byte `cbor:"6,keyasint"`
	IssuedAtNS  int64    `cbor:"7,keyasint"`
	ExpiresAtNS int64    `cbor:"8,keyasint"`
	Body        []byte   `cbor:"9,keyasint"`
}

type Manifest struct {
	Context             CommonContext `cbor:"1,keyasint"`
	ArtifactDigest      [32]byte      `cbor:"10,keyasint"`
	ArtifactVersion     uint64        `cbor:"11,keyasint"`
	Architecture        string        `cbor:"12,keyasint"`
	Format              string        `cbor:"13,keyasint"`
	ImageSize           uint64        `cbor:"14,keyasint"`
	ChunkSize           uint32        `cbor:"15,keyasint"`
	MinimumVersion      uint64        `cbor:"16,keyasint"`
	NotBeforeNS         int64         `cbor:"17,keyasint"`
	NotAfterNS          int64         `cbor:"18,keyasint"`
	PolicyAuthorization []byte        `cbor:"19,keyasint"`
	PolicyKeyID         []byte        `cbor:"20,keyasint"`
}

type Expectation struct {
	RequestID            [16]byte
	HostBinding          [32]byte
	Nonce                [32]byte
	RecoverySigningKeyID []byte
	ExpectedPolicyKeyID  []byte
	CurrentVersion       uint64
	TrustedEarliestNS    int64
	TrustedLatestNS      int64
}

type Publisher struct {
	repository *Repository
	signer     *keys.AuthorizedSigner
}

type Publication struct {
	Artifact Artifact
	Manifest Manifest
	Signed   []byte
}

func init() {
	var err error
	encodeMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decodeMode, err = (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxArrayElements: 16,
		MaxMapPairs: 24, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func NewPublisher(repository *Repository, signer *keys.AuthorizedSigner,
	secureBootImageKey any) (*Publisher, error) {
	if repository == nil || signer == nil || secureBootImageKey == nil {
		return nil, ErrManifest
	}
	if err := signer.RequireRole(keys.RoleRecoveryManifest); err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKIXPublicKey(secureBootImageKey)
	if err != nil {
		return nil, ErrManifest
	}
	if signer.PublicKeyFingerprint() == sha256.Sum256(encoded) {
		return nil, ErrKeyReuse
	}
	return &Publisher{repository: repository, signer: signer}, nil
}

func (publisher *Publisher) Publish(source string, manifest Manifest) (Publication, error) {
	if publisher == nil || publisher.repository == nil || publisher.signer == nil {
		return Publication{}, ErrManifest
	}
	candidate := manifest
	candidate.ArtifactDigest = [sha256.Size]byte{1}
	candidate.ImageSize = 1
	if !candidate.valid() {
		return Publication{}, ErrManifest
	}
	artifact, err := publisher.repository.Publish(source)
	if err != nil {
		return Publication{}, err
	}
	manifest.ArtifactDigest = artifact.Digest
	manifest.ImageSize = artifact.Size
	signed, err := SignManifest(manifest, publisher.signer)
	if err != nil {
		return Publication{}, err
	}
	return Publication{Artifact: artifact, Manifest: manifest, Signed: signed}, nil
}

func EncodeManifest(manifest Manifest) ([]byte, error) {
	if !manifest.valid() {
		return nil, ErrManifest
	}
	payload, err := encodeMode.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode recovery manifest: %w", err)
	}
	return payload, nil
}

func SignManifest(manifest Manifest, signer *keys.AuthorizedSigner) ([]byte, error) {
	if signer == nil {
		return nil, ErrManifestAuth
	}
	if err := signer.RequireRole(keys.RoleRecoveryManifest); err != nil {
		return nil, err
	}
	payload, err := EncodeManifest(manifest)
	if err != nil {
		return nil, err
	}
	keyID := signer.KeyID()
	if len(keyID) == 0 || len(keyID) > maximumKeyIDSize {
		return nil, ErrManifestAuth
	}
	expectation := Expectation{
		RequestID: manifest.Context.RequestID, HostBinding: manifest.Context.HostBinding,
		Nonce: manifest.Context.Nonce, RecoverySigningKeyID: keyID,
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = append([]byte(nil), keyID...)
	message.Payload = payload
	if err := message.Sign(rand.Reader, manifestAAD(expectation), signer.COSESigner()); err != nil {
		return nil, fmt.Errorf("sign recovery manifest: %w", err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("marshal recovery manifest: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > maximumSignedSize {
		return nil, ErrManifest
	}
	return encoded, nil
}

func VerifyManifest(signed []byte, verifier cose.Verifier,
	expectation Expectation) (Manifest, error) {
	if verifier == nil || len(signed) == 0 || len(signed) > maximumSignedSize ||
		!expectation.valid() {
		return Manifest{}, ErrManifestAuth
	}
	message := cose.NewSign1Message()
	if err := message.UnmarshalCBOR(signed); err != nil || len(message.Payload) == 0 ||
		!canonicalSign1(signed, message) ||
		!protectedKeyIDEqual(message, expectation.RecoverySigningKeyID) {
		return Manifest{}, ErrManifestAuth
	}
	var manifest Manifest
	if err := decodeMode.Unmarshal(message.Payload, &manifest); err != nil ||
		!manifest.valid() || !canonicalPayload(message.Payload, manifest) {
		return Manifest{}, ErrManifest
	}
	if manifest.Context.RequestID != expectation.RequestID ||
		manifest.Context.HostBinding != expectation.HostBinding ||
		manifest.Context.Nonce != expectation.Nonce ||
		!bytes.Equal(manifest.PolicyKeyID, expectation.ExpectedPolicyKeyID) {
		return Manifest{}, ErrManifestAuth
	}
	if manifest.ArtifactVersion < expectation.CurrentVersion ||
		expectation.TrustedEarliestNS < manifest.NotBeforeNS ||
		expectation.TrustedLatestNS > manifest.NotAfterNS {
		return Manifest{}, ErrManifestPolicy
	}
	if err := message.Verify(manifestAAD(expectation), verifier); err != nil {
		return Manifest{}, ErrManifestAuth
	}
	return manifest, nil
}

func (manifest Manifest) Equal(other Manifest) bool {
	return manifest.Context.Domain == other.Context.Domain &&
		manifest.Context.Version == other.Context.Version &&
		manifest.Context.Service == other.Context.Service &&
		manifest.Context.RequestID == other.Context.RequestID &&
		manifest.Context.HostBinding == other.Context.HostBinding &&
		manifest.Context.Nonce == other.Context.Nonce &&
		manifest.Context.IssuedAtNS == other.Context.IssuedAtNS &&
		manifest.Context.ExpiresAtNS == other.Context.ExpiresAtNS &&
		bytes.Equal(manifest.Context.Body, other.Context.Body) &&
		manifest.ArtifactDigest == other.ArtifactDigest &&
		manifest.ArtifactVersion == other.ArtifactVersion &&
		manifest.Architecture == other.Architecture && manifest.Format == other.Format &&
		manifest.ImageSize == other.ImageSize && manifest.ChunkSize == other.ChunkSize &&
		manifest.MinimumVersion == other.MinimumVersion &&
		manifest.NotBeforeNS == other.NotBeforeNS && manifest.NotAfterNS == other.NotAfterNS &&
		bytes.Equal(manifest.PolicyAuthorization, other.PolicyAuthorization) &&
		bytes.Equal(manifest.PolicyKeyID, other.PolicyKeyID)
}

func (expectation Expectation) Clone() Expectation {
	expectation.RecoverySigningKeyID = append([]byte(nil), expectation.RecoverySigningKeyID...)
	expectation.ExpectedPolicyKeyID = append([]byte(nil), expectation.ExpectedPolicyKeyID...)
	return expectation
}

func (manifest Manifest) valid() bool {
	return manifest.Context.Domain == Domain && manifest.Context.Version == Version &&
		manifest.Context.Service == ServiceRecoveryArtifact &&
		!allZero(manifest.Context.RequestID[:]) && !allZero(manifest.Context.HostBinding[:]) &&
		!allZero(manifest.Context.Nonce[:]) && manifest.Context.IssuedAtNS >= 0 &&
		manifest.Context.IssuedAtNS == manifest.NotBeforeNS &&
		manifest.Context.ExpiresAtNS == manifest.NotAfterNS &&
		manifest.Context.IssuedAtNS < manifest.Context.ExpiresAtNS &&
		manifest.Context.Body != nil && len(manifest.Context.Body) == 0 &&
		!allZero(manifest.ArtifactDigest[:]) && manifest.ArtifactVersion > 0 &&
		manifest.ArtifactVersion >= manifest.MinimumVersion &&
		manifest.Architecture == ArchitectureX8664 && manifest.Format == FormatUKIPECOFF &&
		utf8.ValidString(manifest.Architecture) && utf8.ValidString(manifest.Format) &&
		manifest.ImageSize > 0 && manifest.ImageSize <= MaximumImageSize &&
		manifest.ChunkSize == ChunkSize && manifest.NotBeforeNS >= 0 &&
		manifest.NotBeforeNS < manifest.NotAfterNS &&
		len(manifest.PolicyAuthorization) > 0 && len(manifest.PolicyAuthorization) <= maximumPolicySize &&
		len(manifest.PolicyKeyID) > 0 && len(manifest.PolicyKeyID) <= maximumKeyIDSize
}

func (expectation Expectation) valid() bool {
	return !allZero(expectation.RequestID[:]) && !allZero(expectation.HostBinding[:]) &&
		!allZero(expectation.Nonce[:]) && len(expectation.RecoverySigningKeyID) > 0 &&
		len(expectation.RecoverySigningKeyID) <= maximumKeyIDSize &&
		len(expectation.ExpectedPolicyKeyID) > 0 && len(expectation.ExpectedPolicyKeyID) <= maximumKeyIDSize &&
		expectation.TrustedEarliestNS >= 0 && expectation.TrustedEarliestNS <= expectation.TrustedLatestNS
}

func manifestAAD(expectation Expectation) []byte {
	result := make([]byte, 0, len(manifestAADDomain)+len(expectation.RequestID)+
		len(expectation.HostBinding)+len(expectation.Nonce)+len(expectation.RecoverySigningKeyID))
	result = append(result, []byte(manifestAADDomain)...)
	result = append(result, expectation.RequestID[:]...)
	result = append(result, expectation.HostBinding[:]...)
	result = append(result, expectation.Nonce[:]...)
	result = append(result, expectation.RecoverySigningKeyID...)
	return result
}

func canonicalSign1(encoded []byte, message *cose.Sign1Message) bool {
	return canonicalSign1WithHeaderCount(encoded, message, 2)
}

func canonicalSign1WithHeaderCount(encoded []byte, message *cose.Sign1Message,
	protectedCount int) bool {
	if message == nil || len(message.Headers.Unprotected) != 0 ||
		len(message.Headers.Protected) != protectedCount {
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

func protectedKeyIDEqual(message *cose.Sign1Message, expected []byte) bool {
	value, found := message.Headers.Protected[cose.HeaderLabelKeyID]
	if !found {
		return false
	}
	keyID, ok := value.([]byte)
	return ok && bytes.Equal(keyID, expected)
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
