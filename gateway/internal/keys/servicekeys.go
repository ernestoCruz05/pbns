package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Role string

const (
	RoleOfflineRoot        Role = "offline-service-root"
	RoleTrustedTime        Role = "trusted-time"
	RoleRecoveryManifest   Role = "recovery-manifest"
	RoleEnrollment         Role = "enrollment"
	RoleAttestation        Role = "attestation"
	RoleAttestationReceipt Role = "attestation-receipt"
)

var (
	ErrRole              = errors.New("service key role mismatch")
	ErrAuthorization     = errors.New("online service key is not authorized")
	ErrOfflinePrivateKey = errors.New("gateway configuration includes an offline root private key")
	ErrInvalidKey        = errors.New("invalid service key")
)

type OnlineCertificate struct {
	Domain        string `cbor:"0,keyasint"`
	Version       uint64 `cbor:"1,keyasint"`
	Role          Role   `cbor:"2,keyasint"`
	KeyID         []byte `cbor:"3,keyasint"`
	PublicKeyDER  []byte `cbor:"4,keyasint"`
	NotBeforeUnix int64  `cbor:"5,keyasint"`
	NotAfterUnix  int64  `cbor:"6,keyasint"`
	Signature     []byte `cbor:"7,keyasint"`
}

type certificateBody struct {
	Domain        string `cbor:"0,keyasint"`
	Version       uint64 `cbor:"1,keyasint"`
	Role          Role   `cbor:"2,keyasint"`
	KeyID         []byte `cbor:"3,keyasint"`
	PublicKeyDER  []byte `cbor:"4,keyasint"`
	NotBeforeUnix int64  `cbor:"5,keyasint"`
	NotAfterUnix  int64  `cbor:"6,keyasint"`
}

type AuthorizedSigner struct {
	role        Role
	keyID       []byte
	signer      cose.Signer
	mode        string
	fingerprint [sha256.Size]byte
}

var canonicalCBOR cbor.EncMode

func init() {
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	canonicalCBOR = mode
}

func validOnlineRole(role Role) bool {
	switch role {
	case RoleTrustedTime, RoleRecoveryManifest, RoleEnrollment, RoleAttestation, RoleAttestationReceipt:
		return true
	default:
		return false
	}
}

func validPrivateKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve != nil && key.Curve.Params() != nil &&
		key.Curve.Params().Name == "P-256" && key.D != nil && key.D.Sign() > 0 &&
		key.D.Cmp(key.Curve.Params().N) < 0 && validPublicKey(&key.PublicKey)
}

func validPublicKey(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve != nil && key.Curve.Params() != nil &&
		key.Curve.Params().Name == "P-256" && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

func NewPinnedOnlineSigner(role Role, keyID []byte, key *ecdsa.PrivateKey) (*AuthorizedSigner, error) {
	return newAuthorizedSigner(role, keyID, key, "direct-pin")
}

func newAuthorizedSigner(role Role, keyID []byte, key *ecdsa.PrivateKey, mode string) (*AuthorizedSigner, error) {
	if !validOnlineRole(role) {
		return nil, ErrRole
	}
	if !validPrivateKey(key) || len(keyID) == 0 || len(keyID) > 64 {
		return nil, ErrInvalidKey
	}
	encodedPublic, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal signer public key: %w", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		return nil, fmt.Errorf("create ES256 signer: %w", err)
	}
	return &AuthorizedSigner{
		role: role, keyID: append([]byte(nil), keyID...), signer: signer, mode: mode,
		fingerprint: sha256.Sum256(encodedPublic),
	}, nil
}

func (signer *AuthorizedSigner) RequireRole(role Role) error {
	if signer == nil || signer.role != role {
		return ErrRole
	}
	return nil
}

func (signer *AuthorizedSigner) KeyID() []byte {
	if signer == nil {
		return nil
	}
	return append([]byte(nil), signer.keyID...)
}

func (signer *AuthorizedSigner) COSESigner() cose.Signer {
	if signer == nil {
		return nil
	}
	return signer.signer
}

func (signer *AuthorizedSigner) AuthorizationMode() string {
	if signer == nil {
		return ""
	}
	return signer.mode
}

func (signer *AuthorizedSigner) PublicKeyFingerprint() [sha256.Size]byte {
	if signer == nil {
		return [sha256.Size]byte{}
	}
	return signer.fingerprint
}

func IssueOnlineCertificate(root *ecdsa.PrivateKey, role Role, keyID []byte,
	publicKey *ecdsa.PublicKey, notBefore, notAfter time.Time) (OnlineCertificate, error) {
	if !validPrivateKey(root) || !validPublicKey(publicKey) || !validOnlineRole(role) ||
		len(keyID) == 0 || len(keyID) > 64 || !notBefore.Before(notAfter) ||
		root.PublicKey.Equal(publicKey) {
		return OnlineCertificate{}, ErrInvalidKey
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return OnlineCertificate{}, fmt.Errorf("marshal online public key: %w", err)
	}
	body := certificateBody{
		Domain: "PBNS-SERVICE-KEY-v1", Version: 1, Role: role,
		KeyID: append([]byte(nil), keyID...), PublicKeyDER: publicDER,
		NotBeforeUnix: notBefore.Unix(), NotAfterUnix: notAfter.Unix(),
	}
	encoded, err := canonicalCBOR.Marshal(body)
	if err != nil {
		return OnlineCertificate{}, fmt.Errorf("encode online certificate: %w", err)
	}
	digest := sha256.Sum256(encoded)
	signature, err := ecdsa.SignASN1(rand.Reader, root, digest[:])
	if err != nil {
		return OnlineCertificate{}, fmt.Errorf("sign online certificate: %w", err)
	}
	return OnlineCertificate{
		Domain: body.Domain, Version: body.Version, Role: body.Role,
		KeyID: body.KeyID, PublicKeyDER: body.PublicKeyDER,
		NotBeforeUnix: body.NotBeforeUnix, NotAfterUnix: body.NotAfterUnix, Signature: signature,
	}, nil
}

func AuthorizeOnlineSigner(rootPublic *ecdsa.PublicKey, certificate OnlineCertificate,
	privateKey *ecdsa.PrivateKey, requiredRole Role, now time.Time) (*AuthorizedSigner, error) {
	if !validPublicKey(rootPublic) || !validPrivateKey(privateKey) ||
		certificate.Domain != "PBNS-SERVICE-KEY-v1" || certificate.Version != 1 ||
		certificate.Role != requiredRole || !validOnlineRole(requiredRole) {
		return nil, ErrRole
	}
	if now.Unix() < certificate.NotBeforeUnix || now.Unix() > certificate.NotAfterUnix ||
		certificate.NotBeforeUnix >= certificate.NotAfterUnix {
		return nil, ErrAuthorization
	}
	parsed, err := x509.ParsePKIXPublicKey(certificate.PublicKeyDER)
	if err != nil {
		return nil, ErrAuthorization
	}
	certifiedPublic, ok := parsed.(*ecdsa.PublicKey)
	if !ok || !certifiedPublic.Equal(&privateKey.PublicKey) {
		return nil, ErrAuthorization
	}
	body := certificateBody{
		Domain: certificate.Domain, Version: certificate.Version, Role: certificate.Role,
		KeyID: append([]byte(nil), certificate.KeyID...), PublicKeyDER: append([]byte(nil), certificate.PublicKeyDER...),
		NotBeforeUnix: certificate.NotBeforeUnix, NotAfterUnix: certificate.NotAfterUnix,
	}
	encoded, err := canonicalCBOR.Marshal(body)
	if err != nil {
		return nil, ErrAuthorization
	}
	digest := sha256.Sum256(encoded)
	if !ecdsa.VerifyASN1(rootPublic, digest[:], certificate.Signature) {
		return nil, ErrAuthorization
	}
	return newAuthorizedSigner(certificate.Role, certificate.KeyID, privateKey, "offline-root-certificate")
}

func ValidateGatewayKeyPaths(onlinePrivatePath, rootPublicPath, offlineRootPrivatePath string) error {
	if offlineRootPrivatePath != "" {
		return ErrOfflinePrivateKey
	}
	if onlinePrivatePath == "" || rootPublicPath == "" {
		return ErrInvalidKey
	}
	return nil
}

func SaveECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	if path == "" || !validPrivateKey(key) {
		return ErrInvalidKey
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create private key directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect private key directory: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("open private key file: %w", err)
	}
	writeErr := file.Chmod(0o600)
	if writeErr == nil {
		_, writeErr = file.Write(encoded)
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write private key: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close private key: %w", closeErr)
	}
	return nil
}

func LoadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, ErrInvalidKey
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read EC private key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "EC PRIVATE KEY" {
		return nil, ErrInvalidKey
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve == nil || key.Curve.Params().Name != "P-256" {
		return nil, ErrInvalidKey
	}
	return key, nil
}

func SaveECPublicKey(path string, key *ecdsa.PublicKey) error {
	if path == "" || !validPublicKey(key) {
		return ErrInvalidKey
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC public key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return writeNewPublicFile(path, encoded)
}

func LoadECPublicKey(path string) (*ecdsa.PublicKey, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrInvalidKey
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read EC public key: %w", err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, ErrInvalidKey
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve == nil || key.Curve.Params().Name != "P-256" {
		return nil, ErrInvalidKey
	}
	return key, nil
}

func SaveOnlineCertificate(path string, certificate OnlineCertificate) error {
	encoded, err := canonicalCBOR.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("encode online certificate: %w", err)
	}
	return writeNewPublicFile(path, encoded)
}

func LoadOnlineCertificate(path string) (OnlineCertificate, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
		return OnlineCertificate{}, ErrAuthorization
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return OnlineCertificate{}, fmt.Errorf("read online certificate: %w", err)
	}
	decodeMode, err := (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		return OnlineCertificate{}, ErrAuthorization
	}
	var certificate OnlineCertificate
	if err := decodeMode.Unmarshal(encoded, &certificate); err != nil {
		return OnlineCertificate{}, ErrAuthorization
	}
	canonical, err := canonicalCBOR.Marshal(certificate)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return OnlineCertificate{}, ErrAuthorization
	}
	return certificate, nil
}

func writeNewPublicFile(path string, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("open public service-key file: %w", err)
	}
	writeErr := file.Chmod(0o644)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write public service-key file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close public service-key file: %w", closeErr)
	}
	return nil
}
