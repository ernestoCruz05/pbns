// Package deployment defines the single canonical public trust bundle shared by
// the signed UEFI client and the gateway process.
package deployment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/fxamacker/cbor/v2"
)

const Domain = "PBNS-DEPLOYMENT-TRUST-v1"

type Role string

const (
	RoleTime      Role = "time"
	RoleChallenge Role = "challenge"
	RoleRecipient Role = "recipient"
	RoleReceipt   Role = "receipt"
)

var ErrInvalid = errors.New("invalid PBNS deployment trust bundle")

type PublicKey struct {
	KID []byte `cbor:"1,keyasint"`
	X   []byte `cbor:"2,keyasint"`
	Y   []byte `cbor:"3,keyasint"`
}

type Bundle struct {
	Domain          string    `cbor:"1,keyasint"`
	Version         uint64    `cbor:"2,keyasint"`
	TLSServerName   string    `cbor:"3,keyasint"`
	TLSPublicKeyDER []byte    `cbor:"4,keyasint"`
	TLSSPKISHA256   [32]byte  `cbor:"5,keyasint"`
	Time            PublicKey `cbor:"6,keyasint"`
	Challenge       PublicKey `cbor:"7,keyasint"`
	Recipient       PublicKey `cbor:"8,keyasint"`
	Receipt         PublicKey `cbor:"9,keyasint"`
}

type Counterparts struct {
	TLSCertFile     string
	TLSKeyFile      string
	PrivateKeyFiles map[Role]string
	KIDs            map[Role]string
}

// Objects owns the exact deployment objects loaded and matched before any
// persistent store is opened. Callers must pass these objects directly to the
// TLS server and services rather than reopening their configured pathnames.
type Objects struct {
	Bundle         Bundle
	TLSCertificate *tls.Certificate
	PrivateKeys    map[Role]*ecdsa.PrivateKey
}

var canonicalMode cbor.EncMode
var strictMode cbor.DecMode

func init() {
	var err error
	canonicalMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	strictMode, err = (cbor.DecOptions{
		DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxArrayElements: 16, MaxMapPairs: 16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func (bundle Bundle) Clone() Bundle {
	clone := bundle
	clone.TLSPublicKeyDER = append([]byte(nil), bundle.TLSPublicKeyDER...)
	clone.Time = cloneKey(bundle.Time)
	clone.Challenge = cloneKey(bundle.Challenge)
	clone.Recipient = cloneKey(bundle.Recipient)
	clone.Receipt = cloneKey(bundle.Receipt)
	return clone
}

func cloneKey(key PublicKey) PublicKey {
	return PublicKey{KID: append([]byte(nil), key.KID...), X: append([]byte(nil), key.X...), Y: append([]byte(nil), key.Y...)}
}

func (counterparts Counterparts) Clone() Counterparts {
	clone := counterparts
	clone.PrivateKeyFiles = make(map[Role]string, len(counterparts.PrivateKeyFiles))
	for role, path := range counterparts.PrivateKeyFiles {
		clone.PrivateKeyFiles[role] = path
	}
	clone.KIDs = make(map[Role]string, len(counterparts.KIDs))
	for role, kid := range counterparts.KIDs {
		clone.KIDs[role] = kid
	}
	return clone
}

func Marshal(bundle Bundle) ([]byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return canonicalMode.Marshal(bundle)
}

func secureParent(path string) bool {
	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return false
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func readSecureRegular(path string, mode os.FileMode, maximum int64) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalid)
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("%w: maximum <= 0", ErrInvalid)
	}
	if !secureParent(path) {
		return nil, fmt.Errorf("%w: parent directory of %s is not private 0700 owned by current user", ErrInvalid, path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot open %s: %v", ErrInvalid, path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("%w: cannot create os.File for %s", ErrInvalid, path)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: fstat %s failed: %v", ErrInvalid, path, err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalid, path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %s owned by UID %d, current process is UID %d", ErrInvalid, path, stat.Uid, os.Geteuid())
	}
	if os.FileMode(stat.Mode&0o777) != mode {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %s mode is 0%03o, expected 0%03o", ErrInvalid, path, stat.Mode&0o777, mode)
	}
	if stat.Size <= 0 || stat.Size > maximum {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %s size %d invalid (max %d)", ErrInvalid, path, stat.Size, maximum)
	}
	encoded := make([]byte, int(stat.Size))
	_, readErr := io.ReadFull(file, encoded)
	var extra [1]byte
	extraCount, extraErr := file.Read(extra[:])
	var after syscall.Stat_t
	statErr := syscall.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || extraCount != 0 || (extraErr != nil && !errors.Is(extraErr, io.EOF)) || statErr != nil ||
		after.Dev != stat.Dev || after.Ino != stat.Ino || after.Mode != stat.Mode || after.Uid != stat.Uid ||
		after.Gid != stat.Gid || after.Nlink != stat.Nlink || after.Size != stat.Size || after.Mtim != stat.Mtim ||
		after.Ctim != stat.Ctim || closeErr != nil {
		clear(encoded)
		return nil, fmt.Errorf("%w: file changed during read or close failed for %s", ErrInvalid, path)
	}
	return encoded, nil
}

func parseBundle(encoded []byte) (Bundle, error) {
	var bundle Bundle
	if strictMode.Unmarshal(encoded, &bundle) != nil {
		return Bundle{}, ErrInvalid
	}
	canonical, err := canonicalMode.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, encoded) || bundle.Validate() != nil {
		return Bundle{}, ErrInvalid
	}
	return bundle.Clone(), nil
}

func Load(path string) (Bundle, error) {
	encoded, err := readSecureRegular(path, 0o444, 64*1024)
	if err != nil {
		return Bundle{}, err
	}
	return parseBundle(encoded)
}

func (bundle Bundle) roleKeys() map[Role]PublicKey {
	return map[Role]PublicKey{RoleTime: bundle.Time, RoleChallenge: bundle.Challenge, RoleRecipient: bundle.Recipient, RoleReceipt: bundle.Receipt}
}

func publicFrom(key PublicKey) (*ecdsa.PublicKey, error) {
	if len(key.KID) == 0 || len(key.KID) > 64 || len(key.X) != 32 || len(key.Y) != 32 {
		return nil, ErrInvalid
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(key.X), Y: new(big.Int).SetBytes(key.Y)}
	if public.X.Sign() == 0 || public.Y.Sign() == 0 || !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, ErrInvalid
	}
	return public, nil
}

func (bundle Bundle) Validate() error {
	if bundle.Domain != Domain || bundle.Version != 1 || bundle.TLSServerName == "" || len(bundle.TLSServerName) > 253 || strings.IndexByte(bundle.TLSServerName, 0) >= 0 || len(bundle.TLSPublicKeyDER) == 0 || sha256.Sum256(bundle.TLSPublicKeyDER) != bundle.TLSSPKISHA256 || bundle.TLSSPKISHA256 == fixtureTLSDigest {
		return ErrInvalid
	}
	tlsParsed, err := x509.ParsePKIXPublicKey(bundle.TLSPublicKeyDER)
	if err != nil {
		return ErrInvalid
	}
	tlsPublic, ok := tlsParsed.(*ecdsa.PublicKey)
	if !ok || tlsPublic.Curve != elliptic.P256() || !tlsPublic.Curve.IsOnCurve(tlsPublic.X, tlsPublic.Y) {
		return ErrInvalid
	}
	seenKeys := map[string]Role{}
	seenKIDs := map[string]Role{}
	for role, key := range bundle.roleKeys() {
		public, err := publicFrom(key)
		if err != nil || rejectedPublic(public) || public.Equal(tlsPublic) {
			return ErrInvalid
		}
		encoded := elliptic.Marshal(elliptic.P256(), public.X, public.Y)
		if _, exists := seenKeys[string(encoded)]; exists {
			return ErrInvalid
		}
		seenKeys[string(encoded)] = role
		if _, exists := seenKIDs[string(key.KID)]; exists {
			return ErrInvalid
		}
		seenKIDs[string(key.KID)] = role
	}
	return nil
}

func rejectedPublic(public *ecdsa.PublicKey) bool {
	if public == nil {
		return true
	}
	for scalar := int64(1); scalar <= 3; scalar++ {
		x, y := elliptic.P256().ScalarBaseMult(big.NewInt(scalar).Bytes())
		if public.X.Cmp(x) == 0 && public.Y.Cmp(y) == 0 {
			return true
		}
	}
	return public.X.Cmp(new(big.Int).SetBytes(fixtureTimeX)) == 0 && public.Y.Cmp(new(big.Int).SetBytes(fixtureTimeY)) == 0
}

func parsePrivate(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "EC PRIVATE KEY" {
		return nil, ErrInvalid
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() || key.D.Sign() <= 0 {
		return nil, ErrInvalid
	}
	return key, nil
}

func loadPrivate(path string) (*ecdsa.PrivateKey, error) {
	encoded, err := readSecureRegular(path, 0o600, 16*1024)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return parsePrivate(encoded)
}

func loadTLS(certPath, keyPath string) (*tls.Certificate, *x509.Certificate, error) {
	certificatePEM, err := readSecureRegular(certPath, 0o600, 64*1024)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := readSecureRegular(keyPath, 0o600, 16*1024)
	if err != nil {
		return nil, nil, err
	}
	defer clear(keyPEM)
	pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || len(pair.Certificate) != 1 {
		return nil, nil, ErrInvalid
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, ErrInvalid
	}
	private, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() || !private.PublicKey.Equal(leaf.PublicKey) {
		return nil, nil, ErrInvalid
	}
	pair.Leaf = leaf
	return &pair, leaf, nil
}

func matchLoaded(bundle Bundle, counterparts Counterparts) (*Objects, error) {
	if err := bundle.Validate(); err != nil {
		return nil, fmt.Errorf("%w: bundle validate failed: %v", ErrInvalid, err)
	}
	if counterparts.TLSCertFile == "" || counterparts.TLSKeyFile == "" {
		return nil, fmt.Errorf("%w: TLS cert or key path empty", ErrInvalid)
	}
	pair, certificate, err := loadTLS(counterparts.TLSCertFile, counterparts.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: loadTLS failed: %v", ErrInvalid, err)
	}
	if err := certificate.VerifyHostname(bundle.TLSServerName); err != nil {
		return nil, fmt.Errorf("%w: VerifyHostname(%q) failed: %v", ErrInvalid, bundle.TLSServerName, err)
	}
	if !bytes.Equal(certificate.RawSubjectPublicKeyInfo, bundle.TLSPublicKeyDER) {
		return nil, fmt.Errorf("%w: certificate SPKI != bundle SPKI", ErrInvalid)
	}
	if sha256.Sum256(certificate.RawSubjectPublicKeyInfo) != bundle.TLSSPKISHA256 {
		return nil, fmt.Errorf("%w: certificate SPKI SHA256 != bundle SHA256", ErrInvalid)
	}
	privateKeys := make(map[Role]*ecdsa.PrivateKey, len(bundle.roleKeys()))
	for role, expected := range bundle.roleKeys() {
		if counterparts.KIDs[role] != string(expected.KID) {
			return nil, fmt.Errorf("%w: KID mismatch for role %s: got %q expected %q", ErrInvalid, role, counterparts.KIDs[role], string(expected.KID))
		}
		private, err := loadPrivate(counterparts.PrivateKeyFiles[role])
		if err != nil {
			return nil, fmt.Errorf("%w: loadPrivate failed for role %s: %v", ErrInvalid, role, err)
		}
		public, _ := publicFrom(expected)
		if !private.PublicKey.Equal(public) {
			return nil, fmt.Errorf("%w: public key mismatch for role %s", ErrInvalid, role)
		}
		privateKeys[role] = private
	}
	return &Objects{Bundle: bundle.Clone(), TLSCertificate: pair, PrivateKeys: privateKeys}, nil
}

// LoadMatched opens each configured deployment object exactly once with
// O_NOFOLLOW, validates the descriptor metadata and bytes, then matches and
// returns those same parsed objects.
func LoadMatched(bundlePath string, counterparts Counterparts) (*Objects, error) {
	encoded, err := readSecureRegular(bundlePath, 0o444, 64*1024)
	if err != nil {
		return nil, err
	}
	bundle, err := parseBundle(encoded)
	if err != nil {
		return nil, err
	}
	return matchLoaded(bundle, counterparts)
}

func (bundle Bundle) Match(counterparts Counterparts) error {
	_, err := matchLoaded(bundle, counterparts)
	return err
}

func ParseHexDigest(value []byte) ([32]byte, error) {
	decoded, err := hex.DecodeString(string(value))
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, ErrInvalid
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest, nil
}

func RenderC(bundle Bundle) ([]byte, []byte, error) {
	if err := bundle.Validate(); err != nil {
		return nil, nil, err
	}
	header := []byte("#ifndef PBNS_DEPLOYMENT_TRUST_GENERATED_H\n#define PBNS_DEPLOYMENT_TRUST_GENERATED_H\n\n#include \"pbns/deployment_trust.h\"\n\nextern const pbns_deployment_trust PBNS_DEPLOYMENT_TRUST;\n\n#endif\n")
	var source strings.Builder
	source.WriteString("#include \"PbnsDeploymentTrust.h\"\n\n")
	writeArray := func(name string, value []byte) {
		fmt.Fprintf(&source, "static const uint8_t %s[%d] = {", name, len(value))
		for index, item := range value {
			if index%8 == 0 {
				source.WriteString("\n    ")
			}
			fmt.Fprintf(&source, "0x%02xU, ", item)
		}
		source.WriteString("\n};\n")
	}
	writeArray("TLS_NAME", []byte(bundle.TLSServerName))
	writeArray("TLS_SPKI", bundle.TLSSPKISHA256[:])
	roles := []struct {
		name string
		key  PublicKey
	}{{"TIME", bundle.Time}, {"CHALLENGE", bundle.Challenge}, {"RECIPIENT", bundle.Recipient}, {"RECEIPT", bundle.Receipt}}
	for _, role := range roles {
		writeArray(role.name+"_KID", role.key.KID)
		writeArray(role.name+"_X", role.key.X)
		writeArray(role.name+"_Y", role.key.Y)
	}
	source.WriteString("\nconst pbns_deployment_trust PBNS_DEPLOYMENT_TRUST = {\n")
	source.WriteString("  .tls = {.expected_server_name = {TLS_NAME, sizeof(TLS_NAME)}, .pinned_leaf_spki_sha256 = {TLS_SPKI, sizeof(TLS_SPKI)}, .handshake_timeout_ms = 15000U},\n")
	for _, role := range roles {
		fmt.Fprintf(&source, "  .%s = {.kid = {%s_KID, sizeof(%s_KID)}, .x = {%s_X, sizeof(%s_X)}, .y = {%s_Y, sizeof(%s_Y)}},\n", strings.ToLower(role.name), role.name, role.name, role.name, role.name, role.name, role.name)
	}
	source.WriteString("};\n")
	return header, []byte(source.String()), nil
}

func SortedRoles() []Role {
	roles := []Role{RoleTime, RoleChallenge, RoleRecipient, RoleReceipt}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	return roles
}

var fixtureTLSDigest = [32]byte{0xa0, 0xd2, 0x19, 0x23, 0xdd, 0xfc, 0xcb, 0xa1, 0x2d, 0x0a, 0x7b, 0xbd, 0x74, 0x08, 0x65, 0x0c, 0xb8, 0xc5, 0x4f, 0x1b, 0xe5, 0x37, 0xfe, 0x3a, 0x7e, 0x69, 0xad, 0xb1, 0x37, 0x6d, 0xa1, 0x06}
var fixtureTimeX = []byte{0x18, 0x4d, 0x92, 0x82, 0xe7, 0x2f, 0x5b, 0x3f, 0x6e, 0x0e, 0xa7, 0x3b, 0x42, 0xac, 0x55, 0xd4, 0x1f, 0x18, 0x58, 0x8a, 0xca, 0x5c, 0xc4, 0x87, 0x36, 0x58, 0x05, 0xd5, 0x78, 0x2a, 0xb3, 0xca}
var fixtureTimeY = []byte{0xee, 0x41, 0x0f, 0xd3, 0xaf, 0xa3, 0x58, 0x94, 0xf5, 0x46, 0x0d, 0x82, 0x2d, 0xaa, 0x3a, 0x3f, 0x62, 0xc6, 0x1f, 0x62, 0x0e, 0xff, 0x4f, 0x65, 0xab, 0x7d, 0x0e, 0x31, 0xb9, 0x4c, 0x78, 0x93}
