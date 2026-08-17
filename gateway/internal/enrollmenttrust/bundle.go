// Package enrollmenttrust binds the canonical enrollment public bundle to the
// exact private gateway counterparts loaded before persistent state is opened.
package enrollmenttrust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fxamacker/cbor/v2"

	"pbns.local/gateway/internal/deployment"
)

const Domain = "PBNS-ENROLLMENT-TRUST-v1"

var ErrInvalid = errors.New("invalid PBNS enrollment trust bundle")

type Bundle struct {
	Domain    string               `cbor:"1,keyasint"`
	Version   uint64               `cbor:"2,keyasint"`
	Recipient deployment.PublicKey `cbor:"3,keyasint"`
	Signer    deployment.PublicKey `cbor:"4,keyasint"`
}

type Counterparts struct {
	RecipientKeyFile string
	RecipientKID     string
	SignerKeyFile    string
	SignerKID        string
}

type Objects struct {
	Bundle    Bundle
	Recipient *ecdsa.PrivateKey
	Signer    *ecdsa.PrivateKey
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
		TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxArrayElements: 16,
		MaxMapPairs: 16, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func clonePublic(key deployment.PublicKey) deployment.PublicKey {
	return deployment.PublicKey{
		KID: append([]byte(nil), key.KID...),
		X:   append([]byte(nil), key.X...),
		Y:   append([]byte(nil), key.Y...),
	}
}

func (bundle Bundle) clone() Bundle {
	return Bundle{Domain: bundle.Domain, Version: bundle.Version,
		Recipient: clonePublic(bundle.Recipient), Signer: clonePublic(bundle.Signer)}
}

func Marshal(bundle Bundle) ([]byte, error) {
	if bundle.validate() != nil {
		return nil, ErrInvalid
	}
	return canonicalMode.Marshal(bundle)
}

func parse(encoded []byte) (Bundle, error) {
	var bundle Bundle
	if len(encoded) == 0 || strictMode.Unmarshal(encoded, &bundle) != nil || bundle.validate() != nil {
		return Bundle{}, ErrInvalid
	}
	canonical, err := canonicalMode.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Bundle{}, ErrInvalid
	}
	return bundle.clone(), nil
}

func Load(path string) (Bundle, error) {
	encoded, err := readSecureRegular(path, 0o444, 64*1024)
	if err != nil {
		return Bundle{}, err
	}
	return parse(encoded)
}

func LoadMatched(path string, counterparts Counterparts) (*Objects, error) {
	if counterparts.RecipientKeyFile == "" || counterparts.SignerKeyFile == "" ||
		counterparts.RecipientKeyFile == counterparts.SignerKeyFile {
		return nil, ErrInvalid
	}
	bundle, err := Load(path)
	if err != nil {
		return nil, err
	}
	if counterparts.RecipientKID != string(bundle.Recipient.KID) ||
		counterparts.SignerKID != string(bundle.Signer.KID) {
		return nil, ErrInvalid
	}
	recipient, err := loadPrivate(counterparts.RecipientKeyFile)
	if err != nil {
		return nil, err
	}
	signer, err := loadPrivate(counterparts.SignerKeyFile)
	if err != nil {
		return nil, err
	}
	recipientPublic, _ := publicFrom(bundle.Recipient)
	signerPublic, _ := publicFrom(bundle.Signer)
	if !recipient.PublicKey.Equal(recipientPublic) || !signer.PublicKey.Equal(signerPublic) ||
		recipient.PublicKey.Equal(&signer.PublicKey) {
		return nil, ErrInvalid
	}
	return &Objects{Bundle: bundle.clone(), Recipient: recipient, Signer: signer}, nil
}

func publicFrom(key deployment.PublicKey) (*ecdsa.PublicKey, error) {
	if len(key.KID) == 0 || len(key.KID) > 64 || len(key.X) != 32 || len(key.Y) != 32 {
		return nil, ErrInvalid
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(key.X), Y: new(big.Int).SetBytes(key.Y)}
	if public.X.Sign() == 0 || public.Y.Sign() == 0 || !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, ErrInvalid
	}
	return public, nil
}

func (bundle Bundle) validate() error {
	if bundle.Domain != Domain || bundle.Version != 1 {
		return ErrInvalid
	}
	recipient, err := publicFrom(bundle.Recipient)
	if err != nil || rejectedPublic(recipient) {
		return ErrInvalid
	}
	signer, err := publicFrom(bundle.Signer)
	if err != nil || rejectedPublic(signer) || recipient.Equal(signer) ||
		bytes.Equal(bundle.Recipient.KID, bundle.Signer.KID) {
		return ErrInvalid
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
	for _, point := range fixturePoints {
		if public.X.Cmp(new(big.Int).SetBytes(point[0])) == 0 &&
			public.Y.Cmp(new(big.Int).SetBytes(point[1])) == 0 {
			return true
		}
	}
	return false
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
	if path == "" || maximum <= 0 || !secureParent(path) {
		return nil, ErrInvalid
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, ErrInvalid
	}
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Uid != uint32(os.Geteuid()) || os.FileMode(before.Mode&0o777) != mode ||
		before.Size <= 0 || before.Size > maximum {
		_ = file.Close()
		return nil, ErrInvalid
	}
	encoded := make([]byte, int(before.Size))
	_, readErr := io.ReadFull(file, encoded)
	var extra [1]byte
	extraCount, extraErr := file.Read(extra[:])
	var after syscall.Stat_t
	statErr := syscall.Fstat(fd, &after)
	closeErr := file.Close()
	if readErr != nil || extraCount != 0 || (extraErr != nil && !errors.Is(extraErr, io.EOF)) ||
		statErr != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode ||
		before.Uid != after.Uid || before.Gid != after.Gid || before.Nlink != after.Nlink ||
		before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || closeErr != nil {
		clear(encoded)
		return nil, ErrInvalid
	}
	return encoded, nil
}

func loadPrivate(path string) (*ecdsa.PrivateKey, error) {
	encoded, err := readSecureRegular(path, 0o600, 16*1024)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "EC PRIVATE KEY" {
		return nil, ErrInvalid
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil || key.Curve != elliptic.P256() || key.D.Sign() <= 0 ||
		!key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrInvalid
	}
	return key, nil
}

func RenderC(bundle Bundle) ([]byte, []byte, error) {
	if bundle.validate() != nil {
		return nil, nil, ErrInvalid
	}
	header := []byte("#ifndef PBNS_ENROLLMENT_TRUST_GENERATED_H\n#define PBNS_ENROLLMENT_TRUST_GENERATED_H\n\n#include \"pbns/enrollment_trust.h\"\n\nextern const pbns_enrollment_trust PBNS_ENROLLMENT_TRUST;\n\n#endif\n")
	var source strings.Builder
	source.WriteString("#include \"PbnsEnrollmentTrust.h\"\n\n")
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
	roles := []struct {
		name string
		key  deployment.PublicKey
	}{{"RECIPIENT", bundle.Recipient}, {"SIGNER", bundle.Signer}}
	for _, role := range roles {
		writeArray(role.name+"_KID", role.key.KID)
		writeArray(role.name+"_X", role.key.X)
		writeArray(role.name+"_Y", role.key.Y)
	}
	source.WriteString("\nconst pbns_enrollment_trust PBNS_ENROLLMENT_TRUST = {\n")
	for _, role := range roles {
		fmt.Fprintf(&source, "  .%s = {.kid = {%s_KID, sizeof(%s_KID)}, .x = {%s_X, sizeof(%s_X)}, .y = {%s_Y, sizeof(%s_Y)}},\n", strings.ToLower(role.name), role.name, role.name, role.name, role.name, role.name, role.name)
	}
	source.WriteString("};\n")
	return header, []byte(source.String()), nil
}

var fixturePoints = [][2][]byte{
	{
		{0xdf, 0xc9, 0x5a, 0x69, 0x0e, 0xa5, 0xcc, 0xb7, 0x37, 0x48, 0x3b, 0xf2, 0xb3, 0x52, 0x5d, 0xe8, 0x35, 0xaa, 0x3e, 0xe3, 0x79, 0x48, 0x98, 0x79, 0x57, 0x4f, 0xde, 0xec, 0x10, 0x1e, 0xe6, 0x77},
		{0xcd, 0xef, 0x0b, 0x1b, 0x3c, 0x19, 0x31, 0x09, 0x7e, 0x94, 0xc3, 0xb7, 0x2c, 0x38, 0xf6, 0xfa, 0xcf, 0x50, 0xe8, 0x23, 0xcf, 0x36, 0x57, 0x49, 0x7e, 0x97, 0xb5, 0x4a, 0x82, 0x6a, 0x79, 0x79},
	},
	{
		{0xe4, 0x4d, 0x0e, 0x03, 0xa3, 0x12, 0xfc, 0xce, 0x22, 0x92, 0xbb, 0xfc, 0x15, 0xe3, 0x66, 0x9a, 0xf8, 0x1d, 0x5e, 0x7f, 0x5e, 0x83, 0xc5, 0x79, 0xff, 0xff, 0x3d, 0x33, 0xd3, 0x04, 0xd4, 0x30},
		{0xce, 0x5c, 0xf8, 0x77, 0x5c, 0x03, 0x73, 0xf7, 0x02, 0x20, 0xd0, 0x97, 0x96, 0x6a, 0x66, 0x6a, 0x10, 0x50, 0x0c, 0x58, 0xa3, 0xd6, 0x70, 0x51, 0x75, 0x67, 0x54, 0xd0, 0x50, 0xd9, 0x3f, 0x09},
	},
}
