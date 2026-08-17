package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"

	"pbns.local/gateway/internal/model"
)

var ErrEKPublic = errors.New("invalid EK public key")

func VerifyEKCertificateChain(
	ekPublicDER []byte,
	chainDER [][]byte,
	roots *x509.CertPool,
	now time.Time,
) (model.Assurance, [32]byte, error) {
	ekPublic, err := parseEKPublic(ekPublicDER)
	if err != nil {
		return "", [32]byte{}, ErrEKPublic
	}
	if len(chainDER) == 0 || len(chainDER) > maximumCertCount || roots == nil || now.IsZero() {
		return model.AssuranceTPMUnverified, [32]byte{}, nil
	}
	certificates := make([]*x509.Certificate, 0, len(chainDER))
	for _, encoded := range chainDER {
		if len(encoded) == 0 || len(encoded) > maximumPublicSize {
			return model.AssuranceTPMUnverified, [32]byte{}, nil
		}
		certificate, parseErr := x509.ParseCertificate(encoded)
		if parseErr != nil {
			return model.AssuranceTPMUnverified, [32]byte{}, nil
		}
		certificates = append(certificates, certificate)
	}
	leaf := certificates[0]
	if !publicKeysEqual(leaf.PublicKey, ekPublic) {
		return model.AssuranceTPMUnverified, [32]byte{}, nil
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: now.UTC(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return model.AssuranceTPMUnverified, [32]byte{}, nil
	}
	return model.AssuranceTPMVerified, chainDigest(chainDER), nil
}

func parseEKPublic(encoded []byte) (any, error) {
	public, err := x509.ParsePKIXPublicKey(encoded)
	if err == nil && validEKPublic(public) {
		return public, nil
	}
	tpmPublic, err := decodeTPMPublic(encoded)
	if err != nil || !validEKTPMPublic(tpmPublic) {
		return nil, ErrEKPublic
	}
	public, err = tpmPublic.Key()
	if err != nil || !validEKPublic(public) {
		return nil, ErrEKPublic
	}
	return public, nil
}

func validEKTPMPublic(public tpm2.Public) bool {
	const required = tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
		tpm2.FlagNoDA | tpm2.FlagRestricted | tpm2.FlagDecrypt
	parameters := public.ECCParameters
	return public.Type == tpm2.AlgECC && public.NameAlg == tpm2.AlgSHA256 &&
		public.Attributes == required && len(public.AuthPolicy) == 0 &&
		parameters != nil && parameters.CurveID == tpm2.CurveNISTP256 &&
		parameters.Sign == nil && parameters.KDF == nil &&
		parameters.Symmetric != nil && parameters.Symmetric.Alg == tpm2.AlgAES &&
		parameters.Symmetric.KeyBits == 128 && parameters.Symmetric.Mode == tpm2.AlgCFB
}

func validEKPublic(public any) bool {
	key, ok := public.(*ecdsa.PublicKey)
	return ok && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil &&
		key.Curve.IsOnCurve(key.X, key.Y)
}

func publicKeysEqual(left, right any) bool {
	leftKey, leftOK := left.(*ecdsa.PublicKey)
	rightKey, rightOK := right.(*ecdsa.PublicKey)
	return leftOK && rightOK && leftKey.Equal(rightKey)
}

func chainDigest(chain [][]byte) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("PBNS-EK-CHAIN-v1"))
	var length [4]byte
	for _, certificate := range chain {
		binary.BigEndian.PutUint32(length[:], uint32(len(certificate)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write(certificate)
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	clear(length[:])
	return digest
}
