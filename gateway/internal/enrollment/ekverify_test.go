package enrollment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"pbns.local/gateway/internal/model"
)

func makeEKChain(t *testing.T) ([]byte, [][]byte, *x509.CertPool) {
	t.Helper()
	now := time.Unix(1_900_000_000, 0).UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PBNS test EK root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "PBNS test EK"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &ekKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ekPublic, err := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return ekPublic, [][]byte{leafDER, rootDER}, roots
}

func TestVerifyEKCertificateChainClassifiesVerifiedAndUnverified(t *testing.T) {
	ekPublic, chain, roots := makeEKChain(t)
	assurance, digest, err := VerifyEKCertificateChain(
		ekPublic, chain, roots, time.Unix(1_900_000_000, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if assurance != model.AssuranceTPMVerified || digest == ([32]byte{}) {
		t.Fatalf("verified chain got assurance=%q digest=%x", assurance, digest)
	}
	assurance, digest, err = VerifyEKCertificateChain(
		ekPublic, nil, roots, time.Unix(1_900_000_000, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if assurance != model.AssuranceTPMUnverified || digest != ([32]byte{}) {
		t.Fatalf("missing chain got assurance=%q digest=%x", assurance, digest)
	}
}

func TestVerifyEKCertificateChainNeverUpgradesWrongOrMalformedChain(t *testing.T) {
	ekPublic, chain, roots := makeEKChain(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		public []byte
		chain  [][]byte
		roots  *x509.CertPool
	}{
		{name: "wrong-public", public: otherPublic, chain: chain, roots: roots},
		{name: "malformed-chain", public: ekPublic, chain: [][]byte{{1, 2, 3}}, roots: roots},
		{name: "missing-roots", public: ekPublic, chain: chain, roots: nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			assurance, digest, err := VerifyEKCertificateChain(
				test.public, test.chain, test.roots, time.Unix(1_900_000_000, 0).UTC(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if assurance != model.AssuranceTPMUnverified || digest != ([32]byte{}) {
				t.Fatalf("got assurance=%q digest=%x", assurance, digest)
			}
		})
	}
	if _, _, err := VerifyEKCertificateChain(
		[]byte{1, 2, 3}, chain, roots, time.Unix(1_900_000_000, 0).UTC(),
	); err == nil {
		t.Fatal("malformed EK public accepted")
	}
}
