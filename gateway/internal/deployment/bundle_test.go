package deployment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func freshBundle(t *testing.T) (Bundle, map[Role]*ecdsa.PrivateKey) {
	t.Helper()
	keys := make(map[Role]*ecdsa.PrivateKey)
	roleKey := func(role Role, kid string) PublicKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[role] = key
		return PublicKey{KID: []byte(kid), X: key.X.FillBytes(make([]byte, 32)), Y: key.Y.FillBytes(make([]byte, 32))}
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Bundle{
		Domain: Domain, Version: 1, TLSServerName: "127.0.0.1", TLSPublicKeyDER: spki, TLSSPKISHA256: sha256.Sum256(spki),
		Time: roleKey(RoleTime, "time-fresh"), Challenge: roleKey(RoleChallenge, "challenge-fresh"),
		Recipient: roleKey(RoleRecipient, "recipient-fresh"), Receipt: roleKey(RoleReceipt, "receipt-fresh"),
	}, keys
}

func TestCanonicalBundleRoundTripAndDeterministicC(t *testing.T) {
	bundle, _ := freshBundle(t)
	encoded, err := Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "deployment.cbor")
	if err := os.WriteFile(path, encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	firstHeader, firstSource, err := RenderC(loaded)
	if err != nil {
		t.Fatal(err)
	}
	secondHeader, secondSource, err := RenderC(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstHeader, secondHeader) || !bytes.Equal(firstSource, secondSource) {
		t.Fatal("same canonical public bundle produced nondeterministic C")
	}
	changed := bundle
	changed.Receipt.KID = []byte("receipt-changed")
	changedHeader, changedSource, err := RenderC(changed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstHeader, changedHeader) && bytes.Equal(firstSource, changedSource) {
		t.Fatal("changed public bundle did not change generated trust pins")
	}
	if bytes.Contains(firstSource, []byte("PRIVATE KEY")) || bytes.Contains(firstSource, []byte("EC PRIVATE")) {
		t.Fatal("generated C contains private-key material")
	}
}

func TestBundleRejectsFixtureSmallScalarDuplicateAndInvalidMaterial(t *testing.T) {
	valid, _ := freshBundle(t)
	fixtureDirectory := filepath.Join("..", "..", "..", "tests", "fixtures", "keys")
	fixtureTLS, err := os.ReadFile(filepath.Join(fixtureDirectory, "tls-gateway-test-spki.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	fixtureDigest, err := ParseHexDigest(bytes.TrimSpace(fixtureTLS))
	if err != nil {
		t.Fatal(err)
	}
	fixtureCertificatePEM, err := os.ReadFile(filepath.Join(fixtureDirectory, "tls-gateway-test-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	fixtureBlock, rest := pem.Decode(fixtureCertificatePEM)
	if fixtureBlock == nil || len(rest) != 0 || fixtureBlock.Type != "CERTIFICATE" {
		t.Fatal("invalid committed TLS fixture certificate")
	}
	fixtureCertificate, err := x509.ParseCertificate(fixtureBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(fixtureCertificate.RawSubjectPublicKeyInfo) != fixtureDigest {
		t.Fatal("committed TLS fixture SPKI and digest disagree")
	}
	cases := map[string]func(*Bundle){
		"fixture TLS": func(bundle *Bundle) {
			bundle.TLSPublicKeyDER = append([]byte(nil), fixtureCertificate.RawSubjectPublicKeyInfo...)
			bundle.TLSSPKISHA256 = fixtureDigest
		},
		"committed time point": func(bundle *Bundle) {
			bundle.Time.X = append([]byte(nil), fixtureTimeX...)
			bundle.Time.Y = append([]byte(nil), fixtureTimeY...)
		},
		"duplicate roles": func(bundle *Bundle) { bundle.Receipt = bundle.Challenge; bundle.Receipt.KID = []byte("other-kid") },
		"TLS equality": func(bundle *Bundle) {
			parsed, parseErr := x509.ParsePKIXPublicKey(bundle.TLSPublicKeyDER)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			public := parsed.(*ecdsa.PublicKey)
			bundle.Recipient.X = public.X.FillBytes(make([]byte, 32))
			bundle.Recipient.Y = public.Y.FillBytes(make([]byte, 32))
		},
		"zero coordinate": func(bundle *Bundle) { bundle.Time.X = make([]byte, 32); bundle.Time.Y = make([]byte, 32) },
		"duplicate kid":   func(bundle *Bundle) { bundle.Receipt.KID = append([]byte(nil), bundle.Challenge.KID...) },
	}
	for scalar := int64(1); scalar <= 3; scalar++ {
		value := scalar
		cases[fmt.Sprintf("small scalar %d", value)] = func(bundle *Bundle) {
			pointX, pointY := elliptic.P256().ScalarBaseMult(big.NewInt(value).Bytes())
			bundle.Challenge.X = pointX.FillBytes(make([]byte, 32))
			bundle.Challenge.Y = pointY.FillBytes(make([]byte, 32))
		}
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := valid.Clone()
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("unsafe bundle accepted")
			}
		})
	}
}

func TestSecureLoaderRequiresPrivateImmediateAuthorityButAllowsSharedAncestor(t *testing.T) {
	sharedAncestor := t.TempDir()
	if err := os.Chmod(sharedAncestor, 0o1777); err != nil {
		t.Fatal(err)
	}
	privateDirectory := filepath.Join(sharedAncestor, "runtime")
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(privateDirectory, "key.pem")
	if err := os.WriteFile(privatePath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if encoded, err := readSecureRegular(privatePath, 0o600, 64); err != nil || string(encoded) != "private" {
		t.Fatalf("private nested path under shared ancestor rejected: %q, %v", encoded, err)
	}

	unsafeDirectory := filepath.Join(sharedAncestor, "unsafe")
	if err := os.Mkdir(unsafeDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	unsafePath := filepath.Join(unsafeDirectory, "key.pem")
	if err := os.WriteFile(unsafePath, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureRegular(unsafePath, 0o600, 64); err == nil {
		t.Fatal("non-private immediate authority directory accepted")
	}

	symlinkDirectory := filepath.Join(sharedAncestor, "runtime-link")
	if err := os.Symlink(privateDirectory, symlinkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecureRegular(filepath.Join(symlinkDirectory, "key.pem"), 0o600, 64); err == nil {
		t.Fatal("symlink immediate authority directory accepted")
	}
}

func TestLoadMatchedReturnsExactSecurelyLoadedObjects(t *testing.T) {
	bundle, privateKeys := freshBundle(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tlsKey, certPath, keyPath := makeTLSCertificate(t, directory, bundle.TLSServerName)
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle.TLSPublicKeyDER = spki
	bundle.TLSSPKISHA256 = sha256.Sum256(spki)
	bundlePath := filepath.Join(directory, "deployment.cbor")
	encoded, err := Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	counterparts := Counterparts{TLSCertFile: certPath, TLSKeyFile: keyPath, PrivateKeyFiles: make(map[Role]string), KIDs: make(map[Role]string)}
	for role, key := range privateKeys {
		path := filepath.Join(directory, string(role)+".pem")
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		counterparts.PrivateKeyFiles[role] = path
		counterparts.KIDs[role] = string(bundle.roleKeys()[role].KID)
	}
	objects, err := LoadMatched(bundlePath, counterparts)
	if err != nil {
		t.Fatal(err)
	}
	if objects.TLSCertificate == nil || len(objects.TLSCertificate.Certificate) != 1 || objects.PrivateKeys[RoleChallenge] != privateKeys[RoleChallenge] && !objects.PrivateKeys[RoleChallenge].Equal(privateKeys[RoleChallenge]) {
		t.Fatal("loaded deployment objects do not match exact configured objects")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, _ := x509.MarshalECPrivateKey(other)
	challengePath := counterparts.PrivateKeyFiles[RoleChallenge]
	if err := os.Remove(challengePath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(challengePath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: otherDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if !objects.PrivateKeys[RoleChallenge].Equal(privateKeys[RoleChallenge]) {
		t.Fatal("loaded deployment key changed after pathname replacement")
	}

	for name, mutate := range map[string]func(string) error{
		"symlink": func(path string) error {
			return os.Symlink(bundlePath, path)
		},
		"unsafe mode": func(path string) error {
			if err := os.WriteFile(path, encoded, 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0o644)
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, "bad-"+name)
			if err := mutate(path); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadMatched(path, counterparts); err == nil {
				t.Fatal("unsafe deployment bundle accepted")
			}
		})
	}
}

func TestMatchDeploymentRequiresTLSAndEveryPrivateCounterpart(t *testing.T) {
	bundle, privateKeys := freshBundle(t)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tlsKey, certPath, keyPath := makeTLSCertificate(t, directory, bundle.TLSServerName)
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle.TLSPublicKeyDER = spki
	bundle.TLSSPKISHA256 = sha256.Sum256(spki)
	privatePaths := make(map[Role]string)
	for role, key := range privateKeys {
		path := filepath.Join(directory, string(role)+".pem")
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		privatePaths[role] = path
	}
	configuration := Counterparts{TLSCertFile: certPath, TLSKeyFile: keyPath, PrivateKeyFiles: privatePaths, KIDs: map[Role]string{
		RoleTime: string(bundle.Time.KID), RoleChallenge: string(bundle.Challenge.KID), RoleRecipient: string(bundle.Recipient.KID), RoleReceipt: string(bundle.Receipt.KID),
	}}
	if err := bundle.Match(configuration); err != nil {
		t.Fatal(err)
	}
	for _, role := range []Role{RoleTime, RoleChallenge, RoleRecipient, RoleReceipt} {
		changed := configuration.Clone()
		delete(changed.PrivateKeyFiles, role)
		if err := bundle.Match(changed); err == nil {
			t.Fatalf("missing %s counterpart accepted", role)
		}
		changed = configuration.Clone()
		changed.KIDs[role] += "-wrong"
		if err := bundle.Match(changed); err == nil {
			t.Fatalf("wrong %s KID accepted", role)
		}
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := filepath.Join(directory, "wrong.pem")
	der, _ := x509.MarshalECPrivateKey(other)
	if err := os.WriteFile(wrongPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := configuration.Clone()
	changed.PrivateKeyFiles[RoleReceipt] = wrongPath
	if err := bundle.Match(changed); err == nil {
		t.Fatal("wrong private counterpart accepted")
	}
}

func testCertificateTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PBNS deployment"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
}

func makeTLSCertificate(t *testing.T, directory, serverName string) (*ecdsa.PrivateKey, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := testCertificateTemplate()
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(directory, "tls-cert.pem")
	keyPath := filepath.Join(directory, "tls-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return key, certPath, keyPath
}
