package enrollmenttrust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"pbns.local/gateway/internal/deployment"
)

func freshKey(t *testing.T, kid string) (*ecdsa.PrivateKey, deployment.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, deployment.PublicKey{
		KID: []byte(kid),
		X:   key.X.FillBytes(make([]byte, 32)),
		Y:   key.Y.FillBytes(make([]byte, 32)),
	}
}

func writePrivate(t *testing.T, path string, key *ecdsa.PrivateKey) {
	t.Helper()
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func freshTrustFixture(t *testing.T) (string, Counterparts, Bundle) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	recipient, recipientPublic := freshKey(t, "fresh-enrollment-recipient")
	signer, signerPublic := freshKey(t, "fresh-enrollment-signer")
	bundle := Bundle{Domain: Domain, Version: 1, Recipient: recipientPublic, Signer: signerPublic}
	encoded, err := Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "enrollment.cbor")
	if err := os.WriteFile(bundlePath, encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	recipientPath := filepath.Join(directory, "recipient-key.pem")
	signerPath := filepath.Join(directory, "signer-key.pem")
	writePrivate(t, recipientPath, recipient)
	writePrivate(t, signerPath, signer)
	return bundlePath, Counterparts{
		RecipientKeyFile: recipientPath,
		RecipientKID:     string(recipientPublic.KID),
		SignerKeyFile:    signerPath,
		SignerKID:        string(signerPublic.KID),
	}, bundle
}

func TestLoadMatchedBindsExactDistinctPrivateCounterparts(t *testing.T) {
	bundlePath, counterparts, bundle := freshTrustFixture(t)
	objects, err := LoadMatched(bundlePath, counterparts)
	if err != nil {
		t.Fatal(err)
	}
	if objects.Recipient == nil || objects.Signer == nil ||
		objects.Recipient.PublicKey.Equal(&objects.Signer.PublicKey) {
		t.Fatal("loaded enrollment roles are missing or reused")
	}
	if string(objects.Bundle.Recipient.KID) != string(bundle.Recipient.KID) ||
		string(objects.Bundle.Signer.KID) != string(bundle.Signer.KID) {
		t.Fatal("loaded enrollment KIDs changed")
	}

	wrong, _ := freshKey(t, "unused")
	writePrivate(t, counterparts.SignerKeyFile, wrong)
	if objects.Signer.PublicKey.Equal(&wrong.PublicKey) {
		t.Fatal("loaded signer changed after configured pathname replacement")
	}
	if _, err := LoadMatched(bundlePath, counterparts); err == nil {
		t.Fatal("mismatched signer private counterpart accepted")
	}
	writePrivate(t, counterparts.SignerKeyFile, objects.Signer)
	counterparts.SignerKID += "-wrong"
	if _, err := LoadMatched(bundlePath, counterparts); err == nil {
		t.Fatal("mismatched signer KID accepted")
	}
}

func TestBundleRejectsRoleReuseAndCommittedEnrollmentFixturePoints(t *testing.T) {
	_, _, valid := freshTrustFixture(t)
	fixtureRecipient := deployment.PublicKey{
		KID: []byte("new-kid"),
		X:   []byte{0xdf, 0xc9, 0x5a, 0x69, 0x0e, 0xa5, 0xcc, 0xb7, 0x37, 0x48, 0x3b, 0xf2, 0xb3, 0x52, 0x5d, 0xe8, 0x35, 0xaa, 0x3e, 0xe3, 0x79, 0x48, 0x98, 0x79, 0x57, 0x4f, 0xde, 0xec, 0x10, 0x1e, 0xe6, 0x77},
		Y:   []byte{0xcd, 0xef, 0x0b, 0x1b, 0x3c, 0x19, 0x31, 0x09, 0x7e, 0x94, 0xc3, 0xb7, 0x2c, 0x38, 0xf6, 0xfa, 0xcf, 0x50, 0xe8, 0x23, 0xcf, 0x36, 0x57, 0x49, 0x7e, 0x97, 0xb5, 0x4a, 0x82, 0x6a, 0x79, 0x79},
	}
	fixtureSigner := deployment.PublicKey{
		KID: []byte("new-kid"),
		X:   []byte{0xe4, 0x4d, 0x0e, 0x03, 0xa3, 0x12, 0xfc, 0xce, 0x22, 0x92, 0xbb, 0xfc, 0x15, 0xe3, 0x66, 0x9a, 0xf8, 0x1d, 0x5e, 0x7f, 0x5e, 0x83, 0xc5, 0x79, 0xff, 0xff, 0x3d, 0x33, 0xd3, 0x04, 0xd4, 0x30},
		Y:   []byte{0xce, 0x5c, 0xf8, 0x77, 0x5c, 0x03, 0x73, 0xf7, 0x02, 0x20, 0xd0, 0x97, 0x96, 0x6a, 0x66, 0x6a, 0x10, 0x50, 0x0c, 0x58, 0xa3, 0xd6, 0x70, 0x51, 0x75, 0x67, 0x54, 0xd0, 0x50, 0xd9, 0x3f, 0x09},
	}
	cases := map[string]Bundle{
		"same public key": func() Bundle {
			candidate := valid
			candidate.Signer = candidate.Recipient
			candidate.Signer.KID = []byte("other-kid")
			return candidate
		}(),
		"same kid": func() Bundle {
			candidate := valid
			candidate.Signer.KID = append([]byte(nil), candidate.Recipient.KID...)
			return candidate
		}(),
		"fixture recipient": func() Bundle {
			candidate := valid
			candidate.Recipient = fixtureRecipient
			return candidate
		}(),
		"fixture signer": func() Bundle {
			candidate := valid
			candidate.Signer = fixtureSigner
			return candidate
		}(),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Marshal(candidate); err == nil {
				t.Fatal("unsafe enrollment trust accepted")
			}
		})
	}
}

func TestCanonicalRoundTripAndPublicCContainNoPrivateMaterial(t *testing.T) {
	bundlePath, _, bundle := freshTrustFixture(t)
	loaded, err := Load(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded.Recipient.X, bundle.Recipient.X) || !bytes.Equal(loaded.Signer.Y, bundle.Signer.Y) {
		t.Fatal("canonical enrollment bundle changed public coordinates")
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
		t.Fatal("same enrollment bundle rendered nondeterministically")
	}
	for _, forbidden := range [][]byte{[]byte("PRIVATE KEY"), []byte("BEGIN EC")} {
		if bytes.Contains(firstSource, forbidden) {
			t.Fatalf("generated enrollment C contains forbidden material %q", forbidden)
		}
	}
}
