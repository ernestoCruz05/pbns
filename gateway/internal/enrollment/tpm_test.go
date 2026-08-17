package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
)

func testTPMPublic(t *testing.T, endorsement bool) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parameters := &tpm2.ECCParams{
		CurveID: tpm2.CurveNISTP256,
		Point: tpm2.ECPoint{
			XRaw: key.X.FillBytes(make([]byte, 32)),
			YRaw: key.Y.FillBytes(make([]byte, 32)),
		},
	}
	attributes := tpm2.FlagSignerDefault
	if endorsement {
		attributes = tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth | tpm2.FlagNoDA |
			tpm2.FlagRestricted | tpm2.FlagDecrypt
		parameters.Symmetric = &tpm2.SymScheme{
			Alg: tpm2.AlgAES, KeyBits: 128, Mode: tpm2.AlgCFB,
		}
	} else {
		parameters.Sign = &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256}
	}
	encoded, err := (tpm2.Public{
		Type: tpm2.AlgECC, NameAlg: tpm2.AlgSHA256,
		Attributes: attributes, ECCParameters: parameters,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded, key
}

func TestDecodeTPMPublicCanonicalizesBareAndTPM2BForms(t *testing.T) {
	bare, _ := testTPMPublic(t, false)
	lengthPrefixed := make([]byte, len(bare)+2)
	binary.BigEndian.PutUint16(lengthPrefixed, uint16(len(bare)))
	copy(lengthPrefixed[2:], bare)
	for _, encoded := range [][]byte{bare, lengthPrefixed} {
		public, err := decodeTPMPublic(encoded)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := public.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(canonical, bare) {
			t.Fatal("TPM public area did not canonicalize to bare TPMT_PUBLIC")
		}
	}
}

func TestGoAttestationActivationUsesExactAKNameWithoutCreationAttestation(t *testing.T) {
	ekPublic, _ := testTPMPublic(t, true)
	akPublic, _ := testTPMPublic(t, false)
	decoded, err := tpm2.DecodePublic(akPublic)
	if err != nil {
		t.Fatal(err)
	}
	name, err := decoded.Name()
	if err != nil {
		t.Fatal(err)
	}
	if name.Digest == nil {
		t.Fatal("AK name has no digest")
	}
	encodedName, err := name.Digest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(encodedName) != 34 {
		t.Fatalf("bare AK name length got %d, want 34", len(encodedName))
	}
	verifier, err := NewGoAttestationVerifier(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := verifier.Generate(activationRequest{
		EKPublic: ekPublic, AKPublic: akPublic, AKName: encodedName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Secret == ([32]byte{}) || len(challenge.CredentialBlob) == 0 ||
		len(challenge.EncryptedSecret) == 0 {
		t.Fatal("activation challenge is incomplete")
	}
	lengthPrefixedName, err := name.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Generate(activationRequest{
		EKPublic: ekPublic, AKPublic: akPublic, AKName: lengthPrefixedName,
	}); err == nil {
		t.Fatal("length-prefixed TPM2B_NAME accepted instead of its exact buffer")
	}

	invalid, err := tpm2.DecodePublic(akPublic)
	if err != nil {
		t.Fatal(err)
	}
	invalid.Attributes &^= tpm2.FlagRestricted
	invalidPublic, err := invalid.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Generate(activationRequest{
		EKPublic: ekPublic, AKPublic: invalidPublic, AKName: encodedName,
	}); err == nil {
		t.Fatal("unrestricted AK accepted")
	}
}
