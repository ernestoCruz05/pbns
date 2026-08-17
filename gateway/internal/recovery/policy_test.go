package recovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func policyTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPolicyInitializationBindsUnwrittenStateAndExactWrite(t *testing.T) {
	key := policyTestKey(t)
	encoded, err := CreateInitializationAuthorization(key, RecoveryNVIndex, 4)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := VerifyInitializationAuthorization(
		encoded, &key.PublicKey, RecoveryNVIndex, false)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Domain != initializationPolicyDomain ||
		authorization.Kind != PolicyKindInitialize || authorization.TargetVersion != 4 ||
		authorization.Offset != 0 || len(authorization.NVPublic) == 0 {
		t.Fatalf("wrong initialization authorization: %#v", authorization)
	}
	if _, err := VerifyInitializationAuthorization(
		encoded, &key.PublicKey, RecoveryNVIndex, true); !errors.Is(err, ErrPolicyVersion) {
		t.Fatalf("initialization replay: %v", err)
	}
	if _, err := VerifyVersionAuthorization(
		encoded, &key.PublicKey, RecoveryNVIndex, 3); err == nil {
		t.Fatal("initialization object accepted as update")
	}

	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := (tpm2.PolicyNVWritten{WrittenSet: false}).Update(calculator); err != nil {
		t.Fatal(err)
	}
	if err := (tpm2.PolicyCPHash{
		CPHashA: tpm2.TPM2BDigest{Buffer: authorization.CPHash},
	}).Update(calculator); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authorization.ApprovedPolicy, calculator.Hash().Digest) {
		t.Fatalf("initialization policy %x, expected %x",
			authorization.ApprovedPolicy, calculator.Hash().Digest)
	}
}

func TestPolicyNVNameTracksTPMWrittenState(t *testing.T) {
	key := policyTestKey(t)
	initializeEncoded, err := CreateInitializationAuthorization(
		key, RecoveryNVIndex, 4)
	if err != nil {
		t.Fatal(err)
	}
	updateEncoded, err := CreateVersionAuthorization(key, RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	initialize, err := VerifyInitializationAuthorization(
		initializeEncoded, &key.PublicKey, RecoveryNVIndex, false)
	if err != nil {
		t.Fatal(err)
	}
	update, err := VerifyVersionAuthorization(
		updateEncoded, &key.PublicKey, RecoveryNVIndex, 4)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(initialize.NVName, update.NVName) {
		t.Fatal("initialization and update incorrectly reuse one NV Name")
	}
	initializePublic, err := tpm2.Unmarshal[tpm2.TPM2BNVPublic](initialize.NVPublic)
	if err != nil {
		t.Fatal(err)
	}
	updatePublic, err := tpm2.Unmarshal[tpm2.TPM2BNVPublic](update.NVPublic)
	if err != nil {
		t.Fatal(err)
	}
	initializeContents, err := initializePublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	updateContents, err := updatePublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	if initializeContents.Attributes.Written || !updateContents.Attributes.Written {
		t.Fatal("TPMA_NV_WRITTEN state is not reflected in authorization public areas")
	}
}

func TestPolicyAuthorizationBindsNVComparisonAndExactWrite(t *testing.T) {
	key := policyTestKey(t)
	encoded, err := CreateVersionAuthorization(key, RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := VerifyVersionAuthorization(encoded, &key.PublicKey, RecoveryNVIndex, 4)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.TargetVersion != 5 || authorization.Offset != 0 ||
		authorization.Operation != uint16(tpm2.TPMEOUnsignedLT) {
		t.Fatalf("wrong comparison: %#v", authorization)
	}
	expectedOperand := make([]byte, 8)
	binary.BigEndian.PutUint64(expectedOperand, 5)
	if !bytes.Equal(authorization.Operand, expectedOperand) {
		t.Fatalf("operand %x", authorization.Operand)
	}
	if authorization.Domain != updatePolicyDomain || authorization.Kind != PolicyKindUpdate ||
		len(authorization.NVPublic) == 0 || len(authorization.NVName) != 34 ||
		len(authorization.PolicyKeyName) != 34 ||
		len(authorization.CPHash) != 32 || len(authorization.ApprovedPolicy) != 32 ||
		len(authorization.FinalPolicy) != 32 || len(authorization.Signature) == 0 ||
		len(authorization.PolicyKeyPublic) == 0 {
		t.Fatalf("incomplete authorization: %#v", authorization)
	}

	policyKeyPublic, err := policyTPMPublic(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyName, err := tpm2.ObjectName(&policyKeyPublic)
	if err != nil {
		t.Fatal(err)
	}
	finalCalculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := (tpm2.PolicyAuthorize{
		KeySign: *keyName, PolicyRef: tpm2.TPM2BDigest{Buffer: []byte(RecoveryPolicyRef)},
	}).Update(finalCalculator); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authorization.FinalPolicy, finalCalculator.Hash().Digest) {
		t.Fatalf("final policy %x, expected %x", authorization.FinalPolicy, finalCalculator.Hash().Digest)
	}
}

func TestPolicyAuthorizationRejectsDowngradeReplayAndSubstitution(t *testing.T) {
	key := policyTestKey(t)
	encoded, err := CreateVersionAuthorization(key, RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []uint64{5, 6} {
		if _, err := VerifyVersionAuthorization(encoded, &key.PublicKey, RecoveryNVIndex, current); !errors.Is(err, ErrPolicyVersion) {
			t.Fatalf("current %d: %v", current, err)
		}
	}
	if _, err := CreateVersionAuthorization(key, RecoveryNVIndex, 0); !errors.Is(err, ErrPolicyVersion) {
		t.Fatalf("zero target: %v", err)
	}

	var base VersionAuthorization
	if err := decodeMode.Unmarshal(encoded, &base); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*VersionAuthorization)
	}{
		{"domain", func(value *VersionAuthorization) { value.Domain = initializationPolicyDomain }},
		{"kind", func(value *VersionAuthorization) { value.Kind = PolicyKindInitialize }},
		{"index", func(value *VersionAuthorization) { value.NVIndex++ }},
		{"nvPublic", func(value *VersionAuthorization) { value.NVPublic[2] ^= 1 }},
		{"name", func(value *VersionAuthorization) { value.NVName[2] ^= 1 }},
		{"target", func(value *VersionAuthorization) { value.TargetVersion++ }},
		{"operand", func(value *VersionAuthorization) { value.Operand[7] ^= 1 }},
		{"offset", func(value *VersionAuthorization) { value.Offset = 1 }},
		{"operation", func(value *VersionAuthorization) { value.Operation++ }},
		{"cpHash", func(value *VersionAuthorization) { value.CPHash[0] ^= 1 }},
		{"approved", func(value *VersionAuthorization) { value.ApprovedPolicy[0] ^= 1 }},
		{"policyRef", func(value *VersionAuthorization) { value.PolicyRef[0] ^= 1 }},
		{"keyPublic", func(value *VersionAuthorization) { value.PolicyKeyPublic = append(value.PolicyKeyPublic, 0) }},
		{"keyName", func(value *VersionAuthorization) { value.PolicyKeyName[2] ^= 1 }},
		{"signature", func(value *VersionAuthorization) { value.Signature[len(value.Signature)-1] ^= 1 }},
		{"final", func(value *VersionAuthorization) { value.FinalPolicy[0] ^= 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base.Clone()
			test.change(&changed)
			changedEncoded, err := encodeMode.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyVersionAuthorization(changedEncoded, &key.PublicKey, RecoveryNVIndex, 4); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
	trailingSignature := base.Clone()
	trailingSignature.Signature = append(trailingSignature.Signature, 0)
	trailingEncoded, err := encodeMode.Marshal(trailingSignature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyVersionAuthorization(
		trailingEncoded, &key.PublicKey, RecoveryNVIndex, 4); err == nil {
		t.Fatal("trailing TPM signature encoding accepted")
	}

	other := policyTestKey(t)
	if _, err := VerifyVersionAuthorization(encoded, &other.PublicKey, RecoveryNVIndex, 4); !errors.Is(err, ErrPolicyAuthentication) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestCheckedInPolicyVectorsVerifyAndReproducePublicFields(t *testing.T) {
	key := recoveryTestPrivateKey(t, "recovery-policy-test-private.pem")
	directory := filepath.Join("..", "..", "..", "tests", "vectors", "recovery-policy-v1")
	tests := []struct {
		name   string
		create func() ([]byte, error)
		verify func([]byte) (VersionAuthorization, error)
	}{
		{
			"initialize-4.cbor",
			func() ([]byte, error) {
				return CreateInitializationAuthorization(key, RecoveryNVIndex, 4)
			},
			func(encoded []byte) (VersionAuthorization, error) {
				return VerifyInitializationAuthorization(
					encoded, &key.PublicKey, RecoveryNVIndex, false)
			},
		},
		{
			"advance-4-to-5.cbor",
			func() ([]byte, error) {
				return CreateVersionAuthorization(key, RecoveryNVIndex, 5)
			},
			func(encoded []byte) (VersionAuthorization, error) {
				return VerifyVersionAuthorization(
					encoded, &key.PublicKey, RecoveryNVIndex, 4)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			checked, err := os.ReadFile(filepath.Join(directory, test.name))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(bytes.ToLower(checked), []byte("ticket")) {
				t.Fatal("authorization contains a ticket field")
			}
			checkedValue, err := test.verify(checked)
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := test.create()
			if err != nil {
				t.Fatal(err)
			}
			freshValue, err := test.verify(fresh)
			if err != nil {
				t.Fatal(err)
			}
			checkedValue.Signature = nil
			freshValue.Signature = nil
			if !reflect.DeepEqual(checkedValue, freshValue) {
				t.Fatal("fresh policy fields differ from checked vector")
			}
		})
	}
}

func TestPolicyAuthorizationIsCanonicalAndRoleSeparated(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateVersionAuthorization(p384, RecoveryNVIndex, 5); err == nil {
		t.Fatal("P-384 policy key accepted")
	}
	key := policyTestKey(t)
	otherKey := policyTestKey(t)
	mismatched := *key
	mismatched.PublicKey = otherKey.PublicKey
	if _, err := CreateVersionAuthorization(&mismatched, RecoveryNVIndex, 5); err == nil {
		t.Fatal("private scalar and public point mismatch accepted")
	}
	encoded, err := CreateVersionAuthorization(key, RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	var authorization VersionAuthorization
	if err := decodeMode.Unmarshal(encoded, &authorization); err != nil {
		t.Fatal(err)
	}
	canonical, err := encodeMode.Marshal(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, canonical) {
		t.Fatal("authorization is not canonical CBOR")
	}
	withUnknown := append([]byte(nil), encoded...)
	withUnknown[0]++
	withUnknown = append(withUnknown, 0x18, 0x63, 0x01)
	if _, err := VerifyVersionAuthorization(withUnknown, &key.PublicKey, RecoveryNVIndex, 4); err == nil {
		t.Fatal("unknown field accepted")
	}
	duplicate := append([]byte(nil), encoded...)
	if duplicate[0] != 0xb1 {
		t.Fatalf("unexpected policy map prefix 0x%02x", duplicate[0])
	}
	duplicate[0] = 0xb2
	duplicate = append(duplicate, 0x11, 0x58, 0x20)
	duplicate = append(duplicate, authorization.FinalPolicy...)
	if _, err := VerifyVersionAuthorization(duplicate, &key.PublicKey, RecoveryNVIndex, 4); err == nil {
		t.Fatal("duplicate field accepted")
	}
}
