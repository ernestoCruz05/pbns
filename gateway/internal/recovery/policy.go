package recovery

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

const (
	RecoveryNVIndex            = uint32(0x01801000)
	RecoveryPolicyRef          = "PBNS-RECOVERY-POLICY-REF-v1"
	initializationPolicyDomain = "PBNS-RECOVERY-POLICY-INIT-v1"
	updatePolicyDomain         = "PBNS-RECOVERY-POLICY-UPDATE-v1"
	PolicyKindInitialize       = "initialize"
	PolicyKindUpdate           = "update"
)

var (
	ErrPolicy               = errors.New("invalid recovery version policy")
	ErrPolicyVersion        = errors.New("recovery version is not an advance")
	ErrPolicyAuthentication = errors.New("recovery version policy authentication failed")
)

type VersionAuthorization struct {
	Domain          string `cbor:"1,keyasint"`
	Version         uint64 `cbor:"2,keyasint"`
	Kind            string `cbor:"3,keyasint"`
	NVIndex         uint32 `cbor:"4,keyasint"`
	NVPublic        []byte `cbor:"5,keyasint"`
	NVName          []byte `cbor:"6,keyasint"`
	TargetVersion   uint64 `cbor:"7,keyasint"`
	Operand         []byte `cbor:"8,keyasint"`
	Offset          uint16 `cbor:"9,keyasint"`
	Operation       uint16 `cbor:"10,keyasint"`
	CPHash          []byte `cbor:"11,keyasint"`
	ApprovedPolicy  []byte `cbor:"12,keyasint"`
	PolicyRef       []byte `cbor:"13,keyasint"`
	PolicyKeyPublic []byte `cbor:"14,keyasint"`
	PolicyKeyName   []byte `cbor:"15,keyasint"`
	Signature       []byte `cbor:"16,keyasint"`
	FinalPolicy     []byte `cbor:"17,keyasint"`
}

func CreateInitializationAuthorization(privateKey *ecdsa.PrivateKey, nvIndex uint32,
	initialVersion uint64) ([]byte, error) {
	return createPolicyAuthorization(privateKey, nvIndex, initialVersion, PolicyKindInitialize)
}

func CreateVersionAuthorization(privateKey *ecdsa.PrivateKey, nvIndex uint32,
	targetVersion uint64) ([]byte, error) {
	return createPolicyAuthorization(privateKey, nvIndex, targetVersion, PolicyKindUpdate)
}

func createPolicyAuthorization(privateKey *ecdsa.PrivateKey, nvIndex uint32,
	targetVersion uint64, kind string) ([]byte, error) {
	if !validPolicyPrivateKey(privateKey) || nvIndex != RecoveryNVIndex || targetVersion == 0 ||
		(kind != PolicyKindInitialize && kind != PolicyKindUpdate) {
		return nil, ErrPolicyVersion
	}
	policyPublic, err := policyTPMPublic(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	keyName, err := tpm2.ObjectName(&policyPublic)
	if err != nil {
		return nil, fmt.Errorf("calculate recovery policy key name: %w", err)
	}
	policyRef := []byte(RecoveryPolicyRef)
	finalPolicy, err := policyAuthorizeDigest(*keyName, policyRef)
	if err != nil {
		return nil, err
	}
	nvPublic := recoveryNVPublic(
		nvIndex, finalPolicy, kind == PolicyKindUpdate)
	nvName, err := tpm2.NVName(&nvPublic)
	if err != nil {
		return nil, fmt.Errorf("calculate recovery NV name: %w", err)
	}
	operand := make([]byte, 8)
	binary.BigEndian.PutUint64(operand, targetVersion)
	var cpHash []byte
	var approvedPolicy []byte
	var operation uint16
	if kind == PolicyKindInitialize {
		cpHash, approvedPolicy, err = initializationPolicyDigests(nvIndex, *nvName, operand)
	} else {
		operation = uint16(tpm2.TPMEOUnsignedLT)
		cpHash, approvedPolicy, err = versionPolicyDigests(
			nvIndex, *nvName, operand, 0, tpm2.TPMEOUnsignedLT)
	}
	if err != nil {
		return nil, err
	}
	approvalDigest := PolicyApprovalDigest(approvedPolicy, policyRef)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, approvalDigest[:])
	if err != nil {
		return nil, fmt.Errorf("sign recovery policy: %w", err)
	}
	signature := tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.FillBytes(make([]byte, 32))},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.FillBytes(make([]byte, 32))},
		}),
	}
	domain := updatePolicyDomain
	if kind == PolicyKindInitialize {
		domain = initializationPolicyDomain
	}
	authorization := VersionAuthorization{
		Domain: domain, Version: 1, Kind: kind, NVIndex: nvIndex,
		NVPublic: tpm2.Marshal(tpm2.New2B(nvPublic)),
		NVName:   append([]byte(nil), nvName.Buffer...), TargetVersion: targetVersion,
		Operand: operand, Offset: 0, Operation: operation,
		CPHash: cpHash, ApprovedPolicy: approvedPolicy, PolicyRef: policyRef,
		PolicyKeyPublic: tpm2.Marshal(tpm2.New2B(policyPublic)),
		PolicyKeyName:   append([]byte(nil), keyName.Buffer...),
		Signature:       tpm2.Marshal(signature), FinalPolicy: finalPolicy,
	}
	encoded, err := encodeMode.Marshal(authorization)
	if err != nil {
		return nil, fmt.Errorf("encode recovery policy: %w", err)
	}
	return encoded, nil
}

func VerifyInitializationAuthorization(encoded []byte, expectedKey *ecdsa.PublicKey,
	expectedIndex uint32, alreadyWritten bool) (VersionAuthorization, error) {
	if alreadyWritten {
		return VersionAuthorization{}, ErrPolicyVersion
	}
	return verifyPolicyAuthorization(
		encoded, expectedKey, expectedIndex, PolicyKindInitialize, 0)
}

func VerifyVersionAuthorization(encoded []byte, expectedKey *ecdsa.PublicKey,
	expectedIndex uint32, currentVersion uint64) (VersionAuthorization, error) {
	return verifyPolicyAuthorization(
		encoded, expectedKey, expectedIndex, PolicyKindUpdate, currentVersion)
}

func verifyPolicyAuthorization(encoded []byte, expectedKey *ecdsa.PublicKey,
	expectedIndex uint32, expectedKind string, currentVersion uint64) (VersionAuthorization, error) {
	if len(encoded) == 0 || len(encoded) > maximumPolicySize ||
		!validPolicyPublicKey(expectedKey) || expectedIndex != RecoveryNVIndex {
		return VersionAuthorization{}, ErrPolicy
	}
	var authorization VersionAuthorization
	if err := decodeMode.Unmarshal(encoded, &authorization); err != nil {
		return VersionAuthorization{}, ErrPolicy
	}
	canonical, err := encodeMode.Marshal(authorization)
	if err != nil || !bytes.Equal(canonical, encoded) || !authorization.shapeValid() ||
		authorization.Kind != expectedKind {
		return VersionAuthorization{}, ErrPolicy
	}
	if authorization.NVIndex != expectedIndex ||
		(expectedKind == PolicyKindUpdate && authorization.TargetVersion <= currentVersion) {
		return VersionAuthorization{}, ErrPolicyVersion
	}
	policyPublic, err := policyTPMPublic(expectedKey)
	if err != nil {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	encodedPublic := tpm2.Marshal(tpm2.New2B(policyPublic))
	if !canonicalTPM2BPublic(authorization.PolicyKeyPublic) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	keyName, err := tpm2.ObjectName(&policyPublic)
	if err != nil || !bytes.Equal(encodedPublic, authorization.PolicyKeyPublic) ||
		!bytes.Equal(keyName.Buffer, authorization.PolicyKeyName) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	finalPolicy, err := policyAuthorizeDigest(*keyName, authorization.PolicyRef)
	if err != nil || !bytes.Equal(finalPolicy, authorization.FinalPolicy) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	nvPublic := recoveryNVPublic(
		expectedIndex, finalPolicy, expectedKind == PolicyKindUpdate)
	encodedNVPublic := tpm2.Marshal(tpm2.New2B(nvPublic))
	if !canonicalTPM2BNVPublic(authorization.NVPublic) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	nvName, err := tpm2.NVName(&nvPublic)
	if err != nil || !bytes.Equal(encodedNVPublic, authorization.NVPublic) ||
		!bytes.Equal(nvName.Buffer, authorization.NVName) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	expectedOperand := make([]byte, 8)
	binary.BigEndian.PutUint64(expectedOperand, authorization.TargetVersion)
	if !bytes.Equal(expectedOperand, authorization.Operand) || authorization.Offset != 0 ||
		!bytes.Equal(authorization.PolicyRef, []byte(RecoveryPolicyRef)) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	var cpHash []byte
	var approvedPolicy []byte
	if expectedKind == PolicyKindInitialize {
		if authorization.Domain != initializationPolicyDomain || authorization.Operation != 0 {
			return VersionAuthorization{}, ErrPolicyAuthentication
		}
		cpHash, approvedPolicy, err = initializationPolicyDigests(
			expectedIndex, *nvName, expectedOperand)
	} else {
		if authorization.Domain != updatePolicyDomain ||
			authorization.Operation != uint16(tpm2.TPMEOUnsignedLT) {
			return VersionAuthorization{}, ErrPolicyAuthentication
		}
		cpHash, approvedPolicy, err = versionPolicyDigests(
			expectedIndex, *nvName, expectedOperand, authorization.Offset,
			tpm2.TPMEO(authorization.Operation))
	}
	if err != nil || !bytes.Equal(cpHash, authorization.CPHash) ||
		!bytes.Equal(approvedPolicy, authorization.ApprovedPolicy) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	signature, err := tpm2.Unmarshal[tpm2.TPMTSignature](authorization.Signature)
	if err != nil || !bytes.Equal(tpm2.Marshal(*signature), authorization.Signature) ||
		signature.SigAlg != tpm2.TPMAlgECDSA {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	ecdsaSignature, err := signature.Signature.ECDSA()
	if err != nil || ecdsaSignature.Hash != tpm2.TPMAlgSHA256 {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	approvalDigest := PolicyApprovalDigest(approvedPolicy, authorization.PolicyRef)
	r := new(big.Int).SetBytes(ecdsaSignature.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecdsaSignature.SignatureS.Buffer)
	if !ecdsa.Verify(expectedKey, approvalDigest[:], r, s) {
		return VersionAuthorization{}, ErrPolicyAuthentication
	}
	return authorization, nil
}

func PolicyApprovalDigest(approvedPolicy, policyRef []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(approvedPolicy)
	_, _ = hash.Write(policyRef)
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (authorization VersionAuthorization) Clone() VersionAuthorization {
	authorization.NVPublic = append([]byte(nil), authorization.NVPublic...)
	authorization.NVName = append([]byte(nil), authorization.NVName...)
	authorization.Operand = append([]byte(nil), authorization.Operand...)
	authorization.CPHash = append([]byte(nil), authorization.CPHash...)
	authorization.ApprovedPolicy = append([]byte(nil), authorization.ApprovedPolicy...)
	authorization.PolicyRef = append([]byte(nil), authorization.PolicyRef...)
	authorization.PolicyKeyPublic = append([]byte(nil), authorization.PolicyKeyPublic...)
	authorization.PolicyKeyName = append([]byte(nil), authorization.PolicyKeyName...)
	authorization.Signature = append([]byte(nil), authorization.Signature...)
	authorization.FinalPolicy = append([]byte(nil), authorization.FinalPolicy...)
	return authorization
}

func (authorization VersionAuthorization) shapeValid() bool {
	validDomain := authorization.Kind == PolicyKindInitialize &&
		authorization.Domain == initializationPolicyDomain ||
		authorization.Kind == PolicyKindUpdate && authorization.Domain == updatePolicyDomain
	return validDomain && authorization.Version == 1 && authorization.NVIndex == RecoveryNVIndex &&
		authorization.TargetVersion > 0 && len(authorization.NVPublic) > 0 &&
		len(authorization.NVPublic) <= 512 && len(authorization.NVName) == 34 &&
		len(authorization.Operand) == 8 && len(authorization.CPHash) == 32 &&
		len(authorization.ApprovedPolicy) == 32 && len(authorization.PolicyRef) > 0 &&
		len(authorization.PolicyRef) <= 64 && len(authorization.PolicyKeyPublic) > 0 &&
		len(authorization.PolicyKeyPublic) <= 512 && len(authorization.PolicyKeyName) == 34 &&
		len(authorization.Signature) > 0 && len(authorization.Signature) <= 256 &&
		len(authorization.FinalPolicy) == 32
}

func policyTPMPublic(publicKey *ecdsa.PublicKey) (tpm2.TPMTPublic, error) {
	if !validPolicyPublicKey(publicKey) {
		return tpm2.TPMTPublic{}, ErrPolicyAuthentication
	}
	return tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
			},
			CurveID: tpm2.TPMECCNistP256,
			KDF:     tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: publicKey.X.FillBytes(make([]byte, 32))},
			Y: tpm2.TPM2BECCParameter{Buffer: publicKey.Y.FillBytes(make([]byte, 32))},
		}),
	}, nil
}

func recoveryNVPublic(index uint32, finalPolicy []byte, written bool) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMIRHNVIndex(index), NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			PolicyWrite: true, OwnerRead: true, NoDA: true,
			NT: tpm2.TPMNTOrdinary, Written: written,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: append([]byte(nil), finalPolicy...)},
		DataSize:   8,
	}
}

func writeCPHash(index uint32, nvName tpm2.TPM2BName, operand []byte,
	offset uint16) ([]byte, error) {
	named := tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: nvName}
	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(index), Name: nvName},
		NVIndex:    named, Data: tpm2.TPM2BMaxNVBuffer{Buffer: append([]byte(nil), operand...)},
		Offset: offset,
	}
	cpHash, err := tpm2.CPHash(tpm2.TPMAlgSHA256, write)
	if err != nil {
		return nil, fmt.Errorf("calculate NV_Write cpHash: %w", err)
	}
	return append([]byte(nil), cpHash.Buffer...), nil
}

func initializationPolicyDigests(index uint32, nvName tpm2.TPM2BName,
	operand []byte) ([]byte, []byte, error) {
	cpHash, err := writeCPHash(index, nvName, operand, 0)
	if err != nil {
		return nil, nil, err
	}
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, nil, err
	}
	if err := (tpm2.PolicyNVWritten{WrittenSet: false}).Update(calculator); err != nil {
		return nil, nil, fmt.Errorf("calculate PolicyNVWritten: %w", err)
	}
	if err := (tpm2.PolicyCPHash{
		CPHashA: tpm2.TPM2BDigest{Buffer: cpHash},
	}).Update(calculator); err != nil {
		return nil, nil, fmt.Errorf("calculate PolicyCpHash: %w", err)
	}
	return cpHash, append([]byte(nil), calculator.Hash().Digest...), nil
}

func versionPolicyDigests(index uint32, nvName tpm2.TPM2BName, operand []byte,
	offset uint16, operation tpm2.TPMEO) ([]byte, []byte, error) {
	cpHash, err := writeCPHash(index, nvName, operand, offset)
	if err != nil {
		return nil, nil, err
	}
	named := tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: nvName}
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, nil, err
	}
	if err := (tpm2.PolicyNV{
		AuthHandle: named, NVIndex: named,
		OperandB: tpm2.TPM2BOperand{Buffer: append([]byte(nil), operand...)},
		Offset:   offset, Operation: operation,
	}).Update(calculator); err != nil {
		return nil, nil, fmt.Errorf("calculate PolicyNV: %w", err)
	}
	if err := (tpm2.PolicyCPHash{
		CPHashA: tpm2.TPM2BDigest{Buffer: cpHash},
	}).Update(calculator); err != nil {
		return nil, nil, fmt.Errorf("calculate PolicyCpHash: %w", err)
	}
	return cpHash, append([]byte(nil), calculator.Hash().Digest...), nil
}

func policyAuthorizeDigest(keyName tpm2.TPM2BName, policyRef []byte) ([]byte, error) {
	calculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyAuthorize{
		KeySign: keyName, PolicyRef: tpm2.TPM2BDigest{Buffer: append([]byte(nil), policyRef...)},
	}).Update(calculator); err != nil {
		return nil, fmt.Errorf("calculate PolicyAuthorize: %w", err)
	}
	return append([]byte(nil), calculator.Hash().Digest...), nil
}

func canonicalTPM2BPublic(encoded []byte) bool {
	value, err := tpm2.Unmarshal[tpm2.TPM2BPublic](encoded)
	return err == nil && bytes.Equal(tpm2.Marshal(*value), encoded)
}

func canonicalTPM2BNVPublic(encoded []byte) bool {
	value, err := tpm2.Unmarshal[tpm2.TPM2BNVPublic](encoded)
	return err == nil && bytes.Equal(tpm2.Marshal(*value), encoded)
}

func validPolicyPrivateKey(key *ecdsa.PrivateKey) bool {
	if key == nil || key.D == nil || key.D.Sign() <= 0 ||
		key.D.Cmp(elliptic.P256().Params().N) >= 0 || !validPolicyPublicKey(&key.PublicKey) {
		return false
	}
	x, y := elliptic.P256().ScalarBaseMult(key.D.Bytes())
	return x.Cmp(key.X) == 0 && y.Cmp(key.Y) == 0
}

func validPolicyPublicKey(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil &&
		key.Curve.IsOnCurve(key.X, key.Y)
}
