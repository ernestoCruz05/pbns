package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
)

var ErrTPMEvidence = errors.New("invalid TPM enrollment evidence")

func tpmEvidenceError(stage string) error {
	return fmt.Errorf("%s: %w", stage, ErrTPMEvidence)
}

type GoAttestationVerifier struct {
	random io.Reader
}

func NewGoAttestationVerifier(random io.Reader) (*GoAttestationVerifier, error) {
	if random == nil {
		return nil, ErrInvalid
	}
	return &GoAttestationVerifier{random: random}, nil
}

func (verifier *GoAttestationVerifier) Generate(
	request activationRequest,
) (activationChallenge, error) {
	if verifier == nil || verifier.random == nil || len(request.EKPublic) == 0 ||
		len(request.AKPublic) == 0 || len(request.AKName) == 0 {
		return activationChallenge{}, ErrTPMEvidence
	}
	ekPublic, err := parseEKPublic(request.EKPublic)
	if err != nil {
		return activationChallenge{}, ErrTPMEvidence
	}
	akPublic, err := decodeTPMPublic(request.AKPublic)
	if err != nil || !validAKTPMPublic(akPublic) {
		return activationChallenge{}, ErrTPMEvidence
	}
	akName, err := akPublic.Name()
	if err != nil || akName.Digest == nil || len(akName.Digest.Value) != sha256.Size {
		return activationChallenge{}, ErrTPMEvidence
	}
	encodedName, err := akName.Digest.Encode()
	if err != nil || !bytes.Equal(encodedName, request.AKName) {
		return activationChallenge{}, ErrTPMEvidence
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(verifier.random, secret); err != nil {
		clear(secret)
		return activationChallenge{}, ErrTPMEvidence
	}
	credential, encryptedSecret, err := credactivation.Generate(
		akName.Digest, ekPublic, 16, secret,
	)
	if err != nil || len(credential) == 0 || len(encryptedSecret) == 0 {
		clear(secret)
		return activationChallenge{}, ErrTPMEvidence
	}
	var result activationChallenge
	copy(result.Secret[:], secret)
	result.CredentialBlob = append([]byte(nil), credential...)
	result.EncryptedSecret = append([]byte(nil), encryptedSecret...)
	clear(secret)
	return result, nil
}

func decodeTPMPublic(encoded []byte) (tpm2.Public, error) {
	public, err := tpm2.DecodePublic(encoded)
	if err == nil {
		return public, nil
	}
	if len(encoded) < 3 || int(binary.BigEndian.Uint16(encoded[:2])) != len(encoded)-2 {
		return tpm2.Public{}, err
	}
	return tpm2.DecodePublic(encoded[2:])
}

func validAKTPMPublic(public tpm2.Public) bool {
	parameters := public.ECCParameters
	return public.Type == tpm2.AlgECC && public.NameAlg == tpm2.AlgSHA256 &&
		public.Attributes == tpm2.FlagSignerDefault && len(public.AuthPolicy) == 0 &&
		parameters != nil && parameters.Symmetric == nil && parameters.KDF == nil &&
		parameters.CurveID == tpm2.CurveNISTP256 && parameters.Sign != nil &&
		parameters.Sign.Alg == tpm2.AlgECDSA && parameters.Sign.Hash == tpm2.AlgSHA256 &&
		len(parameters.Point.XRaw) == 32 && len(parameters.Point.YRaw) == 32
}

func (verifier *GoAttestationVerifier) Verify(
	session certificationSession,
	proof Proof,
) error {
	if verifier == nil || len(session.AKPublic) == 0 ||
		len(session.IdentityTPMPublic) == 0 || session.IdentityPublic == nil ||
		len(proof.CertifyAttestation) == 0 || len(proof.CertifySignature) == 0 {
		return tpmEvidenceError("arguments")
	}
	akPublic, err := decodeTPMPublic(session.AKPublic)
	if err != nil || akPublic.NameAlg != tpm2.AlgSHA256 {
		return tpmEvidenceError("ak-public")
	}
	akKey, err := akPublic.Key()
	if err != nil {
		return tpmEvidenceError("ak-key")
	}
	akECDSA, ok := akKey.(*ecdsa.PublicKey)
	if !ok {
		return tpmEvidenceError("ak-key-type")
	}
	identityTPMPublic, err := decodeTPMPublic(session.IdentityTPMPublic)
	if err != nil {
		return tpmEvidenceError("identity-public")
	}
	identityKey, err := identityTPMPublic.Key()
	if err != nil {
		return tpmEvidenceError("identity-key")
	}
	canonicalIdentityPublic, err := identityTPMPublic.Encode()
	if err != nil || len(canonicalIdentityPublic) == 0 {
		return tpmEvidenceError("identity-public-encoding")
	}
	identityECDSA, ok := identityKey.(*ecdsa.PublicKey)
	if !ok || !identityECDSA.Equal(session.IdentityPublic) {
		return tpmEvidenceError("identity-binding")
	}
	parameters := attest.CertificationParameters{
		Public: canonicalIdentityPublic, CreateAttestation: proof.CertifyAttestation,
		CreateSignature: proof.CertifySignature,
	}
	hashAlgorithm, err := akPublic.NameAlg.Hash()
	if err != nil {
		return tpmEvidenceError("ak-hash")
	}
	if err := parameters.Verify(attest.VerifyOpts{
		Public: akECDSA, Hash: hashAlgorithm,
	}); err != nil {
		return tpmEvidenceError("certification")
	}
	attestation, err := tpm2.DecodeAttestationData(proof.CertifyAttestation)
	if err != nil || !bytes.Equal(attestation.ExtraData, certificationDigest(session)) {
		return tpmEvidenceError("qualifying-data")
	}
	return nil
}

func certificationDigest(session certificationSession) []byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte("PBNS-ENROLLMENT-CERTIFY-v1"))
	_, _ = digest.Write(session.RequestID[:])
	_, _ = digest.Write(session.ServerNonce[:])
	_, _ = digest.Write(session.InitDigest[:])
	_, _ = digest.Write(session.BaselineDigest[:])
	return digest.Sum(nil)
}
