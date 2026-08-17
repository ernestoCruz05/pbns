package attestation

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
)

func receiptKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func receiptInput() ReceiptInput {
	var request [16]byte
	var nonce, host, evidence, baseline [32]byte
	request[0], nonce[0], host[0], evidence[0], baseline[0] = 1, 2, 3, 4, 5
	return ReceiptInput{RequestID: request, VerifierNonce: nonce, HostFingerprint: host,
		EvidenceDigest: evidence, BaselineID: baseline, Assurance: model.AssuranceTPMVerified,
		Verdict: Verdict{Quote: Check{ReasonTrusted}, EventLog: Check{ReasonTrusted},
			MeasurementBaseline: Check{ReasonTrusted}, InventoryDrift: Check{ReasonTrusted}, Capability: Check{ReasonTrusted}}}
}

func TestReceiptCanonicalSign1BindsContextAndRole(t *testing.T) {
	key := receiptKey(t)
	signer, err := keys.NewPinnedOnlineSigner(keys.RoleAttestationReceipt, []byte("receipt-1"), key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := IssueReceipt(signer, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), receiptInput())
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	input := receiptInput()
	got, err := VerifyReceipt(signed, verifier, signer.KeyID(), input.RequestID, input.VerifierNonce,
		input.HostFingerprint, input.EvidenceDigest, input.BaselineID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict() != VerdictFull || len(got.Reasons()) != 0 || DisplayReceipt(got) != "full assurance" {
		t.Fatalf("unexpected receipt %#v display=%q", got, DisplayReceipt(got))
	}
	challengeSigner, err := keys.NewPinnedOnlineSigner(keys.RoleAttestation, []byte("challenge"), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueReceipt(challengeSigner, rand.Reader, input); !errors.Is(err, ErrReceiptRole) {
		t.Fatalf("challenge role signed receipt: %v", err)
	}
}

func TestReceiptRejectsEveryBindingMutantAndWrongKey(t *testing.T) {
	key := receiptKey(t)
	signer, _ := keys.NewPinnedOnlineSigner(keys.RoleAttestationReceipt, []byte("receipt-1"), key)
	input := receiptInput()
	signed, err := IssueReceipt(signer, rand.Reader, input)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	mutants := []struct {
		name                            string
		request                         [16]byte
		nonce, host, evidence, baseline [32]byte
		kid                             []byte
	}{
		{"request", input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID, signer.KeyID()},
		{"nonce", input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID, signer.KeyID()},
		{"host", input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID, signer.KeyID()},
		{"evidence", input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID, signer.KeyID()},
		{"baseline", input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID, signer.KeyID()},
		{"kid", input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID, []byte("wrong")},
	}
	mutants[0].request[0] ^= 1
	mutants[1].nonce[0] ^= 1
	mutants[2].host[0] ^= 1
	mutants[3].evidence[0] ^= 1
	mutants[4].baseline[0] ^= 1
	for _, mutant := range mutants {
		t.Run(mutant.name, func(t *testing.T) {
			if _, err := VerifyReceipt(signed, verifier, mutant.kid, mutant.request, mutant.nonce, mutant.host, mutant.evidence, mutant.baseline); !errors.Is(err, ErrReceiptAuthentication) {
				t.Fatalf("binding mutant accepted: %v", err)
			}
		})
	}
	wrong := receiptKey(t)
	wrongVerifier, _ := cose.NewVerifier(cose.AlgorithmES256, &wrong.PublicKey)
	if _, err := VerifyReceipt(signed, wrongVerifier, signer.KeyID(), input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID); !errors.Is(err, ErrReceiptAuthentication) {
		t.Fatalf("wrong key accepted: %v", err)
	}
	wrongAlgorithm := append([]byte(nil), signed...)
	position := bytes.Index(wrongAlgorithm, []byte{0xa2, 0x01, 0x26, 0x04})
	if position < 0 {
		t.Fatal("protected algorithm not found")
	}
	wrongAlgorithm[position+2] = 0x27
	for _, malformed := range [][]byte{append(append([]byte(nil), signed...), 0), append([]byte{0x9f}, signed...), wrongAlgorithm} {
		if _, err := VerifyReceipt(malformed, verifier, signer.KeyID(), input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID); err == nil {
			t.Fatal("noncanonical/trailing/algorithm mutant accepted")
		}
	}
}

func rawReceiptEnvelope(t *testing.T, protected []byte, unprotected map[int]int, payload, signature []byte) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mode.Marshal(cbor.Tag{Number: 18, Content: []any{protected, unprotected, payload, signature}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestReceiptRejectsProtectedAndUnprotectedProfileMutants(t *testing.T) {
	key := receiptKey(t)
	kid := []byte("receipt-1")
	signer, _ := keys.NewPinnedOnlineSigner(keys.RoleAttestationReceipt, kid, key)
	input := receiptInput()
	valid, err := IssueReceipt(signer, rand.Reader, input)
	if err != nil {
		t.Fatal(err)
	}
	parsed := cose.NewSign1Message()
	if err := parsed.UnmarshalCBOR(valid); err != nil {
		t.Fatal(err)
	}
	protected := append([]byte{0xa2, 0x01, 0x26, 0x04, 0x49}, kid...)
	wrongKid := append([]byte(nil), protected...)
	wrongKid[len(wrongKid)-1] ^= 0x80
	unknown := append(append([]byte{0xa3, 0x01, 0x26, 0x04, 0x49}, kid...), 0x18, 0x63, 0x00)
	noncanonical := append(append([]byte{0xa2, 0x04, 0x49}, kid...), 0x01, 0x26)
	duplicate := append([]byte{0xa3, 0x01, 0x26, 0x01, 0x26, 0x04, 0x49}, kid...)
	mutants := [][]byte{rawReceiptEnvelope(t, wrongKid, map[int]int{}, parsed.Payload, parsed.Signature), rawReceiptEnvelope(t, unknown, map[int]int{}, parsed.Payload, parsed.Signature), rawReceiptEnvelope(t, noncanonical, map[int]int{}, parsed.Payload, parsed.Signature), rawReceiptEnvelope(t, duplicate, map[int]int{}, parsed.Payload, parsed.Signature), rawReceiptEnvelope(t, protected, map[int]int{5: 1}, parsed.Payload, parsed.Signature)}
	verifier, _ := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	for index, mutant := range mutants {
		if verified, err := VerifyReceipt(mutant, verifier, kid, input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID); err == nil || DisplayReceipt(verified) != "attestation failure" {
			t.Fatalf("profile mutant %d accepted", index)
		}
	}
}

func TestReceiptVerdictsReasonsAndDisplayCannotConfuseTransportSuccess(t *testing.T) {
	if DisplayReceipt(VerifiedReceipt{}) != "attestation failure" {
		t.Fatal("zero verified receipt displayed as trusted")
	}
	key := receiptKey(t)
	signer, _ := keys.NewPinnedOnlineSigner(keys.RoleAttestationReceipt, []byte("receipt-1"), key)
	verifier, _ := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	cases := []struct {
		name    string
		input   ReceiptInput
		want    ReceiptVerdict
		display string
	}{
		{"full", receiptInput(), VerdictFull, "full assurance"},
		{"reduced", receiptInput(), VerdictReduced, "reduced assurance"},
		{"failure", receiptInput(), VerdictFailure, "attestation failure"},
	}
	cases[1].input.Assurance = model.AssuranceSoftware
	cases[1].input.Verdict = Verdict{Quote: Check{ReasonSkipped}, EventLog: Check{ReasonSkipped}, MeasurementBaseline: Check{ReasonSkipped}, InventoryDrift: Check{ReasonSkipped}, Capability: Check{ReasonTPMRequired}}
	cases[2].input.Verdict.Quote.Reason = ReasonQuoteSignature
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := IssueReceipt(signer, rand.Reader, tc.input)
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyReceipt(signed, verifier, signer.KeyID(), tc.input.RequestID, tc.input.VerifierNonce, tc.input.HostFingerprint, tc.input.EvidenceDigest, tc.input.BaselineID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict() != tc.want || DisplayReceipt(got) != tc.display {
				t.Fatalf("got %#v %q", got, DisplayReceipt(got))
			}
		})
	}
}

func signRawReceipt(t *testing.T, key *ecdsa.PrivateKey, kid, payload []byte) []byte {
	t.Helper()
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = append([]byte(nil), kid...)
	message.Payload = append([]byte(nil), payload...)
	var receipt Receipt
	if strictMode.Unmarshal(payload, &receipt) != nil {
		receipt = Receipt{Domain: ReceiptDomain, Version: 1, Service: ServiceAttestation}
	}
	if err := message.Sign(rand.Reader, receiptAAD(receipt), signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestReceiptRejectsSignedDomainVersionReasonAndFieldMutants(t *testing.T) {
	key := receiptKey(t)
	kid := []byte("receipt-1")
	verifier, _ := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
	input := receiptInput()
	base := Receipt{Domain: ReceiptDomain, Version: 1, Service: ServiceAttestation, RequestID: input.RequestID,
		VerifierNonce: input.VerifierNonce, HostFingerprint: input.HostFingerprint, EvidenceDigest: input.EvidenceDigest,
		BaselineID: input.BaselineID, Verdict: VerdictFailure, Reasons: []ReasonCode{ReasonCodeQuoteSignature}, KeyID: kid}
	mutants := []Receipt{base, base, base, base, base, base}
	mutants[0].Domain = "PBNS-ATTESTATION-v1"
	mutants[1].Version = 2
	mutants[2].Service = 2
	mutants[3].Reasons = []ReasonCode{ReasonCodeQuoteSignature, ReasonCodeQuoteSignature}
	mutants[4].Reasons = []ReasonCode{ReasonCodeQuoteSignature, ReasonCodeAKName}
	mutants[5].Reasons = []ReasonCode{255}
	for index, mutant := range mutants {
		payload, err := canonicalMode.Marshal(mutant)
		if err != nil {
			t.Fatal(err)
		}
		signed := signRawReceipt(t, key, kid, payload)
		if _, err := VerifyReceipt(signed, verifier, kid, input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID); err == nil {
			t.Fatalf("signed mutant %d accepted", index)
		}
	}
	payload, _ := canonicalMode.Marshal(base)
	duplicate := append([]byte(nil), payload...)
	duplicate[0] = 0xac
	encodedDomain, _ := canonicalMode.Marshal(ReceiptDomain)
	duplicate = append(duplicate, 0x01)
	duplicate = append(duplicate, encodedDomain...)
	unknown := append([]byte(nil), payload...)
	unknown[0] = 0xac
	unknown = append(unknown, 0x0c, 0x00)
	for name, malformed := range map[string][]byte{"duplicate": duplicate, "unknown": unknown} {
		signed := signRawReceipt(t, key, kid, malformed)
		if _, err := VerifyReceipt(signed, verifier, kid, input.RequestID, input.VerifierNonce, input.HostFingerprint, input.EvidenceDigest, input.BaselineID); err == nil {
			t.Fatalf("%s field accepted", name)
		}
	}
}
