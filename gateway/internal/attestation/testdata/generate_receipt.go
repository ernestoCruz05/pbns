// Command generate_receipt creates deterministic hosted C interoperability vectors.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/attestation"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
)

var canonical cbor.EncMode

func init() {
	var err error
	canonical, err = cbor.CanonicalEncOptions().EncMode()
	must(err)
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: generate_receipt OUTPUT-DIR")
	}
	d := big.NewInt(1)
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	private := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
	kid := []byte("receipt-vector-1")
	signer, err := keys.NewPinnedOnlineSigner(keys.RoleAttestationReceipt, kid, private)
	must(err)
	input := fullInput()
	full, err := attestation.IssueReceipt(signer, deterministic(), input)
	must(err)
	failureInput := input
	failureInput.Verdict.Quote.Reason = attestation.ReasonQuoteSignature
	failure, err := attestation.IssueReceipt(signer, deterministic(), failureInput)
	must(err)
	reducedInput := input
	reducedInput.Assurance = model.AssuranceSoftware
	reducedInput.Verdict = attestation.Verdict{Quote: attestation.Check{Reason: attestation.ReasonSkipped}, EventLog: attestation.Check{Reason: attestation.ReasonSkipped}, MeasurementBaseline: attestation.Check{Reason: attestation.ReasonSkipped}, InventoryDrift: attestation.Check{Reason: attestation.ReasonSkipped}, Capability: attestation.Check{Reason: attestation.ReasonTPMRequired}}
	reduced, err := attestation.IssueReceipt(signer, deterministic(), reducedInput)
	must(err)

	base := attestation.Receipt{Domain: attestation.ReceiptDomain, Version: 1, Service: attestation.ServiceAttestation,
		RequestID: input.RequestID, VerifierNonce: input.VerifierNonce, HostFingerprint: input.HostFingerprint,
		EvidenceDigest: input.EvidenceDigest, BaselineID: input.BaselineID, Verdict: attestation.VerdictFailure,
		Reasons: []attestation.ReasonCode{attestation.ReasonCodeQuoteSignature}, KeyID: kid}
	invalid := map[string][]byte{}
	for name, mutant := range map[string]attestation.Receipt{
		"wrong-domain.cose":  func() attestation.Receipt { value := base; value.Domain = "PBNS-ATTESTATION-v1"; return value }(),
		"wrong-version.cose": func() attestation.Receipt { value := base; value.Version = 2; return value }(),
		"wrong-service.cose": func() attestation.Receipt { value := base; value.Service = 2; return value }(),
		"duplicate-reasons.cose": func() attestation.Receipt {
			value := base
			value.Reasons = []attestation.ReasonCode{7, 7}
			return value
		}(),
		"unsorted-reasons.cose": func() attestation.Receipt {
			value := base
			value.Reasons = []attestation.ReasonCode{7, 3}
			return value
		}(),
	} {
		payload, encodeErr := canonical.Marshal(mutant)
		must(encodeErr)
		invalid[name] = signRaw(private, kid, payload, aad(mutant))
	}
	payload, err := canonical.Marshal(base)
	must(err)
	duplicate := append([]byte(nil), payload...)
	duplicate[0] = 0xac
	encodedDomain, err := canonical.Marshal(attestation.ReceiptDomain)
	must(err)
	duplicate = append(duplicate, 0x01)
	duplicate = append(duplicate, encodedDomain...)
	invalid["duplicate-field.cose"] = signRaw(private, kid, duplicate, aad(base))
	unknown := append([]byte(nil), payload...)
	unknown[0] = 0xac
	unknown = append(unknown, 0x0c, 0x00)
	invalid["unknown-field.cose"] = signRaw(private, kid, unknown, aad(base))
	parsed := cose.NewSign1Message()
	must(parsed.UnmarshalCBOR(full))
	protected := append([]byte{0xa2, 0x01, 0x26, 0x04, 0x50}, kid...)
	wrongAlgorithm := append([]byte(nil), protected...)
	wrongAlgorithm[2] = 0x27
	wrongKid := append([]byte(nil), protected...)
	wrongKid[len(wrongKid)-1] ^= 0x80
	unknownProtected := append(append([]byte{0xa3, 0x01, 0x26, 0x04, 0x50}, kid...), 0x18, 0x63, 0x00)
	noncanonicalProtected := append(append([]byte{0xa2, 0x04, 0x50}, kid...), 0x01, 0x26)
	duplicateProtected := append([]byte{0xa3, 0x01, 0x26, 0x01, 0x26, 0x04, 0x50}, kid...)
	invalid["wrong-algorithm.cose"] = rawEnvelope(wrongAlgorithm, map[int]int{}, parsed.Payload, parsed.Signature)
	invalid["wrong-protected-kid.cose"] = rawEnvelope(wrongKid, map[int]int{}, parsed.Payload, parsed.Signature)
	invalid["unknown-protected.cose"] = rawEnvelope(unknownProtected, map[int]int{}, parsed.Payload, parsed.Signature)
	invalid["noncanonical-protected.cose"] = rawEnvelope(noncanonicalProtected, map[int]int{}, parsed.Payload, parsed.Signature)
	invalid["duplicate-protected.cose"] = rawEnvelope(duplicateProtected, map[int]int{}, parsed.Payload, parsed.Signature)
	invalid["nonempty-unprotected.cose"] = rawEnvelope(protected, map[int]int{5: 1}, parsed.Payload, parsed.Signature)

	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	must(err)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	must(os.MkdirAll(os.Args[1], 0o755))
	write(os.Args[1], "receipt.cose", full)
	write(os.Args[1], "reduced.cose", reduced)
	write(os.Args[1], "failure.cose", failure)
	write(os.Args[1], "public.pem", publicPEM)
	for name, value := range invalid {
		write(os.Args[1], name, value)
	}
	fmt.Printf("receipt_sha256=%x\n", sha256.Sum256(full))
}

func fullInput() attestation.ReceiptInput {
	var request [16]byte
	var nonce, host, evidence, baseline [32]byte
	request[0], nonce[0], host[0], evidence[0], baseline[0] = 1, 2, 3, 4, 5
	return attestation.ReceiptInput{RequestID: request, VerifierNonce: nonce, HostFingerprint: host,
		EvidenceDigest: evidence, BaselineID: baseline, Assurance: model.AssuranceTPMVerified,
		Verdict: attestation.Verdict{Quote: attestation.Check{Reason: attestation.ReasonTrusted}, EventLog: attestation.Check{Reason: attestation.ReasonTrusted}, MeasurementBaseline: attestation.Check{Reason: attestation.ReasonTrusted}, InventoryDrift: attestation.Check{Reason: attestation.ReasonTrusted}, Capability: attestation.Check{Reason: attestation.ReasonTrusted}}}
}
func aad(receipt attestation.Receipt) []byte {
	encoded, err := canonical.Marshal([]any{"PBNS-ATTESTATION-RECEIPT-SIGN-v1", uint64(1), attestation.ServiceAttestation,
		receipt.RequestID[:], receipt.VerifierNonce[:], receipt.HostFingerprint[:], receipt.EvidenceDigest[:], receipt.BaselineID[:], receipt.KeyID})
	must(err)
	return encoded
}
func rawEnvelope(protected []byte, unprotected map[int]int, payload, signature []byte) []byte {
	encoded, err := canonical.Marshal(cbor.Tag{Number: 18, Content: []any{protected, unprotected, payload, signature}})
	must(err)
	return encoded
}
func signRaw(key *ecdsa.PrivateKey, kid, payload, externalAAD []byte) []byte {
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	must(err)
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = kid
	message.Payload = payload
	must(message.Sign(deterministic(), externalAAD, signer))
	encoded, err := message.MarshalCBOR()
	must(err)
	return encoded
}
func deterministic() *bytes.Reader { return bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)) }
func write(directory, name string, value []byte) {
	must(os.WriteFile(filepath.Join(directory, name), value, 0o644))
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
