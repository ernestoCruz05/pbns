package attestation

import (
	"bytes"
	"errors"
	"io"
	"sort"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
)

const (
	ReceiptDomain    = "PBNS-ATTESTATION-RECEIPT-v1"
	receiptAADDomain = "PBNS-ATTESTATION-RECEIPT-SIGN-v1"
	maxReceiptSize   = 4096
)

var (
	ErrReceiptInvalid        = errors.New("invalid attestation receipt")
	ErrReceiptAuthentication = errors.New("attestation receipt authentication failed")
	ErrReceiptRole           = errors.New("attestation receipt signer role mismatch")
)

type ReceiptVerdict uint64

const (
	VerdictFull    ReceiptVerdict = 1
	VerdictReduced ReceiptVerdict = 2
	VerdictFailure ReceiptVerdict = 3
)

type ReasonCode uint64

const (
	ReasonCodeTPMRequired               ReasonCode = 1
	ReasonCodeIdentityAssociation       ReasonCode = 2
	ReasonCodeAKName                    ReasonCode = 3
	ReasonCodeAKProfile                 ReasonCode = 4
	ReasonCodeQuoteMalformed            ReasonCode = 5
	ReasonCodeQuoteType                 ReasonCode = 6
	ReasonCodeQuoteSignature            ReasonCode = 7
	ReasonCodeQualifyingData            ReasonCode = 8
	ReasonCodePCRSelection              ReasonCode = 9
	ReasonCodePCRDigest                 ReasonCode = 10
	ReasonCodeEventLogMalformed         ReasonCode = 11
	ReasonCodeEventLogReplay            ReasonCode = 12
	ReasonCodeUnsupportedEventAlgorithm ReasonCode = 13
	ReasonCodeBaselineUnavailable       ReasonCode = 14
	ReasonCodeMeasurementBaseline       ReasonCode = 15
	ReasonCodeInventoryDrift            ReasonCode = 16
)

type ReceiptInput struct {
	RequestID       [16]byte
	VerifierNonce   [32]byte
	HostFingerprint [32]byte
	EvidenceDigest  [32]byte
	BaselineID      [32]byte
	Assurance       model.Assurance
	Verdict         Verdict
}

type Receipt struct {
	Domain          string         `cbor:"1,keyasint"`
	Version         uint64         `cbor:"2,keyasint"`
	Service         uint64         `cbor:"3,keyasint"`
	RequestID       [16]byte       `cbor:"4,keyasint"`
	VerifierNonce   [32]byte       `cbor:"5,keyasint"`
	HostFingerprint [32]byte       `cbor:"6,keyasint"`
	EvidenceDigest  [32]byte       `cbor:"7,keyasint"`
	BaselineID      [32]byte       `cbor:"8,keyasint"`
	Verdict         ReceiptVerdict `cbor:"9,keyasint"`
	Reasons         []ReasonCode   `cbor:"10,keyasint"`
	KeyID           []byte         `cbor:"11,keyasint"`
}

// VerifiedReceipt carries display authority only after successful authentication.
type VerifiedReceipt struct {
	receipt       Receipt
	authenticated bool
}

func (verified VerifiedReceipt) Verdict() ReceiptVerdict {
	if !verified.authenticated {
		return VerdictFailure
	}
	return verified.receipt.Verdict
}
func (verified VerifiedReceipt) Reasons() []ReasonCode {
	if !verified.authenticated {
		return nil
	}
	return append([]ReasonCode(nil), verified.receipt.Reasons...)
}

func IssueReceipt(signer *keys.AuthorizedSigner, random io.Reader, input ReceiptInput) ([]byte, error) {
	if signer == nil || random == nil || signer.RequireRole(keys.RoleAttestationReceipt) != nil {
		return nil, ErrReceiptRole
	}
	verdict, reasons := receiptOutcome(input.Assurance, input.Verdict)
	receipt := Receipt{Domain: ReceiptDomain, Version: 1, Service: ServiceAttestation,
		RequestID: input.RequestID, VerifierNonce: input.VerifierNonce, HostFingerprint: input.HostFingerprint,
		EvidenceDigest: input.EvidenceDigest, BaselineID: input.BaselineID, Verdict: verdict,
		Reasons: reasons, KeyID: signer.KeyID()}
	if !validReceipt(receipt) {
		return nil, ErrReceiptInvalid
	}
	payload, err := canonicalMode.Marshal(receipt)
	if err != nil {
		return nil, ErrReceiptInvalid
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = signer.KeyID()
	message.Payload = payload
	if err := message.Sign(random, receiptAAD(receipt), signer.COSESigner()); err != nil {
		return nil, ErrReceiptAuthentication
	}
	encoded, err := message.MarshalCBOR()
	if err != nil || len(encoded) > maxReceiptSize {
		return nil, ErrReceiptInvalid
	}
	return encoded, nil
}

func VerifyReceipt(encoded []byte, verifier cose.Verifier, expectedKID []byte,
	requestID [16]byte, nonce, host, evidence, baseline [32]byte) (VerifiedReceipt, error) {
	if verifier == nil || len(expectedKID) == 0 || len(expectedKID) > 64 || len(encoded) == 0 || len(encoded) > maxReceiptSize {
		return VerifiedReceipt{}, ErrReceiptAuthentication
	}
	message := cose.NewSign1Message()
	if message.UnmarshalCBOR(encoded) != nil {
		return VerifiedReceipt{}, ErrReceiptInvalid
	}
	if !canonicalReceiptSign1(encoded, message, expectedKID) {
		return VerifiedReceipt{}, ErrReceiptAuthentication
	}
	var receipt Receipt
	if decodeCanonical(message.Payload, &receipt) != nil || !validReceipt(receipt) {
		return VerifiedReceipt{}, ErrReceiptInvalid
	}
	if receipt.RequestID != requestID || receipt.VerifierNonce != nonce || receipt.HostFingerprint != host ||
		receipt.EvidenceDigest != evidence || receipt.BaselineID != baseline || !bytes.Equal(receipt.KeyID, expectedKID) {
		return VerifiedReceipt{}, ErrReceiptAuthentication
	}
	if message.Verify(receiptAAD(receipt), verifier) != nil {
		return VerifiedReceipt{}, ErrReceiptAuthentication
	}
	return VerifiedReceipt{receipt: cloneReceipt(receipt), authenticated: true}, nil
}

func DisplayReceipt(verified VerifiedReceipt) string {
	if !verified.authenticated || !validReceipt(verified.receipt) {
		return "attestation failure"
	}
	switch verified.receipt.Verdict {
	case VerdictFull:
		return "full assurance"
	case VerdictReduced:
		return "reduced assurance"
	default:
		return "attestation failure"
	}
}

func receiptAAD(receipt Receipt) []byte {
	return mustCanonical([]any{receiptAADDomain, uint64(1), ServiceAttestation, receipt.RequestID[:],
		receipt.VerifierNonce[:], receipt.HostFingerprint[:], receipt.EvidenceDigest[:], receipt.BaselineID[:], receipt.KeyID})
}

func receiptOutcome(assurance model.Assurance, verdict Verdict) (ReceiptVerdict, []ReasonCode) {
	if (assurance == model.AssuranceTPMVerified || assurance == model.AssuranceTPMUnverified) && verdict.Trusted() {
		return VerdictFull, []ReasonCode{}
	}
	if assurance == model.AssuranceSoftware && verdict.Capability.Reason == ReasonTPMRequired &&
		verdict.Quote.Reason == ReasonSkipped && verdict.EventLog.Reason == ReasonSkipped &&
		verdict.MeasurementBaseline.Reason == ReasonSkipped && verdict.InventoryDrift.Reason == ReasonSkipped {
		return VerdictReduced, []ReasonCode{ReasonCodeTPMRequired}
	}
	reasons := make([]ReasonCode, 0, 5)
	for _, check := range []Check{verdict.Quote, verdict.EventLog, verdict.MeasurementBaseline, verdict.InventoryDrift, verdict.Capability} {
		if code, ok := reasonCode(check.Reason); ok {
			reasons = append(reasons, code)
		}
	}
	if assurance != model.AssuranceTPMVerified && len(reasons) == 0 {
		reasons = append(reasons, ReasonCodeIdentityAssociation)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	reasons = uniqueReasons(reasons)
	return VerdictFailure, reasons
}

func reasonCode(reason Reason) (ReasonCode, bool) {
	switch reason {
	case ReasonTPMRequired:
		return ReasonCodeTPMRequired, true
	case ReasonIdentityAssociation:
		return ReasonCodeIdentityAssociation, true
	case ReasonAKName:
		return ReasonCodeAKName, true
	case ReasonAKProfile:
		return ReasonCodeAKProfile, true
	case ReasonQuoteMalformed:
		return ReasonCodeQuoteMalformed, true
	case ReasonQuoteType:
		return ReasonCodeQuoteType, true
	case ReasonQuoteSignature:
		return ReasonCodeQuoteSignature, true
	case ReasonQualifyingData:
		return ReasonCodeQualifyingData, true
	case ReasonPCRSelection:
		return ReasonCodePCRSelection, true
	case ReasonPCRDigest:
		return ReasonCodePCRDigest, true
	case ReasonEventLogMalformed:
		return ReasonCodeEventLogMalformed, true
	case ReasonEventLogReplay:
		return ReasonCodeEventLogReplay, true
	case ReasonUnsupportedEventAlgorithm:
		return ReasonCodeUnsupportedEventAlgorithm, true
	case ReasonBaselineUnavailable:
		return ReasonCodeBaselineUnavailable, true
	case ReasonMeasurementBaseline:
		return ReasonCodeMeasurementBaseline, true
	case ReasonInventoryDrift:
		return ReasonCodeInventoryDrift, true
	default:
		return 0, false
	}
}

func validReceipt(receipt Receipt) bool {
	if receipt.Domain != ReceiptDomain || receipt.Version != 1 || receipt.Service != ServiceAttestation ||
		allZero(receipt.RequestID[:]) || allZero(receipt.VerifierNonce[:]) || allZero(receipt.HostFingerprint[:]) ||
		allZero(receipt.EvidenceDigest[:]) || allZero(receipt.BaselineID[:]) || len(receipt.KeyID) == 0 || len(receipt.KeyID) > 64 ||
		!validateReasonCodes(receipt.Reasons) {
		return false
	}
	switch receipt.Verdict {
	case VerdictFull:
		return len(receipt.Reasons) == 0
	case VerdictReduced:
		return len(receipt.Reasons) == 1 && receipt.Reasons[0] == ReasonCodeTPMRequired
	case VerdictFailure:
		return len(receipt.Reasons) > 0
	default:
		return false
	}
}

func validateReasonCodes(reasons []ReasonCode) bool {
	for index, reason := range reasons {
		if reason < ReasonCodeTPMRequired || reason > ReasonCodeInventoryDrift || (index > 0 && reason <= reasons[index-1]) {
			return false
		}
	}
	return true
}
func uniqueReasons(values []ReasonCode) []ReasonCode {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
func cloneReceipt(receipt Receipt) Receipt {
	receipt.Reasons = append([]ReasonCode(nil), receipt.Reasons...)
	receipt.KeyID = append([]byte(nil), receipt.KeyID...)
	return receipt
}

func canonicalReceiptSign1(encoded []byte, message *cose.Sign1Message, expectedKID []byte) bool {
	if message == nil || len(message.Headers.Unprotected) != 0 || len(message.Headers.Protected) != 2 {
		return false
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmES256 {
		return false
	}
	kid, ok := message.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	if !ok || !bytes.Equal(kid, expectedKID) {
		return false
	}
	for label := range message.Headers.Protected {
		if label != cose.HeaderLabelAlgorithm && label != cose.HeaderLabelKeyID {
			return false
		}
	}
	protected, err := message.Headers.Protected.MarshalCBOR()
	if err != nil || !bytes.Equal(protected, message.Headers.RawProtected) {
		return false
	}
	unprotected, err := canonicalMode.Marshal(message.Headers.Unprotected)
	if err != nil || !bytes.Equal(unprotected, message.Headers.RawUnprotected) {
		return false
	}
	canonical, err := message.MarshalCBOR()
	return err == nil && bytes.Equal(canonical, encoded)
}
