package attestation

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"log"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	modern "github.com/google/go-tpm/tpm2"

	"pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/model"
)

const tpmGeneratedMagic uint32 = 0xff544347

type Reason string

const (
	ReasonTrusted                   Reason = "trusted"
	ReasonSkipped                   Reason = "skipped"
	ReasonTPMRequired               Reason = "tpm_required"
	ReasonIdentityAssociation       Reason = "identity_association"
	ReasonAKName                    Reason = "ak_name"
	ReasonAKProfile                 Reason = "ak_profile"
	ReasonQuoteMalformed            Reason = "quote_malformed"
	ReasonQuoteType                 Reason = "quote_type"
	ReasonQuoteSignature            Reason = "quote_signature"
	ReasonQualifyingData            Reason = "qualifying_data"
	ReasonPCRSelection              Reason = "pcr_selection"
	ReasonPCRDigest                 Reason = "pcr_digest"
	ReasonEventLogMalformed         Reason = "event_log_malformed"
	ReasonEventLogReplay            Reason = "event_log_replay"
	ReasonUnsupportedEventAlgorithm Reason = "unsupported_event_algorithm"
	ReasonBaselineUnavailable       Reason = "baseline_unavailable"
	ReasonMeasurementBaseline       Reason = "measurement_baseline"
	ReasonInventoryDrift            Reason = "inventory_drift"
)

type Check struct{ Reason Reason }

func (c Check) Trusted() bool { return c.Reason == ReasonTrusted }

// Verdict intentionally separates TPM-attested measurements from inventory, which is signed by the identity but not directly TPM-attested.
type Verdict struct {
	Quote               Check
	EventLog            Check
	MeasurementBaseline Check
	InventoryDrift      Check
	Capability          Check
}

func (v Verdict) Trusted() bool {
	return v.Quote.Trusted() && v.EventLog.Trusted() && v.MeasurementBaseline.Trusted() && v.InventoryDrift.Trusted() && v.Capability.Trusted()
}

type VerificationError struct{ Verdict Verdict }

func (e *VerificationError) Error() string { return "TPM verification rejected" }

// BaselineSource is read-only. store.Store.GetBaseline has this exact shape.
type BaselineSource interface {
	GetBaseline([32]byte) ([]byte, error)
}

type Verifier struct{ baselines BaselineSource }

func NewVerifier(baselines BaselineSource) (*Verifier, error) {
	if baselines == nil {
		return nil, ErrInvalid
	}
	return &Verifier{baselines: baselines}, nil
}

// Verify implements the immutable EvidenceConsumer boundary.
func (v *Verifier) Verify(evidence VerifiedEvidence) error {
	if v == nil || v.baselines == nil {
		return ErrVerification
	}
	verdict := v.Assess(evidence)
	if !verdict.Trusted() {
		return &VerificationError{Verdict: verdict}
	}
	return nil
}

// Assess is pure apart from its one read of the controlled enrollment baseline.
func (v *Verifier) Assess(evidence VerifiedEvidence) Verdict {
	result := Verdict{Quote: Check{ReasonSkipped}, EventLog: Check{ReasonSkipped}, MeasurementBaseline: Check{ReasonSkipped}, InventoryDrift: Check{ReasonSkipped}, Capability: Check{ReasonTrusted}}
	if v == nil || v.baselines == nil || evidence.Host.Assurance == model.AssuranceSoftware {
		log.Printf("[PBNS-ATTEST] Assess rejected: TPM required (assurance=%v)", evidence.Host.Assurance)
		result.Capability.Reason = ReasonTPMRequired
		return result
	}
	if evidence.Host.Validate() != nil || sha256.Sum256(evidence.Host.IdentityCOSEKey) != evidence.Host.Fingerprint || evidence.Host.Fingerprint != evidence.Challenge.Context.HostFingerprint {
		log.Printf("[PBNS-ATTEST] Assess rejected: Identity association failure")
		result.Capability.Reason = ReasonIdentityAssociation
		return result
	}
	quote, pcrs, reason := verifyQuote(evidence)
	log.Printf("[PBNS-ATTEST] verifyQuote result: %s (pcrs=%d)", reason, len(pcrs))
	if reason != ReasonTrusted {
		result.Quote.Reason = reason
		return result
	}
	result.Quote.Reason = ReasonTrusted
	eventReason := replayEventLog(evidence.Evidence.EventLog, pcrs)
	log.Printf("[PBNS-ATTEST] replayEventLog result: %s", eventReason)
	if eventReason != ReasonTrusted {
		result.EventLog.Reason = eventReason
		return result
	}
	result.EventLog.Reason = ReasonTrusted

	encoded, err := v.baselines.GetBaseline(evidence.Host.BaselineID)
	if err != nil || sha256.Sum256(encoded) != evidence.Host.BaselineID {
		result.MeasurementBaseline.Reason = ReasonBaselineUnavailable
		return result
	}
	controlled, decodeErr := baseline.Decode(encoded)
	if decodeErr != nil {
		result.MeasurementBaseline.Reason = ReasonBaselineUnavailable
		return result
	}
	observed := baseline.Observed{
		MeasurementDigest: evidence.Evidence.EventLogDigest,
		SecureBoot:        evidence.Evidence.Inventory.SecureBoot,
		SetupMode:         evidence.Evidence.Inventory.SetupMode,
		DBDigest:          evidence.Evidence.Inventory.DBDigest,
		DBXDigest:         evidence.Evidence.Inventory.DBXDigest,
		FirmwareDigest:    baseline.FirmwareIdentity(evidence.Evidence.Inventory.FirmwareVendor, evidence.Evidence.Inventory.FirmwareVersion),
		MemoryMiB:         evidence.Evidence.Inventory.MemoryMiB,
		StorageGiB:        evidence.Evidence.Inventory.Storage.CapacityGiB,
		BlockDevices:      evidence.Evidence.Inventory.Storage.BlockDeviceCount,
	}
	comparison := baseline.Verify(controlled, observed)
	log.Printf("[PBNS-ATTEST] Baseline comparison: MeasurementMatch=%v, InventoryMatch=%v", comparison.MeasurementMatch, comparison.InventoryMatch)
	if !comparison.MeasurementMatch {
		result.MeasurementBaseline.Reason = ReasonMeasurementBaseline
		return result
	}
	if !comparison.InventoryMatch {
		result.InventoryDrift.Reason = ReasonInventoryDrift
		return result
	}
	result.MeasurementBaseline.Reason = ReasonTrusted
	result.InventoryDrift.Reason = ReasonTrusted
	_ = quote
	return result
}

func verifyQuote(evidence VerifiedEvidence) (*tpm2.AttestationData, []attest.PCR, Reason) {
	public, inner, err := decodeAKPublic(evidence.Host.AKPublic)
	if err != nil {
		log.Printf("[PBNS-ATTEST] verifyQuote: decodeAKPublic failed: %v", err)
		return nil, nil, ReasonAKProfile
	}
	if !validAKProfile(public) {
		log.Printf("[PBNS-ATTEST] verifyQuote: invalid AK profile")
		return nil, nil, ReasonAKProfile
	}
	name, err := public.Name()
	if err != nil {
		log.Printf("[PBNS-ATTEST] verifyQuote: public.Name() failed: %v", err)
		return nil, nil, ReasonAKName
	}
	encodedName, err := name.Digest.Encode()
	if err != nil || !bytes.Equal(encodedName, evidence.Host.AKName) || !bytes.Equal(encodedName, evidence.Evidence.AKName) {
		log.Printf("[PBNS-ATTEST] verifyQuote: AKName mismatch: encName=%x hostName=%x evidName=%x", encodedName[:8], evidence.Host.AKName[:8], evidence.Evidence.AKName[:8])
		return nil, nil, ReasonAKName
	}
	if !canonicalQuoteEncoding(evidence.Evidence.Quote) {
		log.Printf("[PBNS-ATTEST] verifyQuote: non-canonical quote encoding")
		return nil, nil, ReasonQuoteMalformed
	}
	attestation, err := tpm2.DecodeAttestationData(evidence.Evidence.Quote)
	if err != nil {
		log.Printf("[PBNS-ATTEST] verifyQuote: DecodeAttestationData failed: %v", err)
		return nil, nil, ReasonQuoteMalformed
	}
	if attestation.Magic != tpmGeneratedMagic || attestation.AttestedQuoteInfo == nil {
		log.Printf("[PBNS-ATTEST] verifyQuote: invalid magic (%x) or nil AttestedQuoteInfo", attestation.Magic)
		return nil, nil, ReasonQuoteType
	}
	if attestation.Type != tpm2.TagAttestQuote {
		log.Printf("[PBNS-ATTEST] verifyQuote: invalid type (%x)", attestation.Type)
		return nil, nil, ReasonQuoteType
	}
	expectedQualifying := qualifyingData(evidence.Challenge.Context.RequestID, evidence.Challenge.VerifierNonce, evidence.Evidence.ReportDigest, evidence.Evidence.SelectionDigest, evidence.Evidence.EventLogDigest)
	if !bytes.Equal(attestation.ExtraData, expectedQualifying) {
		log.Printf("[PBNS-ATTEST] verifyQuote: qualifyingData mismatch (got %x, want %x)", attestation.ExtraData[:8], expectedQualifying[:8])
		return nil, nil, ReasonQualifyingData
	}
	if !quoteSelectionMatches(attestation.AttestedQuoteInfo.PCRSelection, evidence.Challenge.Selection) {
		log.Printf("[PBNS-ATTEST] verifyQuote: quoteSelectionMatches failed")
		return nil, nil, ReasonPCRSelection
	}
	pcrs, values, ok := selectedPCRs(evidence.Evidence.PCRValues, evidence.Challenge.Selection)
	if !ok {
		log.Printf("[PBNS-ATTEST] verifyQuote: selectedPCRs failed")
		return nil, nil, ReasonPCRSelection
	}
	digest := sha256.Sum256(values)
	if !bytes.Equal(attestation.AttestedQuoteInfo.PCRDigest, digest[:]) {
		log.Printf("[PBNS-ATTEST] verifyQuote: PCRDigest mismatch")
		return nil, nil, ReasonPCRDigest
	}
	if !canonicalSignatureEncoding(evidence.Evidence.QuoteSignature) {
		log.Printf("[PBNS-ATTEST] verifyQuote: non-canonical quote signature encoding")
		return nil, nil, ReasonQuoteSignature
	}
	ak, err := attest.ParseAKPublic(inner)
	if err != nil {
		log.Printf("[PBNS-ATTEST] verifyQuote: ParseAKPublic failed: %v", err)
		return nil, nil, ReasonIdentityAssociation
	}
	if err := ak.Verify(attest.Quote{Quote: evidence.Evidence.Quote, Signature: evidence.Evidence.QuoteSignature}, pcrs, expectedQualifying); err != nil {
		log.Printf("[PBNS-ATTEST] verifyQuote: ak.Verify failed: %v", err)
		return nil, nil, ReasonQuoteSignature
	}
	return attestation, pcrs, ReasonTrusted
}

func canonicalQuoteEncoding(encoded []byte) bool {
	value, err := modern.Unmarshal[modern.TPMSAttest](encoded)
	return err == nil && bytes.Equal(modern.Marshal(*value), encoded)
}

func canonicalSignatureEncoding(encoded []byte) bool {
	value, err := modern.Unmarshal[modern.TPMTSignature](encoded)
	return err == nil && bytes.Equal(modern.Marshal(*value), encoded)
}

// decodeAKPublic accepts a complete canonical TPMT_PUBLIC or TPM2B_PUBLIC.
// Modern go-tpm performs all TPM structure decoding; full Marshal equality
// rejects trailing data and alternate/non-canonical wire representations.
func decodeAKPublic(encoded []byte) (tpm2.Public, []byte, error) {
	if modernPublic, err := modern.Unmarshal[modern.TPMTPublic](encoded); err == nil && bytes.Equal(modern.Marshal(*modernPublic), encoded) {
		inner := modern.Marshal(*modernPublic)
		legacy, legacyErr := tpm2.DecodePublic(inner)
		return legacy, inner, legacyErr
	}
	if wrapped, err := modern.Unmarshal[modern.TPM2BPublic](encoded); err == nil && bytes.Equal(modern.Marshal(*wrapped), encoded) {
		contents, contentsErr := wrapped.Contents()
		if contentsErr != nil {
			return tpm2.Public{}, nil, contentsErr
		}
		inner := modern.Marshal(*contents)
		legacy, legacyErr := tpm2.DecodePublic(inner)
		return legacy, inner, legacyErr
	}
	return tpm2.Public{}, nil, ErrInvalid
}

// This is the exact restricted ECC attestation-key profile enforced at TPM
// enrollment; quote verification must not accept a different signing key.
func validAKProfile(public tpm2.Public) bool {
	parameters := public.ECCParameters
	return public.Type == tpm2.AlgECC && public.NameAlg == tpm2.AlgSHA256 &&
		public.Attributes == tpm2.FlagSignerDefault && len(public.AuthPolicy) == 0 &&
		parameters != nil && parameters.Symmetric == nil && parameters.KDF == nil &&
		parameters.CurveID == tpm2.CurveNISTP256 && parameters.Sign != nil &&
		parameters.Sign.Alg == tpm2.AlgECDSA && parameters.Sign.Hash == tpm2.AlgSHA256 &&
		len(parameters.Point.XRaw) == 32 && len(parameters.Point.YRaw) == 32
}

func quoteSelectionMatches(actual tpm2.PCRSelection, expected model.PCRSelection) bool {
	// TPM2 Quote carries one TPMS_PCR_SELECTION. PBNS's accepted challenge has
	// exactly the single SHA-256 bank, so reject any broader representation.
	if len(expected) != 1 || uint64(actual.Hash) != expected[0].Algorithm || len(actual.PCRs) != len(expected[0].Indices) {
		return false
	}
	for i := range actual.PCRs {
		if uint64(actual.PCRs[i]) != expected[0].Indices[i] {
			return false
		}
	}
	return true
}

func selectedPCRs(values []PCRValue, selection model.PCRSelection) ([]attest.PCR, []byte, bool) {
	count := 0
	for _, bank := range selection {
		count += len(bank.Indices)
	}
	if len(values) != count {
		return nil, nil, false
	}
	pcrs, joined := make([]attest.PCR, 0, count), make([]byte, 0, count*sha256.Size)
	at := 0
	for _, bank := range selection {
		if bank.Algorithm != uint64(tpm2.AlgSHA256) {
			return nil, nil, false
		}
		for _, index := range bank.Indices {
			value := values[at]
			at++
			if value.Algorithm != bank.Algorithm || value.Index != index || len(value.Value) != sha256.Size {
				return nil, nil, false
			}
			pcrs = append(pcrs, attest.PCR{Index: int(index), Digest: append([]byte(nil), value.Value...), DigestAlg: crypto.SHA256})
			joined = append(joined, value.Value...)
		}
	}
	return pcrs, joined, true
}

// qualifyingData mirrors the C reference oracle: six fixed-width components, no NUL or length prefixes.
func qualifyingData(requestID [16]byte, nonce [32]byte, report, selection, log [32]byte) []byte {
	material := make([]byte, 0, 163)
	material = append(material, "PBNS-ATTESTATION-v1"...)
	material = append(material, requestID[:]...)
	material = append(material, nonce[:]...)
	material = append(material, report[:]...)
	material = append(material, selection[:]...)
	material = append(material, log[:]...)
	digest := sha256.Sum256(material)
	return digest[:]
}

var _ EvidenceConsumer = (*Verifier)(nil)
