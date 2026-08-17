package attestation

import (
	"errors"

	"pbns.local/gateway/internal/baseline"
)

// BaselineCandidate is an authenticated observation for a separately authorized update.
type BaselineCandidate struct {
	Encoded          []byte
	HostFingerprint  [32]byte
	ParentBaselineID [32]byte
	EvidenceDigest   [32]byte
}

// BaselineCandidateSink receives only a canonical candidate; it cannot mutate a verifier or store.
type BaselineCandidateSink interface {
	WriteCandidate(BaselineCandidate) error
}

type baselineCandidateVerifier struct {
	root *Verifier
	sink BaselineCandidateSink
}

func NewBaselineCandidateVerifier(root *Verifier, sink BaselineCandidateSink) EvidenceConsumer {
	if root == nil || sink == nil {
		return nil
	}
	return &baselineCandidateVerifier{root: root, sink: sink}
}

func (candidate *baselineCandidateVerifier) Verify(evidence VerifiedEvidence) error {
	if candidate == nil || candidate.root == nil || candidate.sink == nil {
		return ErrVerification
	}
	verdict := candidate.root.Assess(evidence)
	if verdict.Trusted() {
		return nil
	}
	if !verdict.Quote.Trusted() || !verdict.EventLog.Trusted() || !verdict.Capability.Trusted() ||
		(verdict.MeasurementBaseline.Reason != ReasonMeasurementBaseline && verdict.InventoryDrift.Reason != ReasonInventoryDrift) {
		return errors.Join(ErrVerification, &VerificationError{Verdict: verdict})
	}
	parent, err := candidate.root.baselines.GetBaseline(evidence.Host.BaselineID)
	if err != nil {
		return errors.Join(ErrVerification, &VerificationError{Verdict: verdict})
	}
	controlled, err := baseline.Decode(parent)
	if err != nil {
		return errors.Join(ErrVerification, &VerificationError{Verdict: verdict})
	}
	controlled.Record.MeasurementDigest = evidence.Evidence.EventLogDigest
	controlled.Record.SecureBoot = evidence.Evidence.Inventory.SecureBoot
	controlled.Record.SetupMode = evidence.Evidence.Inventory.SetupMode
	controlled.Record.DBDigest = evidence.Evidence.Inventory.DBDigest
	controlled.Record.DBXDigest = evidence.Evidence.Inventory.DBXDigest
	controlled.Record.FirmwareDigest = baseline.FirmwareIdentity(evidence.Evidence.Inventory.FirmwareVendor, evidence.Evidence.Inventory.FirmwareVersion)
	controlled.MemoryMiB = evidence.Evidence.Inventory.MemoryMiB
	controlled.StorageGiB = evidence.Evidence.Inventory.Storage.CapacityGiB
	controlled.BlockDevices = evidence.Evidence.Inventory.Storage.BlockDeviceCount
	encoded, err := baseline.Encode(controlled)
	if err != nil {
		return errors.Join(ErrVerification, &VerificationError{Verdict: verdict})
	}
	value := BaselineCandidate{Encoded: encoded, HostFingerprint: evidence.Host.Fingerprint, ParentBaselineID: evidence.Host.BaselineID, EvidenceDigest: evidence.Digest}
	if err := candidate.sink.WriteCandidate(value); err != nil {
		return errors.Join(ErrVerification, err)
	}
	return errors.Join(ErrVerification, &VerificationError{Verdict: verdict})
}

var _ EvidenceConsumer = (*baselineCandidateVerifier)(nil)
