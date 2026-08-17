// Package baselineupdate verifies externally authorized controlled baseline updates.
package baselineupdate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	controlled "pbns.local/gateway/internal/baseline"
)

const (
	ProposalDomain    = "PBNS-BASELINE-UPDATE-v1"
	approvalAADDomain = "PBNS-BASELINE-UPDATE-SIGN-v1"
	maxProposalSize   = 4*1024*1024 + 8192
	maxSignatureSize  = 4*1024*1024 + 16384
	maxLifetime       = 24 * time.Hour
)

var (
	ErrInvalid       = errors.New("invalid baseline proposal")
	ErrAuthorization = errors.New("baseline proposal is not authorized")
)

type Classification uint64

const (
	ChangeInventory Classification = 1
	ChangeSecurity  Classification = 2
)

type Proposal struct {
	Domain           string         `cbor:"1,keyasint"`
	Version          uint64         `cbor:"2,keyasint"`
	HostFingerprint  [32]byte       `cbor:"3,keyasint"`
	ParentBaselineID [32]byte       `cbor:"4,keyasint"`
	NewBaselineID    [32]byte       `cbor:"5,keyasint"`
	NewBaseline      []byte         `cbor:"6,keyasint"`
	Classification   Classification `cbor:"7,keyasint"`
	IssuedAtUnixNS   int64          `cbor:"8,keyasint"`
	ExpiresAtUnixNS  int64          `cbor:"9,keyasint"`
	AdminKeyID       [32]byte       `cbor:"10,keyasint"`
}
type Approval struct {
	proposal       Proposal
	proposalDigest [32]byte
	authorized     bool
}

var canonical cbor.EncMode
var strict cbor.DecMode

func init() {
	var err error
	canonical, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	strict, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 8, MaxMapPairs: 16, MaxArrayElements: 16, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}).DecMode()
	if err != nil {
		panic(err)
	}
}
func CreateProposal(host, parentID [32]byte, parent, updated []byte, classification Classification, issued, expires time.Time, adminKeyID [32]byte) ([]byte, error) {
	issuedNS, err := checkedUnixNanoseconds(issued)
	if err != nil {
		return nil, ErrInvalid
	}
	expiresNS, err := checkedUnixNanoseconds(expires)
	if err != nil {
		return nil, ErrInvalid
	}
	proposal := Proposal{Domain: ProposalDomain, Version: 1, HostFingerprint: host, ParentBaselineID: parentID, NewBaselineID: sha256.Sum256(updated), NewBaseline: append([]byte(nil), updated...), Classification: classification, IssuedAtUnixNS: issuedNS, ExpiresAtUnixNS: expiresNS, AdminKeyID: adminKeyID}
	if sha256.Sum256(parent) != parentID || !validProposal(proposal) || !classificationMatches(parent, updated, classification) {
		return nil, ErrInvalid
	}
	encoded, err := canonical.Marshal(proposal)
	if err != nil {
		return nil, ErrInvalid
	}
	return encoded, nil
}
func DecodeProposal(encoded []byte) (Proposal, error) {
	var p Proposal
	if len(encoded) == 0 || len(encoded) > maxProposalSize || strict.Unmarshal(encoded, &p) != nil || !validProposal(p) {
		return Proposal{}, ErrInvalid
	}
	again, err := canonical.Marshal(p)
	if err != nil || !bytes.Equal(again, encoded) {
		return Proposal{}, ErrInvalid
	}
	p.NewBaseline = append([]byte(nil), p.NewBaseline...)
	return p, nil
}
func VerifyApproval(proposalBytes, signature []byte, public *ecdsa.PublicKey, now time.Time) (Approval, error) {
	if public == nil || public.Curve == nil || public.Curve.Params().Name != "P-256" || len(signature) == 0 || len(signature) > maxSignatureSize {
		return Approval{}, ErrAuthorization
	}
	proposal, err := DecodeProposal(proposalBytes)
	if err != nil {
		return Approval{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return Approval{}, ErrAuthorization
	}
	kid := sha256.Sum256(der)
	nowNS, err := checkedUnixNanoseconds(now)
	if err != nil || subtle.ConstantTimeCompare(kid[:], proposal.AdminKeyID[:]) != 1 || !withinValidity(proposal, nowNS) {
		return Approval{}, ErrAuthorization
	}
	message := cose.NewSign1Message()
	if message.UnmarshalCBOR(signature) != nil || !canonicalApproval(signature, message, proposal.AdminKeyID) || !bytes.Equal(message.Payload, proposalBytes) {
		return Approval{}, ErrAuthorization
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, public)
	if err != nil || message.Verify(ApprovalAAD(proposal), verifier) != nil {
		return Approval{}, ErrAuthorization
	}
	return Approval{proposal: proposal, proposalDigest: sha256.Sum256(proposalBytes), authorized: true}, nil
}
func ApprovalAAD(p Proposal) []byte {
	encoded, err := canonical.Marshal([]any{approvalAADDomain, uint64(1), p.HostFingerprint[:], p.ParentBaselineID[:], p.NewBaselineID[:], uint64(p.Classification), p.IssuedAtUnixNS, p.ExpiresAtUnixNS, p.AdminKeyID[:]})
	if err != nil {
		panic(err)
	}
	return encoded
}
func (a Approval) Valid() bool {
	return a.authorized && validProposal(a.proposal) && a.proposalDigest != [32]byte{}
}

// AuthorizeParentAt binds an opaque approval to its parent and half-open validity window.
func (a Approval) AuthorizeParentAt(parent []byte, at time.Time) (int64, error) {
	if !a.Valid() || sha256.Sum256(parent) != a.proposal.ParentBaselineID || !classificationMatches(parent, a.proposal.NewBaseline, a.proposal.Classification) {
		return 0, ErrInvalid
	}
	approvedAtUnixNS, err := checkedUnixNanoseconds(at)
	if err != nil || !withinValidity(a.proposal, approvedAtUnixNS) {
		return 0, ErrAuthorization
	}
	return approvedAtUnixNS, nil
}
func (a Approval) HostFingerprint() [32]byte  { return a.proposal.HostFingerprint }
func (a Approval) ParentBaselineID() [32]byte { return a.proposal.ParentBaselineID }
func (a Approval) NewBaselineID() [32]byte    { return a.proposal.NewBaselineID }
func (a Approval) NewBaseline() []byte        { return append([]byte(nil), a.proposal.NewBaseline...) }
func (a Approval) ProposalDigest() [32]byte   { return a.proposalDigest }

func checkedUnixNanoseconds(at time.Time) (int64, error) {
	utc := at.UTC()
	candidate := utc.UnixNano()
	if utc.IsZero() || !time.Unix(0, candidate).UTC().Equal(utc) {
		return 0, ErrAuthorization
	}
	return candidate, nil
}

func withinValidity(proposal Proposal, unixNS int64) bool {
	return unixNS >= proposal.IssuedAtUnixNS && unixNS < proposal.ExpiresAtUnixNS
}

func validProposal(p Proposal) bool {
	return p.Domain == ProposalDomain && p.Version == 1 && p.HostFingerprint != [32]byte{} && p.ParentBaselineID != [32]byte{} && p.NewBaselineID != [32]byte{} && p.NewBaselineID != p.ParentBaselineID && p.AdminKeyID != [32]byte{} && len(p.NewBaseline) > 0 && len(p.NewBaseline) <= maxProposalSize-8192 && sha256.Sum256(p.NewBaseline) == p.NewBaselineID && (p.Classification == ChangeInventory || p.Classification == ChangeSecurity) && p.IssuedAtUnixNS > 0 && p.ExpiresAtUnixNS > p.IssuedAtUnixNS && p.ExpiresAtUnixNS-p.IssuedAtUnixNS <= maxLifetime.Nanoseconds() && func() bool { _, err := controlled.Decode(p.NewBaseline); return err == nil }()
}
func classificationMatches(parentBytes, newBytes []byte, c Classification) bool {
	parent, err := controlled.Decode(parentBytes)
	if err != nil {
		return false
	}
	updated, err := controlled.Decode(newBytes)
	if err != nil || bytes.Equal(parentBytes, newBytes) {
		return false
	}
	security := parent.Record.MeasurementDigest != updated.Record.MeasurementDigest || parent.Record.SecureBoot != updated.Record.SecureBoot || parent.Record.SetupMode != updated.Record.SetupMode || parent.Record.DBDigest != updated.Record.DBDigest || parent.Record.DBXDigest != updated.Record.DBXDigest || parent.Record.FirmwareDigest != updated.Record.FirmwareDigest
	inventory := parent.Record.Inventory != updated.Record.Inventory || parent.MemoryMiB != updated.MemoryMiB || parent.StorageGiB != updated.StorageGiB || parent.BlockDevices != updated.BlockDevices
	if security {
		return c == ChangeSecurity
	}
	return inventory && c == ChangeInventory
}
func canonicalApproval(encoded []byte, message *cose.Sign1Message, kid [32]byte) bool {
	if message == nil || len(message.Headers.Unprotected) != 0 || len(message.Headers.Protected) != 2 {
		return false
	}
	algorithm, err := message.Headers.Protected.Algorithm()
	if err != nil || algorithm != cose.AlgorithmES256 {
		return false
	}
	actual, ok := message.Headers.Protected[cose.HeaderLabelKeyID].([]byte)
	if !ok || len(actual) != 32 || subtle.ConstantTimeCompare(actual, kid[:]) != 1 {
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
	unprotected, err := canonical.Marshal(message.Headers.Unprotected)
	if err != nil || !bytes.Equal(unprotected, message.Headers.RawUnprotected) {
		return false
	}
	again, err := message.MarshalCBOR()
	return err == nil && bytes.Equal(again, encoded)
}
