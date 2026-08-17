package model

import (
	"errors"
	"strings"
	"testing"
)

func testDigest(value byte) [32]byte {
	var digest [32]byte
	digest[0] = value
	return digest
}

func validSoftwareHost() HostRecord {
	return HostRecord{
		Fingerprint:     testDigest(1),
		IdentityCOSEKey: []byte{0xa1, 0x01, 0x02},
		Assurance:       AssuranceSoftware,
		BaselineID:      testDigest(2),
		EnrolledAtUnix:  1_900_000_000,
	}
}

func TestSoftwareHostRecordValidation(t *testing.T) {
	host := validSoftwareHost()
	if err := host.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*HostRecord){
		"zero fingerprint": func(record *HostRecord) { record.Fingerprint = [32]byte{} },
		"missing identity": func(record *HostRecord) { record.IdentityCOSEKey = nil },
		"zero baseline":    func(record *HostRecord) { record.BaselineID = [32]byte{} },
		"zero enrolled at": func(record *HostRecord) { record.EnrolledAtUnix = 0 },
		"invalid assurance": func(record *HostRecord) {
			record.Assurance = Assurance("full")
		},
		"software with AK": func(record *HostRecord) { record.AKPublic = []byte{1} },
		"software with EK": func(record *HostRecord) { record.EKPublic = []byte{1} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := host.Clone()
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestTPMAssuranceRequiresMatchingEvidence(t *testing.T) {
	unverified := validSoftwareHost()
	unverified.Assurance = AssuranceTPMUnverified
	unverified.AKPublic = []byte{1}
	unverified.AKName = []byte{2}
	unverified.EKPublic = []byte{3}
	if err := unverified.Validate(); err != nil {
		t.Fatal(err)
	}
	unverifiedWithChain := unverified.Clone()
	unverifiedWithChain.EKChainDigest = testDigest(4)
	if err := unverifiedWithChain.Validate(); err != nil {
		t.Fatalf("unverified chain digest should remain reportable: %v", err)
	}
	verified := unverified.Clone()
	verified.Assurance = AssuranceTPMVerified
	if err := verified.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("verified host without chain digest got %v", err)
	}
	verified.EKChainDigest = testDigest(3)
	if err := verified.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCloneOwnsVariableLengthFields(t *testing.T) {
	host := validSoftwareHost()
	clone := host.Clone()
	clone.IdentityCOSEKey[0] ^= 0xff
	if host.IdentityCOSEKey[0] == clone.IdentityCOSEKey[0] {
		t.Fatal("clone aliases identity key")
	}
}

func TestHostRenderingDoesNotExposeKeyMaterial(t *testing.T) {
	host := validSoftwareHost()
	host.IdentityCOSEKey = []byte("private-looking-test-material")
	rendered := host.String()
	if strings.Contains(rendered, string(host.IdentityCOSEKey)) {
		t.Fatalf("rendered host exposed key bytes: %q", rendered)
	}
	if !strings.Contains(rendered, string(AssuranceSoftware)) {
		t.Fatalf("rendered host omitted assurance: %q", rendered)
	}
}
