package attestation

import (
	"crypto/sha256"
	"errors"
	"testing"

	"pbns.local/gateway/internal/baseline"
)

type candidateSink struct {
	calls int
	value BaselineCandidate
}

func (sink *candidateSink) WriteCandidate(value BaselineCandidate) error {
	sink.calls++
	sink.value = value
	return nil
}

func TestCandidateRequiresTrustedQuoteAndEventLog(t *testing.T) {
	fixture := loadSwtpmFixture(t)
	prior, err := baseline.Decode(fixture.Baseline)
	if err != nil {
		t.Fatal(err)
	}
	prior.Record.MeasurementDigest[0] ^= 1
	old, err := baseline.Encode(prior)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Host.BaselineID = sha256.Sum256(old)
	verifier, err := NewVerifier(baselineMap{fixture.Host.BaselineID: old})
	if err != nil {
		t.Fatal(err)
	}
	sink := &candidateSink{}
	wrapped := NewBaselineCandidateVerifier(verifier, sink)
	input := fixtureInput(fixture)
	input.Digest[0] = 1
	err = wrapped.Verify(input)
	if !errors.Is(err, ErrVerification) || sink.calls != 1 {
		t.Fatalf("expected one read-only candidate after trusted preflight: %v calls=%d verdict=%#v", err, sink.calls, verifier.Assess(fixtureInput(fixture)))
	}
	if sink.value.HostFingerprint != fixture.Host.Fingerprint || sink.value.ParentBaselineID != fixture.Host.BaselineID || sink.value.EvidenceDigest == ([32]byte{}) {
		t.Fatalf("candidate identity binding: %#v", sink.value)
	}
	candidate, err := baseline.Decode(sink.value.Encoded)
	if err != nil || candidate.Record.MeasurementDigest != fixture.Evidence.EventLogDigest {
		t.Fatalf("candidate baseline: %v %#v", err, candidate)
	}
}

func TestCandidateRejectsUntrustedQuoteAndEventLog(t *testing.T) {
	fixture := loadSwtpmFixture(t)
	verifier := fixtureVerifier(t, fixture)
	for name, mutate := range map[string]func(*swtpmFixture){
		"quote":     func(value *swtpmFixture) { value.Evidence.Quote[0] ^= 1 },
		"event-log": func(value *swtpmFixture) { value.Evidence.EventLog = nil },
	} {
		t.Run(name, func(t *testing.T) {
			value := cloneFixture(fixture)
			mutate(&value)
			sink := &candidateSink{}
			input := fixtureInput(value)
			input.Digest[0] = 1
			if err := NewBaselineCandidateVerifier(verifier, sink).Verify(input); !errors.Is(err, ErrVerification) || sink.calls != 0 {
				t.Fatalf("untrusted %s candidate: %v calls=%d verdict=%#v", name, err, sink.calls, verifier.Assess(fixtureInput(value)))
			}
		})
	}
}
