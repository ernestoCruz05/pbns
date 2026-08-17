package attestation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-attestation/attest"
)

func TestEventAlgorithmPolicyAllowsKnownExtraBanksWithSHA256Selection(t *testing.T) {
	if !eventAlgorithmsSupported([]attest.HashAlg{attest.HashSHA1, attest.HashSHA256, attest.HashSHA384, attest.HashSHA512}) {
		t.Fatal("rejected QEMU firmware event-log banks")
	}
	if eventAlgorithmsSupported([]attest.HashAlg{attest.HashSHA1, attest.HashSHA384, attest.HashSHA512}) {
		t.Fatal("accepted event log without selected SHA-256 bank")
	}
	if eventAlgorithmsSupported([]attest.HashAlg{attest.HashSHA256, attest.HashAlg(0x12)}) {
		t.Fatal("accepted unsupported event-log bank")
	}
}

func TestEventLogReplayAndChangedEvent(t *testing.T) {
	f := loadSwtpmFixture(t)
	pcrs, _, ok := selectedPCRs(f.Evidence.PCRValues, f.Challenge.Selection)
	if !ok {
		t.Fatal("fixture PCRs invalid")
	}
	if got := replayEventLog(f.Evidence.EventLog, pcrs); got != ReasonTrusted {
		t.Fatalf("valid replay = %q", got)
	}
	changed := append([]byte(nil), f.Evidence.EventLog...)
	// Change the final PCR7 event's submitted SHA-256 digest, not its
	// unauthenticated event data (generic EV_ACTION data is not self-hashed).
	changed[len(changed)-62] ^= 1
	if got := replayEventLog(changed, pcrs); got != ReasonEventLogReplay {
		t.Fatalf("changed event = %q", got)
	}
}

func TestInvalidCorpus(t *testing.T) {
	f := loadSwtpmFixture(t)
	pcrs, _, ok := selectedPCRs(f.Evidence.PCRValues, f.Challenge.Selection)
	if !ok {
		t.Fatal("fixture PCRs invalid")
	}
	cases := map[string]Reason{
		"not-an-event-log.bin":      ReasonEventLogMalformed,
		"truncated-final-event.bin": ReasonEventLogMalformed,
		"unsupported-algorithm.bin": ReasonUnsupportedEventAlgorithm,
		"missing-separator.bin":     ReasonEventLogReplay,
		"missing-pcr4-event.bin":    ReasonEventLogReplay,
		"missing-pcr7-event.bin":    ReasonEventLogReplay,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", "attestation", "invalid", name))
			if err != nil {
				t.Fatal(err)
			}
			if got := replayEventLog(encoded, pcrs); got != want {
				t.Fatalf("reason=%q want %q", got, want)
			}
		})
	}
}
