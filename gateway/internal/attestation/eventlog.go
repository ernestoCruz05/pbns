package attestation

import (
	"bytes"
	"crypto/sha256"
	"log"

	"github.com/google/go-attestation/attest"
)

func eventAlgorithmsSupported(algorithms []attest.HashAlg) bool {
	selected := false
	for _, algorithm := range algorithms {
		switch algorithm {
		case attest.HashSHA1, attest.HashSHA384, attest.HashSHA512:
		case attest.HashSHA256:
			selected = true
		default:
			return false
		}
	}
	return selected
}

// replayEventLog delegates TCG2 decoding and PCR replay to go-attestation. Only
// the selected SHA-256 bank contributes to the verifier decision; recognized
// extra banks advertised by firmware remain unselected.
func replayEventLog(encoded []byte, pcrs []attest.PCR) Reason {
	log.Printf("[PBNS-EVENTLOG] Parsing event log (%d bytes, %d PCRs to replay)", len(encoded), len(pcrs))
	for _, p := range pcrs {
		log.Printf("[PBNS-EVENTLOG] Expected PCR %d (alg=%v): %x", p.Index, p.DigestAlg, p.Digest)
	}
	eventLog, err := attest.ParseEventLog(encoded)
	if err != nil {
		log.Printf("[PBNS-EVENTLOG] ParseEventLog error: %v", err)
		return ReasonEventLogMalformed
	}
	events256 := eventLog.Events(attest.HashSHA256)
	log.Printf("[PBNS-EVENTLOG] Event log has %d SHA-256 events, algs=%v", len(events256), eventLog.Algs)
	if len(eventLog.Algs) == 0 {
		log.Printf("[PBNS-EVENTLOG] No algorithms found in event log")
		return ReasonEventLogMalformed
	}
	if !eventAlgorithmsSupported(eventLog.Algs) {
		log.Printf("[PBNS-EVENTLOG] Unsupported algorithms in event log: %v", eventLog.Algs)
		return ReasonUnsupportedEventAlgorithm
	}

	// Manual step-by-step replay for diagnostic insight
	replayedPCRs := make(map[int][32]byte)
	eventCountPerPCR := make(map[int]int)
	for i, ev := range events256 {
		eventCountPerPCR[ev.Index]++
		cur := replayedPCRs[ev.Index]
		h := sha256.New()
		h.Write(cur[:])
		h.Write(ev.Digest)
		copy(cur[:], h.Sum(nil))
		replayedPCRs[ev.Index] = cur
		if i < 5 || ev.Index == 0 || ev.Index == 7 {
			if eventCountPerPCR[ev.Index] <= 3 {
				log.Printf("[PBNS-EVENTLOG] Event[%d]: PCR=%d Type=0x%x Digest=%x DataLen=%d", i, ev.Index, ev.Type, ev.Digest[:min(len(ev.Digest), 8)], len(ev.Data))
			}
		}
	}
	for _, p := range pcrs {
		replayed := replayedPCRs[p.Index]
		log.Printf("[PBNS-EVENTLOG] PCR %d: %d events replayed -> Got %x vs Expected %x (Match=%v)",
			p.Index, eventCountPerPCR[p.Index], replayed[:], p.Digest, bytes.Equal(replayed[:], p.Digest))
	}

	events, err := eventLog.Verify(pcrs)
	if err != nil {
		log.Printf("[PBNS-EVENTLOG] eventLog.Verify failed: %v", err)
		return ReasonEventLogReplay
	}
	log.Printf("[PBNS-EVENTLOG] eventLog.Verify succeeded with %d events", len(events))
	replayed := make(map[int]bool, len(pcrs))
	separator := false
	for _, event := range events {
		if len(event.Digest) != 0 {
			replayed[event.Index] = true
		}
		if event.Type == attest.EventType(4) && len(event.Data) == 4 && event.Data[0] == 0 && event.Data[1] == 0 && event.Data[2] == 0 && event.Data[3] == 0 {
			separator = true
		}
	}
	if !separator {
		log.Printf("[PBNS-EVENTLOG] Separator event (EventType 4, 0x00000000) not found in events (events count=%d)", len(events))
		return ReasonEventLogReplay
	}
	for _, pcr := range pcrs {
		if !replayed[pcr.Index] {
			log.Printf("[PBNS-EVENTLOG] Selected PCR %d has no replayed events", pcr.Index)
			return ReasonEventLogReplay
		}
	}
	log.Printf("[PBNS-EVENTLOG] Event log replay passed completely!")
	return ReasonTrusted
}
