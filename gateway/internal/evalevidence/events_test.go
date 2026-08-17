package evalevidence

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"pbns.local/gateway/internal/recovery"
)

func privateEventPath(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "events")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "events.jsonl")
}

func validEvent() recovery.EvaluationEvent {
	return recovery.EvaluationEvent{
		Connection: 1,
		Operation:  "artifact",
		Frame:      "DATA",
		Sequence:   0,
		Fault:      recovery.EvaluationFaultArtifactDigestMismatch,
		Outcome:    "injected",
	}
}

func TestOpenRequiresPrivateNewRegularPath(t *testing.T) {
	path := privateEventPath(t)
	sink, err := Open(path, "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("event mode = %v, want regular 0600", info.Mode())
	}

	for name, setup := range map[string]func(string){
		"existing": func(path string) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(path string) {
			if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := privateEventPath(t)
			setup(candidate)
			if sink, err := Open(candidate, "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch); err == nil || sink != nil {
				t.Fatalf("Open(%q) = %v, %v; want rejection", candidate, sink, err)
			}
		})
	}

	unsafeParent := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(unsafeParent, "events.jsonl"), "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch); err == nil {
		t.Fatal("Open accepted non-0700 parent")
	}

	parentLink := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(filepath.Dir(path), parentLink); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(parentLink, "events.jsonl"), "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch); err == nil {
		t.Fatal("Open accepted symlink parent")
	}
}

func TestOpenParentSyncFailureReturnsNoSinkAndRemovesEvent(t *testing.T) {
	path := privateEventPath(t)
	sink, err := open(path, "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch, func(int) error {
		return errors.New("parent sync failed")
	})
	if err == nil || sink != nil {
		t.Fatalf("Open with parent sync failure = %v, %v; want nil sink and error", sink, err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("event left behind after parent sync failure: %v", err)
	}
}

func TestOpenRejectsNonCanonicalAndSymlinkDotDotPaths(t *testing.T) {
	path := privateEventPath(t)
	parent := filepath.Dir(path)
	for _, candidate := range []string{parent + "/./dot.jsonl", parent + "/../dotdot.jsonl"} {
		sink, err := Open(candidate, "case-1", recovery.EvaluationFaultArtifactDigestMismatch)
		if sink != nil {
			_ = sink.Close()
		}
		if err == nil {
			t.Fatalf("Open accepted non-canonical path %q", candidate)
		}
	}

	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(filepath.Join(outside, "deeper"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "redirect")
	if err := os.Symlink(filepath.Join(outside, "deeper"), link); err != nil {
		t.Fatal(err)
	}
	candidate := link + "/../escaped.jsonl"
	sink, err := Open(candidate, "case-1", recovery.EvaluationFaultArtifactDigestMismatch)
	if sink != nil {
		_ = sink.Close()
	}
	if err == nil {
		t.Fatalf("Open accepted symlink/.. path %q", candidate)
	}
	if _, err := os.Lstat(filepath.Join(outside, "escaped.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe event output exists: %v", err)
	}
}

func TestOpenValidatesClosedCaseAndFault(t *testing.T) {
	for _, caseName := range []string{"", "Upper", "contains_space", "-leading", "slash/name", strings.Repeat("a", 65)} {
		if sink, err := Open(privateEventPath(t), caseName, recovery.EvaluationFaultArtifactDigestMismatch); err == nil || sink != nil {
			t.Fatalf("Open accepted case %q", caseName)
		}
	}
	for _, fault := range []recovery.EvaluationFault{"", "unknown", recovery.EvaluationFaultArtifactDigestMismatch + "," + recovery.EvaluationFaultChunkSequence} {
		if sink, err := Open(privateEventPath(t), "digest-mismatch", fault); err == nil || sink != nil {
			t.Fatalf("Open accepted fault %q", fault)
		}
	}
}

func TestRecordSyncsOneCanonicalClosedEvent(t *testing.T) {
	path := privateEventPath(t)
	sink, err := Open(path, "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.Record(validEvent()); err != nil {
		t.Fatal(err)
	}

	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("read separate descriptor: read=%v close=%v", err, closeErr)
	}
	if !strings.HasSuffix(string(contents), "\n") || strings.Count(string(contents), "\n") != 1 {
		t.Fatalf("event stream is not one complete JSONL line: %q", contents)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(strings.TrimSuffix(string(contents), "\n")), &object); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	wantKeys := []string{"case", "connection", "fault", "frame", "next", "operation", "outcome", "schema", "sequence", "window"}
	if !reflect.DeepEqual(keys, wantKeys) {
		t.Fatalf("serialized keys = %v, want %v", keys, wantKeys)
	}
	if string(contents) != "{\"schema\":\"pbns-recovery-evaluation-v1\",\"case\":\"digest-mismatch\",\"connection\":1,\"operation\":\"artifact\",\"frame\":\"DATA\",\"sequence\":0,\"next\":0,\"window\":0,\"fault\":\"artifact-digest-mismatch\",\"outcome\":\"injected\"}\n" {
		t.Fatalf("canonical event = %q", contents)
	}
}

func TestRecordAcceptsEveryClosedEventShape(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		fault recovery.EvaluationFault
		event recovery.EvaluationEvent
	}{
		{"manifest", recovery.EvaluationFaultArtifactDigestMismatch, recovery.EvaluationEvent{Connection: 1, Operation: "manifest", Frame: "RESPONSE", Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent"}},
		{"data", recovery.EvaluationFaultArtifactDigestMismatch, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "DATA", Sequence: 1, Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent"}},
		{"ack", recovery.EvaluationFaultChunkSequence, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "ACK", Next: recovery.ACKWindow, Window: recovery.ACKWindow, Fault: recovery.EvaluationFaultChunkSequence, Outcome: "accepted"}},
		{"complete", recovery.EvaluationFaultChunkSequence, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "COMPLETE", Sequence: 3, Fault: recovery.EvaluationFaultChunkSequence, Outcome: "sent"}},
		{"chunk-injected", recovery.EvaluationFaultChunkSequence, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "DATA", Sequence: 2, Fault: recovery.EvaluationFaultChunkSequence, Outcome: "injected"}},
		{"interruption", recovery.EvaluationFaultInterruptAfterData7, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "DATA", Sequence: 7, Fault: recovery.EvaluationFaultInterruptAfterData7, Outcome: "interrupt-ready"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sink, err := Open(privateEventPath(t), "case-1", testCase.fault)
			if err != nil {
				t.Fatal(err)
			}
			if err := sink.Record(testCase.event); err != nil {
				t.Fatal(err)
			}
			if err := sink.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRecordRejectsInvalidClosedEventsAndClosedSink(t *testing.T) {
	invalid := []recovery.EvaluationEvent{
		{},
		{Connection: 1, Operation: "other", Frame: "DATA", Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent"},
		{Connection: 1, Operation: "artifact", Frame: "other", Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent"},
		{Connection: 1, Operation: "artifact", Frame: "DATA", Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "other"},
		{Connection: 1, Operation: "artifact", Frame: "DATA", Fault: recovery.EvaluationFaultChunkSequence, Outcome: "sent"},
		{Connection: 1, Operation: "manifest", Frame: "RESPONSE", Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "injected"},
		{Connection: 1, Operation: "artifact", Frame: "ACK", Next: 1, Window: 7, Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "accepted"},
		{Connection: 1, Operation: "artifact", Frame: "DATA", Sequence: 1, Next: 1, Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent"},
	}
	for _, event := range invalid {
		path := privateEventPath(t)
		sink, err := Open(path, "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch)
		if err != nil {
			t.Fatal(err)
		}
		if err := sink.Record(event); err == nil {
			t.Fatalf("Record(%#v) succeeded", event)
		}
		if err := sink.Close(); err != nil {
			t.Fatal(err)
		}
	}

	sink, err := Open(privateEventPath(t), "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	if err := sink.Record(validEvent()); err == nil {
		t.Fatal("Record after Close succeeded")
	}
}

func TestRecordRejectsImpossibleFaultEvents(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		fault recovery.EvaluationFault
		event recovery.EvaluationEvent
	}{
		{"digest-data-zero-sent", recovery.EvaluationFaultArtifactDigestMismatch, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "DATA", Sequence: 0, Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent"}},
		{"chunk-data-one-sent", recovery.EvaluationFaultChunkSequence, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "DATA", Sequence: 1, Fault: recovery.EvaluationFaultChunkSequence, Outcome: "sent"}},
		{"ack-next-not-window-multiple", recovery.EvaluationFaultArtifactDigestMismatch, recovery.EvaluationEvent{Connection: 1, Operation: "artifact", Frame: "ACK", Next: recovery.ACKWindow + 1, Window: recovery.ACKWindow, Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "accepted"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			sink, err := Open(privateEventPath(t), "case-1", testCase.fault)
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			if err := sink.Record(testCase.event); err == nil {
				t.Fatalf("Record(%#v) accepted impossible event", testCase.event)
			}
		})
	}
}

func TestSerializedRecordCannotContainSecretCapableFields(t *testing.T) {
	typeOfRecord := reflect.TypeOf(eventRecord{})
	want := []string{"Schema", "Case", "Connection", "Operation", "Frame", "Sequence", "Next", "Window", "Fault", "Outcome"}
	if typeOfRecord.NumField() != len(want) {
		t.Fatalf("record fields = %d, want %d", typeOfRecord.NumField(), len(want))
	}
	serialized := make([]string, 0, len(want))
	for index, name := range want {
		field := typeOfRecord.Field(index)
		if field.Name != name || field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Array {
			t.Fatalf("record field %d = %s %s", index, field.Name, field.Type)
		}
		serialized = append(serialized, strings.Split(field.Tag.Get("json"), ",")[0])
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{"payload", "id", "nonce", "digest", "key", "host", "transcript", "policy", "artifact"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("secret-capable record field %q", field.Name)
			}
		}
	}
	if !reflect.DeepEqual(serialized, []string{"schema", "case", "connection", "operation", "frame", "sequence", "next", "window", "fault", "outcome"}) {
		t.Fatalf("serialized record keys = %v", serialized)
	}
}

func TestRecordFailureClosesSinkToFurtherRecords(t *testing.T) {
	sink, err := Open(privateEventPath(t), "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Record(validEvent()); err == nil {
		t.Fatal("Record after underlying close succeeded")
	}
	if err := sink.Record(validEvent()); err == nil {
		t.Fatal("Record succeeded after prior write failure")
	}
	if err := sink.Close(); err == nil {
		t.Fatal("Close after underlying close succeeded")
	}
}

func TestRecordIsSafeForConcurrentWriters(t *testing.T) {
	path := privateEventPath(t)
	sink, err := Open(path, "digest-mismatch", recovery.EvaluationFaultArtifactDigestMismatch)
	if err != nil {
		t.Fatal(err)
	}
	const records = 24
	errors := make(chan error, records)
	for sequence := uint32(1); sequence <= records; sequence++ {
		go func(sequence uint32) {
			errors <- sink.Record(recovery.EvaluationEvent{
				Connection: uint64(sequence), Operation: "artifact", Frame: "DATA",
				Sequence: sequence, Fault: recovery.EvaluationFaultArtifactDigestMismatch, Outcome: "sent",
			})
		}(sequence)
	}
	for range records {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines := len(splitJSONLLines(t, contents)); lines != records {
		t.Fatalf("JSONL records = %d, want %d", lines, records)
	}
}

type failingEventFile struct {
	writeN   int
	writeErr error
	syncErr  error
	writes   int
	syncs    int
}

func (file *failingEventFile) Write(contents []byte) (int, error) {
	file.writes++
	if file.writeN != 0 {
		return file.writeN, file.writeErr
	}
	return len(contents), file.writeErr
}

func (file *failingEventFile) Sync() error {
	file.syncs++
	return file.syncErr
}

func (file *failingEventFile) Close() error { return nil }

func TestRecordPartialWriteAndSyncFailureAreSticky(t *testing.T) {
	for _, testCase := range []struct {
		name string
		file failingEventFile
	}{
		{"partial-write", failingEventFile{writeN: 1}},
		{"sync-failure", failingEventFile{syncErr: errors.New("sync failed")}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			file := testCase.file
			sink := &Sink{file: &file, caseName: "case-1", fault: recovery.EvaluationFaultArtifactDigestMismatch}
			if err := sink.Record(validEvent()); err == nil {
				t.Fatal("first failing Record succeeded")
			}
			writes, syncs := file.writes, file.syncs
			if err := sink.Record(validEvent()); err == nil {
				t.Fatal("Record succeeded after sticky failure")
			}
			if file.writes != writes || file.syncs != syncs {
				t.Fatalf("sticky failure performed I/O: writes %d->%d syncs %d->%d", writes, file.writes, syncs, file.syncs)
			}
		})
	}
}

func splitJSONLLines(t *testing.T, contents []byte) [][]byte {
	t.Helper()
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		t.Fatalf("incomplete JSONL stream %q", contents)
	}
	lines := make([][]byte, 0)
	start := 0
	for index, byte := range contents {
		if byte == '\n' {
			lines = append(lines, contents[start:index])
			start = index + 1
		}
	}
	return lines
}
