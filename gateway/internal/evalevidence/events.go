// Package evalevidence writes the closed, non-secret recovery evaluation event stream.
package evalevidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"pbns.local/gateway/internal/recovery"
)

const eventSchema = "pbns-recovery-evaluation-v1"

var (
	errInvalid  = errors.New("invalid recovery evaluation evidence")
	errClosed   = errors.New("recovery evaluation evidence sink is closed")
	errFailed   = errors.New("recovery evaluation evidence sink failed")
	casePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// Sink synchronizes complete, validated evaluation events to one new JSONL file.
type Sink struct {
	mutex    sync.Mutex
	file     eventFile
	caseName string
	fault    recovery.EvaluationFault
	closed   bool
	failed   bool
	failure  error
}

type eventFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// eventRecord is deliberately private and limited to the fixed public JSONL schema.
type eventRecord struct {
	Schema     string                   `json:"schema"`
	Case       string                   `json:"case"`
	Connection uint64                   `json:"connection"`
	Operation  string                   `json:"operation"`
	Frame      string                   `json:"frame"`
	Sequence   uint32                   `json:"sequence"`
	Next       uint32                   `json:"next"`
	Window     uint32                   `json:"window"`
	Fault      recovery.EvaluationFault `json:"fault"`
	Outcome    string                   `json:"outcome"`
}

// Open creates a new private event stream under an owned, private parent directory.
func Open(path, caseName string, fault recovery.EvaluationFault) (*Sink, error) {
	return open(path, caseName, fault, unix.Fsync)
}

// open keeps the parent synchronization dependency explicit for the failure
// path test. Production always supplies unix.Fsync through Open.
func open(path, caseName string, fault recovery.EvaluationFault, syncParent func(int) error) (*Sink, error) {
	if path == "" || !casePattern.MatchString(caseName) || !validFault(fault) || syncParent == nil {
		return nil, errInvalid
	}
	file, err := openNewEventFile(path, syncParent)
	if err != nil {
		return nil, err
	}
	return &Sink{file: file, caseName: caseName, fault: fault}, nil
}

func openNewEventFile(path string, syncParent func(int) error) (*os.File, error) {
	parent, base, err := eventPathParts(path)
	if err != nil {
		return nil, err
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open evaluation event parent: %w", err)
	}
	defer unix.Close(parentFD)

	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return nil, fmt.Errorf("inspect evaluation event parent: %w", err)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR || parentStat.Mode&0o777 != 0o700 ||
		parentStat.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("%w: event parent must be owned mode 0700 directory", errInvalid)
	}

	var entryStat unix.Stat_t
	if err := unix.Fstatat(parentFD, base, &entryStat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if entryStat.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil, fmt.Errorf("%w: event path is a symlink", errInvalid)
		}
		return nil, fmt.Errorf("%w: event path already exists", errInvalid)
	} else if err != unix.ENOENT {
		return nil, fmt.Errorf("inspect evaluation event path: %w", err)
	}

	fileFD, err := unix.Openat(parentFD, base,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create evaluation event stream: %w", err)
	}
	if err := unix.Fchmod(fileFD, 0o600); err != nil {
		_ = unix.Close(fileFD)
		_ = unix.Unlinkat(parentFD, base, 0)
		return nil, fmt.Errorf("set evaluation event stream mode: %w", err)
	}
	file := os.NewFile(uintptr(fileFD), path)
	if file == nil {
		_ = unix.Close(fileFD)
		_ = unix.Unlinkat(parentFD, base, 0)
		return nil, fmt.Errorf("create evaluation event stream: %w", errInvalid)
	}
	// Persist the create-exclusive directory entry before exposing the sink. Each
	// Record then synchronizes its complete JSONL line before returning.
	if err := syncParent(parentFD); err != nil {
		_ = file.Close()
		_ = unix.Unlinkat(parentFD, base, 0)
		return nil, fmt.Errorf("synchronize evaluation event parent: %w", err)
	}
	return file, nil
}

func eventPathParts(path string) (string, string, error) {
	if path == "" || filepath.Clean(path) != path {
		return "", "", fmt.Errorf("%w: event path is not canonical", errInvalid)
	}
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == ".." {
			return "", "", fmt.Errorf("%w: event path contains ..", errInvalid)
		}
	}
	parent, base := filepath.Dir(path), filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return "", "", fmt.Errorf("%w: invalid event filename", errInvalid)
	}
	return parent, base, nil
}

// Record validates, writes, and synchronizes one complete JSON object before returning.
func (sink *Sink) Record(event recovery.EvaluationEvent) error {
	if sink == nil {
		return errInvalid
	}
	sink.mutex.Lock()
	defer sink.mutex.Unlock()
	if sink.closed {
		return errClosed
	}
	if sink.failed {
		return errors.Join(errFailed, sink.failure)
	}
	if !validEvaluationEvent(sink.fault, event) {
		return errInvalid
	}
	encoded, err := json.Marshal(eventRecord{
		Schema: eventSchema, Case: sink.caseName, Connection: event.Connection,
		Operation: event.Operation, Frame: event.Frame, Sequence: event.Sequence,
		Next: event.Next, Window: event.Window, Fault: event.Fault, Outcome: event.Outcome,
	})
	if err != nil {
		return sink.fail(err)
	}
	encoded = append(encoded, '\n')
	written, err := sink.file.Write(encoded)
	if err == nil && written != len(encoded) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = sink.file.Sync()
	}
	if err != nil {
		return sink.fail(err)
	}
	return nil
}

func (sink *Sink) fail(err error) error {
	sink.failed = true
	sink.failure = err
	return err
}

// Close synchronizes and closes the stream once. Repeated calls are harmless.
func (sink *Sink) Close() error {
	if sink == nil {
		return errInvalid
	}
	sink.mutex.Lock()
	defer sink.mutex.Unlock()
	if sink.closed {
		return nil
	}
	sink.closed = true
	syncErr := sink.file.Sync()
	closeErr := sink.file.Close()
	sink.file = nil
	if syncErr != nil || closeErr != nil {
		sink.failed = true
		sink.failure = errors.Join(sink.failure, syncErr, closeErr)
	}
	if sink.failure != nil {
		return sink.failure
	}
	return nil
}

func validFault(fault recovery.EvaluationFault) bool {
	switch fault {
	case recovery.EvaluationFaultInterruptAfterData7,
		recovery.EvaluationFaultArtifactDigestMismatch,
		recovery.EvaluationFaultChunkSequence:
		return true
	default:
		return false
	}
}

func validEvaluationEvent(fault recovery.EvaluationFault, event recovery.EvaluationEvent) bool {
	if event.Connection == 0 || event.Fault != fault || !validFault(event.Fault) {
		return false
	}
	switch event.Operation {
	case "manifest":
		return event.Frame == "RESPONSE" && event.Sequence == 0 && event.Next == 0 &&
			event.Window == 0 && event.Outcome == "sent"
	case "artifact":
		switch event.Frame {
		case "DATA":
			if event.Next != 0 || event.Window != 0 {
				return false
			}
			switch event.Outcome {
			case "sent":
				return !((fault == recovery.EvaluationFaultArtifactDigestMismatch && event.Sequence == 0) ||
					(fault == recovery.EvaluationFaultChunkSequence && event.Sequence == 1) ||
					(fault == recovery.EvaluationFaultInterruptAfterData7 && event.Sequence == 7))
			case "injected":
				return (fault == recovery.EvaluationFaultArtifactDigestMismatch && event.Sequence == 0) ||
					(fault == recovery.EvaluationFaultChunkSequence && event.Sequence == 2)
			case "interrupt-ready":
				return fault == recovery.EvaluationFaultInterruptAfterData7 && event.Sequence == 7
			default:
				return false
			}
		case "ACK":
			return event.Outcome == "accepted" && event.Next > 0 &&
				event.Next%recovery.ACKWindow == 0 && event.Window == recovery.ACKWindow
		case "COMPLETE":
			return event.Outcome == "sent" && event.Next == 0 && event.Window == 0
		default:
			return false
		}
	default:
		return false
	}
}
