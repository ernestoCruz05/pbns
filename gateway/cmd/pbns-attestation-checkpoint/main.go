package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"pbns.local/gateway/internal/attestation"
	"pbns.local/gateway/internal/gatewayapp"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return 2
	}
	flags := flag.NewFlagSet("pbns-attestation-checkpoint", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var candidatePath, receiptPath string
	flags.StringVar(&candidatePath, "candidate-output", "", "new private canonical candidate file")
	flags.StringVar(&receiptPath, "receipt-output", "", "new private signed receipt file")
	if flags.Parse(arguments) != nil || (candidatePath == "" && receiptPath == "") || (candidatePath != "" && receiptPath != "") {
		_, _ = fmt.Fprintln(stderr, "usage: pbns-attestation-checkpoint (--candidate-output FILE|--receipt-output FILE) gateway-options")
		return 2
	}
	var options gatewayapp.Options
	if candidatePath != "" {
		sink, err := newCandidateFileSink(candidatePath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
		options.BaselineCandidateSink = sink
	} else {
		sink, err := newReceiptFileSink(receiptPath)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
		options.ReceiptSink = sink
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := gatewayapp.Run(ctx, flags.Args(), options); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

type candidateFileSink struct{ path string }
type receiptFileSink struct{ path string }

func newCandidateFileSink(path string) (candidateFileSink, error) {
	if !validOutputPath(path) {
		return candidateFileSink{}, fmt.Errorf("invalid candidate output path")
	}
	return candidateFileSink{path: path}, nil
}

func newReceiptFileSink(path string) (receiptFileSink, error) {
	if !validOutputPath(path) {
		return receiptFileSink{}, fmt.Errorf("invalid receipt output path")
	}
	return receiptFileSink{path: path}, nil
}

func validOutputPath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	return err == nil && info.Mode().IsDir() && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm() == 0o700
}

func (sink candidateFileSink) WriteCandidate(candidate attestation.BaselineCandidate) error {
	if len(candidate.Encoded) == 0 || candidate.HostFingerprint == ([32]byte{}) || candidate.ParentBaselineID == ([32]byte{}) || candidate.EvidenceDigest == ([32]byte{}) {
		return fmt.Errorf("invalid candidate")
	}
	return writeExclusive(sink.path, candidate.Encoded)
}

func (sink receiptFileSink) WriteReceipt(receipt []byte, digest [32]byte) error {
	if len(receipt) == 0 || digest == ([32]byte{}) {
		return fmt.Errorf("invalid receipt")
	}
	return writeExclusive(sink.path, receipt)
}

func writeExclusive(path string, value []byte) (err error) {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open output")
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Size != 0 {
		return fmt.Errorf("unsafe output file")
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAll(file, value); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func writeAll(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count <= 0 || count > len(value) {
			return io.ErrUnexpectedEOF
		}
		value = value[count:]
	}
	return nil
}
