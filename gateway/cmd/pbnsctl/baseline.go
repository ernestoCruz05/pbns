package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"pbns.local/gateway/internal/baselineupdate"
	"pbns.local/gateway/internal/store"
)

const adminPublicKeyMaxSize = 16 * 1024

type BaselineProposal = baselineupdate.Proposal
type ChangeClassification = baselineupdate.Classification

const (
	ChangeInventory = baselineupdate.ChangeInventory
	ChangeSecurity  = baselineupdate.ChangeSecurity
)

var (
	ErrBaselineInvalid       = baselineupdate.ErrInvalid
	ErrBaselineAuthorization = baselineupdate.ErrAuthorization
)

func createBaselineProposal(database *store.Store, host [32]byte, updated []byte, classification ChangeClassification, issued, expires time.Time, kid [32]byte) ([]byte, error) {
	if database == nil {
		return nil, ErrBaselineInvalid
	}
	record, err := database.GetHost(host)
	if err != nil {
		return nil, err
	}
	parent, err := database.GetBaseline(record.BaselineID)
	if err != nil {
		return nil, err
	}
	return baselineupdate.CreateProposal(host, record.BaselineID, parent, updated, classification, issued, expires, kid)
}
func decodeBaselineProposal(encoded []byte) (BaselineProposal, error) {
	return baselineupdate.DecodeProposal(encoded)
}
func baselineProposalAAD(proposal BaselineProposal) []byte {
	return baselineupdate.ApprovalAAD(proposal)
}
func approveBaselineProposal(database *store.Store, proposal, signature []byte, public *ecdsa.PublicKey, now time.Time) error {
	approval, err := baselineupdate.VerifyApproval(proposal, signature, public, now)
	if err != nil {
		return err
	}
	return database.ApplyBaselineApproval(approval)
}

func runBaseline(database *store.Store, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("usage: baseline propose|approve ...")
	}
	switch arguments[0] {
	case "propose":
		return runBaselinePropose(database, arguments[1:], output)
	case "approve":
		return runBaselineApprove(database, arguments[1:], output)
	default:
		return fmt.Errorf("unknown baseline command")
	}
}
func runBaselinePropose(database *store.Store, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("baseline propose", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var hostText, baselinePath, classificationText, adminIDText, outputPath string
	var validFor time.Duration
	flags.StringVar(&hostText, "host", "", "host fingerprint")
	flags.StringVar(&baselinePath, "baseline", "", "canonical controlled baseline")
	flags.StringVar(&classificationText, "classification", "", "inventory or security")
	flags.StringVar(&adminIDText, "admin-key-id", "", "trusted admin public-key fingerprint")
	flags.StringVar(&outputPath, "output", "", "new public proposal file")
	flags.DurationVar(&validFor, "valid-for", time.Hour, "proposal validity")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || hostText == "" || baselinePath == "" || adminIDText == "" || outputPath == "" || validFor <= 0 || validFor > 24*time.Hour {
		return fmt.Errorf("usage: baseline propose --host HEX --baseline FILE --classification inventory|security --admin-key-id HEX --output FILE")
	}
	host, err := parseDigest(hostText)
	if err != nil {
		return err
	}
	kid, err := parseDigest(adminIDText)
	if err != nil {
		return err
	}
	classification := ChangeClassification(0)
	switch classificationText {
	case "inventory":
		classification = ChangeInventory
	case "security":
		classification = ChangeSecurity
	default:
		return ErrBaselineInvalid
	}
	updated, err := readRegularFile(baselinePath, 4*1024*1024+8192)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	proposal, err := createBaselineProposal(database, host, updated, classification, now, now.Add(validFor), kid)
	if err != nil {
		return err
	}
	if err := writeNewArtifact(outputPath, proposal, 0o644); err != nil {
		return err
	}
	decoded, _ := decodeBaselineProposal(proposal)
	_, err = fmt.Fprintf(output, "proposal=%s\nnew_baseline=%s\n", outputPath, formatDigest(decoded.NewBaselineID))
	return err
}
func runBaselineApprove(database *store.Store, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("baseline approve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var proposalPath, signaturePath, publicPath string
	flags.StringVar(&proposalPath, "proposal", "", "canonical proposal")
	flags.StringVar(&signaturePath, "signature", "", "external COSE Sign1 approval")
	flags.StringVar(&publicPath, "admin-public-key", "", "pinned administrator P-256 public key")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || proposalPath == "" || signaturePath == "" || publicPath == "" {
		return fmt.Errorf("usage: baseline approve --proposal FILE --signature FILE --admin-public-key FILE")
	}
	proposal, err := readRegularFile(proposalPath, 4*1024*1024+8192)
	if err != nil {
		return err
	}
	signature, err := readRegularFile(signaturePath, 4*1024*1024+16384)
	if err != nil {
		return err
	}
	public, err := loadAdminPublicKey(publicPath)
	if err != nil {
		return err
	}
	if err := approveBaselineProposal(database, proposal, signature, public, time.Now().UTC()); err != nil {
		return err
	}
	decoded, _ := decodeBaselineProposal(proposal)
	_, err = fmt.Fprintf(output, "host=%s\nactive_baseline=%s\n", formatDigest(decoded.HostFingerprint), formatDigest(decoded.NewBaselineID))
	return err
}
func parseDigest(encoded string) ([32]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, ErrBaselineInvalid
	}
	var digest [32]byte
	copy(digest[:], decoded)
	if digest == [32]byte{} {
		return [32]byte{}, ErrBaselineInvalid
	}
	return digest, nil
}
func formatDigest(digest [32]byte) string { return hex.EncodeToString(digest[:]) }

// readRegularFile opens once with O_NOFOLLOW, validates that descriptor, then reads it bounded.
func readRegularFile(path string, maximum int) ([]byte, error) {
	return readRegularFileAfterOpen(path, maximum, nil)
}

func readRegularFileAfterOpen(path string, maximum int, afterOpen func(string)) (result []byte, err error) {
	if path == "" || maximum <= 0 {
		return nil, ErrBaselineInvalid
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, ErrBaselineInvalid
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrBaselineInvalid
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = ErrBaselineInvalid
		}
	}()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size <= 0 || stat.Size > int64(maximum) {
		return nil, ErrBaselineInvalid
	}
	if afterOpen != nil {
		afterOpen(path)
	}
	result = make([]byte, int(stat.Size))
	if _, err = io.ReadFull(file, result); err != nil {
		return nil, ErrBaselineInvalid
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); readErr != io.EOF || count != 0 {
		return nil, ErrBaselineInvalid
	}
	return result, nil
}
func writeNewArtifact(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	writeErr := file.Chmod(mode)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
func loadAdminPublicKey(path string) (*ecdsa.PublicKey, error) {
	encoded, err := readRegularFile(path, adminPublicKeyMaxSize)
	if err != nil {
		return nil, ErrBaselineAuthorization
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, ErrBaselineAuthorization
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve == nil || key.Curve.Params().Name != "P-256" || !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, ErrBaselineAuthorization
	}
	return key, nil
}
