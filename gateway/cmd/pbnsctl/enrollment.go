package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"pbns.local/gateway/internal/store"
)

func runEnrollment(database *store.Store, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("enrollment command required")
	}
	switch arguments[0] {
	case "create":
		return createEnrollment(database, arguments[1:], output)
	case "show":
		return showEnrollment(database, arguments[1:], output)
	case "revoke":
		return revokeEnrollment(database, arguments[1:], output)
	default:
		return errors.New("unknown enrollment command")
	}
}

func createEnrollment(database *store.Store, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("enrollment create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ttl := 10 * time.Minute
	flags.DurationVar(&ttl, "ttl", ttl, "token lifetime")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || ttl <= 0 {
		return errors.New("invalid enrollment create arguments")
	}
	issued, err := database.CreateEnrollment(ttl)
	if err != nil {
		return err
	}
	if err := writeValue(output, "enrollment_id", hex.EncodeToString(issued.Digest[:])); err != nil {
		return err
	}
	if err := writeValue(output, "enrollment_token", issued.Plaintext); err != nil {
		return err
	}
	return writeValue(output, "expires_at", issued.ExpiresAt.UTC().Format(time.RFC3339Nano))
}

func showEnrollment(database *store.Store, arguments []string, output io.Writer) error {
	digest, err := enrollmentID(arguments, "enrollment show")
	if err != nil {
		return err
	}
	enrollment, err := database.GetEnrollment(digest)
	if err != nil {
		return err
	}
	if err := writeValue(output, "enrollment_id", hex.EncodeToString(enrollment.Digest[:])); err != nil {
		return err
	}
	if err := writeValue(output, "state", string(enrollment.State)); err != nil {
		return err
	}
	return writeValue(
		output,
		"expires_at",
		time.Unix(0, enrollment.ExpiresAtUnixNano).UTC().Format(time.RFC3339Nano),
	)
}

func revokeEnrollment(database *store.Store, arguments []string, output io.Writer) error {
	digest, err := enrollmentID(arguments, "enrollment revoke")
	if err != nil {
		return err
	}
	if err := database.RevokeEnrollment(digest); err != nil {
		return err
	}
	if err := writeValue(output, "enrollment_id", hex.EncodeToString(digest[:])); err != nil {
		return err
	}
	return writeValue(output, "state", string(store.EnrollmentRevoked))
}

func enrollmentID(arguments []string, name string) ([32]byte, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var encoded string
	flags.StringVar(&encoded, "id", "", "SHA-256 enrollment identifier")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return [32]byte{}, errors.New("invalid enrollment identifier")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != encoded {
		return [32]byte{}, errors.New("invalid enrollment identifier")
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest, nil
}

func runHosts(database *store.Store, arguments []string, output io.Writer) error {
	if len(arguments) != 1 || arguments[0] != "list" {
		return errors.New("invalid hosts command")
	}
	hosts, err := database.ListHosts()
	if err != nil {
		return err
	}
	if err := writeValue(output, "hosts", fmt.Sprintf("%d", len(hosts))); err != nil {
		return err
	}
	for index, host := range hosts {
		value := fmt.Sprintf("%x:%s:%d", host.Fingerprint, host.Assurance, host.EnrolledAtUnix)
		if err := writeValue(output, fmt.Sprintf("host_%d", index), value); err != nil {
			return err
		}
	}
	return nil
}

func writeValue(writer io.Writer, key, value string) error {
	if writer == nil || key == "" || value == "" {
		return errors.New("invalid output")
	}
	if _, err := fmt.Fprintf(writer, "%s=%s\n", key, value); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
