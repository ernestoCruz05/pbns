package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

const (
	credentialsVersion = 1
	ssidMax            = 32
	pskMax             = 63
	hostnameMax        = 253
	spkiSize           = 32
	recordMax          = 448
)

var errInvalidRecord = errors.New("invalid Pico credential record")
var errPrivateInput = errors.New("SSID and PSK files must have mode 0600")
var errOutputExists = errors.New("credential output already exists")

type credentialRecord struct {
	Version    uint64 `cbor:"1,keyasint"`
	SSID       []byte `cbor:"2,keyasint"`
	PSK        []byte `cbor:"3,keyasint"`
	Hostname   string `cbor:"4,keyasint"`
	Port       uint64 `cbor:"5,keyasint"`
	SPKISHA256 []byte `cbor:"6,keyasint"`
}

func containsZero(value []byte) bool {
	return bytes.IndexByte(value, 0) >= 0
}

func encodeRecord(ssid, psk []byte, hostname string, port uint16, spkiSHA256 []byte) ([]byte, error) {
	if len(ssid) < 1 || len(ssid) > ssidMax || !utf8.Valid(ssid) || containsZero(ssid) ||
		len(psk) < 1 || len(psk) > pskMax || containsZero(psk) ||
		len(hostname) < 1 || len(hostname) > hostnameMax || !utf8.ValidString(hostname) ||
		containsZero([]byte(hostname)) || port == 0 || len(spkiSHA256) != spkiSize {
		return nil, errInvalidRecord
	}
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical CBOR mode: %w", err)
	}
	encoded, err := mode.Marshal(credentialRecord{
		Version:    credentialsVersion,
		SSID:       append([]byte(nil), ssid...),
		PSK:        append([]byte(nil), psk...),
		Hostname:   hostname,
		Port:       uint64(port),
		SPKISHA256: append([]byte(nil), spkiSHA256...),
	})
	if err != nil {
		return nil, fmt.Errorf("encode canonical credential record: %w", err)
	}
	if len(encoded) > recordMax {
		return nil, errInvalidRecord
	}
	return encoded, nil
}

func readBounded(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open local input file")
	}
	contents, readErr := io.ReadAll(io.LimitReader(file, int64(maximum+1)))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.New("cannot read local input file")
	}
	if len(contents) > maximum {
		return nil, errInvalidRecord
	}
	return contents, nil
}

func readPrivate(path string, maximum int) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("cannot inspect private input file")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errPrivateInput
	}
	return readBounded(path, maximum)
}

func writePrivate(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return errOutputExists
	}
	if err != nil {
		return errors.New("cannot create credential output")
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	written, writeErr := file.Write(contents)
	if writeErr == nil && written != len(contents) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("cannot write credential output")
	}
	remove = false
	return nil
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("pbns-pico-record", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ssidPath := flags.String("ssid-file", "", "mode-0600 file containing exact SSID bytes")
	pskPath := flags.String("psk-file", "", "mode-0600 file containing exact PSK bytes")
	hostname := flags.String("host", "", "gateway hostname or address")
	port := flags.Int("port", 0, "gateway TCP port")
	spkiPath := flags.String("spki-sha256-file", "", "file containing the leaf SPKI SHA-256 hex")
	outputPath := flags.String("output", "", "new credential CBOR output file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		*ssidPath == "" || *pskPath == "" || *hostname == "" || *port < 1 ||
		*port > 65535 || *spkiPath == "" || *outputPath == "" {
		return errInvalidRecord
	}
	ssid, err := readPrivate(*ssidPath, ssidMax)
	if err != nil {
		return err
	}
	psk, err := readPrivate(*pskPath, pskMax)
	if err != nil {
		return err
	}
	spkiText, err := readBounded(*spkiPath, spkiSize*2+2)
	if err != nil {
		return err
	}
	spki, err := hex.DecodeString(string(bytes.TrimSpace(spkiText)))
	if err != nil {
		return errInvalidRecord
	}
	record, err := encodeRecord(ssid, psk, *hostname, uint16(*port), spki)
	if err != nil {
		return err
	}
	return writePrivate(*outputPath, record)
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "wrote private Pico credential record")
}
