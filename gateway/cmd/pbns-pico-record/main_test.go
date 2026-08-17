package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func testPin(t *testing.T) []byte {
	t.Helper()
	pin, err := hex.DecodeString("a0d21923ddfccba12d0a7bbd7408650cb8c54f1be537fe3a7e69adb1376da106")
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func TestEncodeRecordUsesCanonicalIntegerKeyedCBOR(t *testing.T) {
	record, err := encodeRecord([]byte("test-network"), []byte("private-passphrase"),
		"192.0.2.10", 8443, testPin(t))
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[uint64]any
	if err := cbor.Unmarshal(record, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded[1] != uint64(1) || !bytes.Equal(decoded[2].([]byte), []byte("test-network")) ||
		!bytes.Equal(decoded[3].([]byte), []byte("private-passphrase")) ||
		decoded[4] != "192.0.2.10" || decoded[5] != uint64(8443) ||
		!bytes.Equal(decoded[6].([]byte), testPin(t)) {
		t.Fatalf("unexpected record: %#v", decoded)
	}
	canonical, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := canonical.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(record, reencoded) {
		t.Fatalf("record is not canonical: %x", record)
	}
}

func TestEncodeRecordRejectsInvalidFields(t *testing.T) {
	validSSID := []byte("network")
	validPSK := []byte("passphrase")
	validPin := testPin(t)
	tests := []struct {
		name string
		ssid []byte
		psk  []byte
		host string
		port uint16
		pin  []byte
	}{
		{name: "empty SSID", psk: validPSK, host: "gateway", port: 1, pin: validPin},
		{name: "long SSID", ssid: bytes.Repeat([]byte{'s'}, 33), psk: validPSK, host: "gateway", port: 1, pin: validPin},
		{name: "empty PSK", ssid: validSSID, host: "gateway", port: 1, pin: validPin},
		{name: "long PSK", ssid: validSSID, psk: bytes.Repeat([]byte{'p'}, 64), host: "gateway", port: 1, pin: validPin},
		{name: "zero in PSK", ssid: validSSID, psk: []byte{'p', 0}, host: "gateway", port: 1, pin: validPin},
		{name: "empty host", ssid: validSSID, psk: validPSK, port: 1, pin: validPin},
		{name: "zero port", ssid: validSSID, psk: validPSK, host: "gateway", pin: validPin},
		{name: "wrong pin", ssid: validSSID, psk: validPSK, host: "gateway", port: 1, pin: validPin[:31]},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := encodeRecord(test.ssid, test.psk, test.host, test.port, test.pin); err == nil {
				t.Fatal("invalid record was accepted")
			}
		})
	}
}

func TestRunReadsPrivateFilesAndCreatesPrivateOutput(t *testing.T) {
	directory := t.TempDir()
	ssidPath := filepath.Join(directory, "ssid")
	pskPath := filepath.Join(directory, "psk")
	pinPath := filepath.Join(directory, "pin")
	outputPath := filepath.Join(directory, "credentials.cbor")
	if err := os.WriteFile(ssidPath, []byte("test-network"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pskPath, []byte("private-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(hex.EncodeToString(testPin(t))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"--ssid-file", ssidPath,
		"--psk-file", pskPath,
		"--host", "192.0.2.10",
		"--port", "8443",
		"--spki-sha256-file", pinPath,
		"--output", outputPath,
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode is %o", info.Mode().Perm())
	}
	if err := run([]string{
		"--ssid-file", ssidPath,
		"--psk-file", pskPath,
		"--host", "192.0.2.10",
		"--port", "8443",
		"--spki-sha256-file", pinPath,
		"--output", outputPath,
	}); err == nil {
		t.Fatal("existing output was overwritten")
	}
}

func TestRunRejectsSecretFilesWithoutExact0600Mode(t *testing.T) {
	directory := t.TempDir()
	ssidPath := filepath.Join(directory, "ssid")
	pskPath := filepath.Join(directory, "psk")
	pinPath := filepath.Join(directory, "pin")
	if err := os.WriteFile(ssidPath, []byte("test-network"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pskPath, []byte("private-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(hex.EncodeToString(testPin(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"--ssid-file", ssidPath,
		"--psk-file", pskPath,
		"--host", "gateway",
		"--port", "8443",
		"--spki-sha256-file", pinPath,
		"--output", filepath.Join(directory, "credentials.cbor"),
	}
	if err := run(arguments); err == nil {
		t.Fatal("group-readable secret file was accepted")
	}
	if err := os.Chmod(ssidPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := run(arguments); err == nil {
		t.Fatal("mode-0400 secret file was accepted")
	}
}
