package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateDatabasePath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "gateway.db")
}

func parseOutput(t *testing.T, output string) map[string]string {
	t.Helper()
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || value == "" {
			t.Fatalf("invalid output line %q", line)
		}
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("duplicate output key %q", key)
		}
		values[key] = value
	}
	return values
}

func TestEnrollmentCreateShowAndRevoke(t *testing.T) {
	path := privateDatabasePath(t)
	var stdout, stderr bytes.Buffer
	if status := run([]string{"--db", path, "enrollment", "create", "--ttl", "10m"}, &stdout, &stderr); status != 0 {
		t.Fatalf("create status %d stderr=%q", status, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("create stderr=%q", stderr.String())
	}
	created := parseOutput(t, stdout.String())
	if len(created) != 3 {
		t.Fatalf("create fields=%v", created)
	}
	secret, err := base64.RawURLEncoding.DecodeString(created["enrollment_token"])
	if err != nil || len(secret) != 32 {
		t.Fatalf("invalid enrollment token: %v length=%d", err, len(secret))
	}
	digest := sha256.Sum256(secret)
	if created["enrollment_id"] != hex.EncodeToString(digest[:]) {
		t.Fatalf("id=%q digest=%x", created["enrollment_id"], digest)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode %o", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(created["enrollment_token"])) {
		t.Fatal("database contains plaintext token")
	}

	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--db", path, "enrollment", "show", "--id", created["enrollment_id"]}, &stdout, &stderr); status != 0 {
		t.Fatalf("show status %d stderr=%q", status, stderr.String())
	}
	if strings.Contains(stdout.String(), created["enrollment_token"]) {
		t.Fatalf("show leaked token: %q", stdout.String())
	}
	shown := parseOutput(t, stdout.String())
	if shown["state"] != "live" || shown["enrollment_id"] != created["enrollment_id"] {
		t.Fatalf("show output=%v", shown)
	}

	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--db", path, "enrollment", "revoke", "--id", created["enrollment_id"]}, &stdout, &stderr); status != 0 {
		t.Fatalf("revoke status %d stderr=%q", status, stderr.String())
	}
	if values := parseOutput(t, stdout.String()); values["state"] != "revoked" {
		t.Fatalf("revoke output=%v", values)
	}

	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--db", path, "enrollment", "show", "--id", created["enrollment_id"]}, &stdout, &stderr); status != 0 {
		t.Fatalf("show revoked status %d stderr=%q", status, stderr.String())
	}
	if values := parseOutput(t, stdout.String()); values["state"] != "revoked" {
		t.Fatalf("show revoked output=%v", values)
	}
}

func TestHostsListAndInvalidCommands(t *testing.T) {
	path := privateDatabasePath(t)
	var stdout, stderr bytes.Buffer
	if status := run([]string{"--db", path, "hosts", "list"}, &stdout, &stderr); status != 0 {
		t.Fatalf("hosts status %d stderr=%q", status, stderr.String())
	}
	if stdout.String() != "hosts=0\n" {
		t.Fatalf("hosts output=%q", stdout.String())
	}
	for _, arguments := range [][]string{
		{},
		{"--db", path},
		{"--db", path, "enrollment", "create", "--ttl", "0s"},
		{"--db", path, "enrollment", "show", "--id", "not-a-digest"},
		{"--db", path, "unknown"},
	} {
		stdout.Reset()
		stderr.Reset()
		if status := run(arguments, &stdout, &stderr); status == 0 {
			t.Fatalf("arguments %v unexpectedly passed", arguments)
		}
		if stdout.Len() != 0 {
			t.Fatalf("arguments %v wrote stdout %q", arguments, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Fatalf("arguments %v omitted error", arguments)
		}
	}
}
