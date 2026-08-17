package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pbns.local/gateway/internal/keys"
)

func TestKeysCreateOfflineRootAndIssueTimeKey(t *testing.T) {
	rootDirectory := filepath.Join(t.TempDir(), "offline-root")
	var stdout, stderr bytes.Buffer
	if status := run([]string{"keys", "root-create", "--offline-dir", rootDirectory}, &stdout, &stderr); status != 0 {
		t.Fatalf("root-create status=%d stderr=%q", status, stderr.String())
	}
	rootOutput := parseOutput(t, stdout.String())
	if len(rootOutput["root_fingerprint"]) != 64 || strings.Contains(stdout.String(), "private") {
		t.Fatalf("unsafe root output %q", stdout.String())
	}
	rootPrivate := filepath.Join(rootDirectory, "root-private.pem")
	if info, err := os.Stat(rootPrivate); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("root private mode: info=%v err=%v", info, err)
	}
	if info, err := os.Stat(rootDirectory); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("root directory mode: info=%v err=%v", info, err)
	}

	onlineDirectory := filepath.Join(t.TempDir(), "online-private")
	publicDirectory := filepath.Join(t.TempDir(), "pin-bundle")
	stdout.Reset()
	stderr.Reset()
	arguments := []string{
		"keys", "issue", "--offline-root-private", rootPrivate,
		"--online-dir", onlineDirectory, "--public-dir", publicDirectory,
		"--role", string(keys.RoleTrustedTime), "--kid", "time-2026-01", "--valid-for", "24h",
	}
	if status := run(arguments, &stdout, &stderr); status != 0 {
		t.Fatalf("issue status=%d stderr=%q", status, stderr.String())
	}
	issued := parseOutput(t, stdout.String())
	if issued["role"] != string(keys.RoleTrustedTime) || issued["kid"] != "time-2026-01" ||
		strings.Contains(stdout.String(), "private") {
		t.Fatalf("unsafe issue output %q", stdout.String())
	}
	onlinePrivate := filepath.Join(onlineDirectory, "trusted-time-private.pem")
	privateKey, err := keys.LoadECPrivateKey(onlinePrivate)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, err := keys.LoadECPublicKey(issued["root_public"])
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := keys.LoadOnlineCertificate(issued["certificate"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.AuthorizeOnlineSigner(rootPublic, certificate, privateKey,
		keys.RoleTrustedTime, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestKeysParsesReceiptRoleWithoutChangingChallengeRole(t *testing.T) {
	receipt, err := parseOnlineRole(string(keys.RoleAttestationReceipt))
	if err != nil || receipt != keys.RoleAttestationReceipt {
		t.Fatalf("receipt role=%q err=%v", receipt, err)
	}
	challenge, err := parseOnlineRole(string(keys.RoleAttestation))
	if err != nil || challenge != keys.RoleAttestation {
		t.Fatalf("challenge role=%q err=%v", challenge, err)
	}
	if receipt == challenge {
		t.Fatal("receipt and challenge roles collapsed")
	}
}

func TestKeysRejectsImplicitOrRepeatedOfflineDirectory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"keys", "root-create"}, &stdout, &stderr); status == 0 {
		t.Fatal("implicit offline directory accepted")
	}
	directory := filepath.Join(t.TempDir(), "offline")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"keys", "root-create", "--offline-dir", directory}, &stdout, &stderr); status == 0 {
		t.Fatal("existing offline directory accepted")
	}
}
