package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
)

func TestRecoveryPublishCommand(t *testing.T) {
	directory := t.TempDir()
	manifestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secureBootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestPrivatePath := filepath.Join(directory, "manifest.pem")
	secureBootPublicPath := filepath.Join(directory, "secureboot.pem")
	if err := keys.SaveECPrivateKey(manifestPrivatePath, manifestKey); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(secureBootPublicPath, &secureBootKey.PublicKey); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(directory, "recovery.efi")
	artifactContent := bytes.Repeat([]byte{0x5a}, 16_385)
	if err := os.WriteFile(artifactPath, artifactContent, 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "policy.cbor")
	if err := os.WriteFile(policyPath, []byte{0xa1, 0x01, 0x02}, 0o600); err != nil {
		t.Fatal(err)
	}
	repositoryPath := filepath.Join(directory, "repository")
	outputPath := filepath.Join(directory, "manifest.cose")
	requestID := sequentialHex(16, 0x10)
	hostBinding := sequentialHex(32, 0x20)
	nonce := sequentialHex(32, 0x40)
	notBefore := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)
	arguments := []string{
		"publish", "--artifact", artifactPath, "--repository", repositoryPath,
		"--request-id", requestID, "--host-binding", hostBinding, "--nonce", nonce,
		"--version", "7", "--minimum-version", "5",
		"--not-before", notBefore.Format(time.RFC3339Nano),
		"--not-after", notAfter.Format(time.RFC3339Nano),
		"--policy-authorization", policyPath, "--policy-key-id", "policy-key-2026",
		"--manifest-private-key", manifestPrivatePath,
		"--manifest-key-id", "recovery-key-2026",
		"--secureboot-public-key", secureBootPublicPath, "--output", outputPath,
	}
	var stdout bytes.Buffer
	if err := runRecovery(arguments, &stdout); err != nil {
		t.Fatal(err)
	}
	var result struct {
		ArtifactSHA256 string `json:"artifact_sha256"`
		ArtifactSize   uint64 `json:"artifact_size"`
		ManifestPath   string `json:"manifest_path"`
		Version        uint64 `json:"version"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ArtifactSize != uint64(len(artifactContent)) || result.ManifestPath != outputPath || result.Version != 7 {
		t.Fatalf("wrong publication result: %#v", result)
	}
	signed, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &manifestKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var expectation recovery.Expectation
	requestBytes, _ := hex.DecodeString(requestID)
	hostBytes, _ := hex.DecodeString(hostBinding)
	nonceBytes, _ := hex.DecodeString(nonce)
	copy(expectation.RequestID[:], requestBytes)
	copy(expectation.HostBinding[:], hostBytes)
	copy(expectation.Nonce[:], nonceBytes)
	expectation.RecoverySigningKeyID = []byte("recovery-key-2026")
	expectation.ExpectedPolicyKeyID = []byte("policy-key-2026")
	expectation.CurrentVersion = 6
	expectation.TrustedEarliestNS = notBefore.Add(time.Second).UnixNano()
	expectation.TrustedLatestNS = notAfter.Add(-time.Second).UnixNano()
	manifest, err := recovery.VerifyManifest(signed, verifier, expectation)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ImageSize != uint64(len(artifactContent)) || manifest.ArtifactVersion != 7 ||
		hex.EncodeToString(manifest.ArtifactDigest[:]) != result.ArtifactSHA256 {
		t.Fatal("published manifest does not bind the registered artifact")
	}
	if err := runRecovery(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("existing signed-manifest output replaced")
	}
}

func TestRecoveryPublishRejectsReusedKey(t *testing.T) {
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(directory, "manifest.pem")
	publicPath := filepath.Join(directory, "secureboot.pem")
	if err := keys.SaveECPrivateKey(privatePath, key); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(publicPath, &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(directory, "artifact.efi")
	policyPath := filepath.Join(directory, "policy.cbor")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte{1}, 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{
		"publish", "--artifact", artifactPath, "--repository", filepath.Join(directory, "repo"),
		"--request-id", sequentialHex(16, 1), "--host-binding", sequentialHex(32, 2),
		"--nonce", sequentialHex(32, 3), "--version", "1",
		"--not-before", "2026-08-02T00:00:00Z", "--not-after", "2026-08-03T00:00:00Z",
		"--policy-authorization", policyPath, "--policy-key-id", "policy",
		"--manifest-private-key", privatePath, "--manifest-key-id", "manifest",
		"--secureboot-public-key", publicPath, "--output", filepath.Join(directory, "manifest.cose"),
	}
	if err := runRecovery(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("reused Secure Boot and manifest key accepted")
	}
}

func sequentialHex(size int, first byte) string {
	value := make([]byte, size)
	for index := range value {
		value[index] = first + byte(index)
	}
	return hex.EncodeToString(value)
}
