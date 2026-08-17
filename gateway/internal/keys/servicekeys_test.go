package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPinnedSignerEnforcesRole(t *testing.T) {
	key := generateKey(t)
	signer, err := NewPinnedOnlineSigner(RoleTrustedTime, []byte("time-1"), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.RequireRole(RoleTrustedTime); err != nil {
		t.Fatal(err)
	}
	if err := signer.RequireRole(RoleRecoveryManifest); !errors.Is(err, ErrRole) {
		t.Fatalf("role confusion accepted: %v", err)
	}
	if _, err := NewPinnedOnlineSigner(RoleOfflineRoot, []byte("bad"), key); !errors.Is(err, ErrRole) {
		t.Fatalf("offline root accepted as online signer: %v", err)
	}
}

func TestOfflineRootAuthorizesOnlineCertificate(t *testing.T) {
	root := generateKey(t)
	online := generateKey(t)
	now := time.Unix(1_800_000_000, 0)
	certificate, err := IssueOnlineCertificate(root, RoleTrustedTime, []byte("time-1"),
		&online.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := AuthorizeOnlineSigner(&root.PublicKey, certificate, online, RoleTrustedTime, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.RequireRole(RoleTrustedTime); err != nil {
		t.Fatal(err)
	}

	wrongRoot := generateKey(t)
	if _, err := AuthorizeOnlineSigner(&wrongRoot.PublicKey, certificate, online, RoleTrustedTime, now); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("unauthorized certificate accepted: %v", err)
	}
	if _, err := AuthorizeOnlineSigner(&root.PublicKey, certificate, online, RoleRecoveryManifest, now); !errors.Is(err, ErrRole) {
		t.Fatalf("wrong certificate role accepted: %v", err)
	}
	if _, err := AuthorizeOnlineSigner(&root.PublicKey, certificate, online, RoleTrustedTime, now.Add(2*time.Hour)); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("expired certificate accepted: %v", err)
	}
}

func TestReceiptCertificateRoleIsDistinctFromChallengeRole(t *testing.T) {
	root, receiptKey := generateKey(t), generateKey(t)
	now := time.Unix(1_800_000_000, 0)
	certificate, err := IssueOnlineCertificate(root, RoleAttestationReceipt, []byte("receipt-1"), &receiptKey.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeOnlineSigner(&root.PublicKey, certificate, receiptKey, RoleAttestationReceipt, now); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeOnlineSigner(&root.PublicKey, certificate, receiptKey, RoleAttestation, now); !errors.Is(err, ErrRole) {
		t.Fatalf("receipt certificate authorized challenge signer: %v", err)
	}
}

func TestGatewayPathsRejectOfflinePrivateKey(t *testing.T) {
	rootPrivate := filepath.Join(t.TempDir(), "offline-root-private.pem")
	if err := ValidateGatewayKeyPaths("online.pem", "root-public.pem", rootPrivate); !errors.Is(err, ErrOfflinePrivateKey) {
		t.Fatalf("offline private key path accepted: %v", err)
	}
	if err := ValidateGatewayKeyPaths("online.pem", "root-public.pem", ""); err != nil {
		t.Fatal(err)
	}
}

func TestSavePrivateKeyUsesPrivateModes(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "offline")
	path := filepath.Join(directory, "root-private.pem")
	if err := SaveECPrivateKey(path, generateKey(t)); err != nil {
		t.Fatal(err)
	}
	directoryInfo, err := filepath.Glob(directory)
	if err != nil || len(directoryInfo) != 1 {
		t.Fatal("private directory missing")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o", stat.Mode().Perm())
	}
	parent, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm() != 0o700 {
		t.Fatalf("private directory mode = %o", parent.Mode().Perm())
	}
}
