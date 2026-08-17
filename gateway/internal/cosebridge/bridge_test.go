package cosebridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	interopAAD       = []byte("PBNS-ENCRYPT-INTEROP-v1")
	interopKID       = []byte("pbns-recipient-v1")
	interopPlaintext = []byte("pbns interop payload")
)

func projectPath(parts ...string) string {
	base := []string{"..", "..", ".."}
	return filepath.Join(append(base, parts...)...)
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func mustPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	contents := mustRead(t, projectPath("tests", "fixtures", "keys", "cose-recipient-test-private.pem"))
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid private-key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PrivateKey", key)
	}
	return privateKey
}

func mustPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	contents := mustRead(t, projectPath("tests", "fixtures", "keys", "cose-recipient-test-public.pem"))
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid public-key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsa.PublicKey", key)
	}
	return publicKey
}

func TestDecryptUsesNativeClearFree(t *testing.T) {
	message := mustRead(t, projectPath("tests", "vectors", "cose-encrypt-v1", "tcose-to-cosec.cbor"))
	for name, decrypt := range map[string]func() error{
		"legacy": func() error { _, err := Decrypt(mustPrivateKey(t), interopKID, message, interopAAD); return err },
		"bounded": func() error {
			_, err := DecryptBounded(mustPrivateKey(t), interopKID, message, interopAAD, MaxAttestationMessage)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := clearFreeCountForTest()
			if err := decrypt(); err != nil {
				t.Fatal(err)
			}
			if after := clearFreeCountForTest(); after <= before {
				t.Fatal("decrypt output was not native-cleansed")
			}
		})
	}
}

func TestDecryptsTCoseVector(t *testing.T) {
	message := mustRead(t, projectPath("tests", "vectors", "cose-encrypt-v1", "tcose-to-cosec.cbor"))
	plaintext, err := Decrypt(mustPrivateKey(t), interopKID, message, interopAAD)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(interopPlaintext, plaintext) {
		t.Fatalf("plaintext mismatch: %x", plaintext)
	}
}

func TestDecryptsUefiTCoseVector(t *testing.T) {
	message := mustRead(t, projectPath("tests", "vectors", "cose-encrypt-v1", "uefi-to-cosec.cbor"))
	plaintext, err := Decrypt(mustPrivateKey(t), interopKID, message, interopAAD)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(interopPlaintext, plaintext) {
		t.Fatalf("plaintext mismatch: %x", plaintext)
	}
}

func TestEncryptsForTCose(t *testing.T) {
	message, err := Encrypt(mustPublicKey(t), interopKID, interopPlaintext, interopAAD)
	if err != nil {
		t.Fatal(err)
	}

	messagePath := filepath.Join(t.TempDir(), "message.cbor")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}

	helper := projectPath("build", "dev", "pbns-test-encrypt")
	privateKey := projectPath("tests", "fixtures", "keys", "cose-recipient-test-private.pem")
	cmd := exec.Command(helper, "--decrypt", privateKey, messagePath, string(interopKID), string(interopAAD))
	plaintext, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			t.Fatalf("t_cose decrypt helper: %v: %smessage: %x", err, exitError.Stderr, message)
		}
		t.Fatalf("t_cose decrypt helper: %v", err)
	}
	if !bytes.Equal(interopPlaintext, plaintext) {
		t.Fatalf("plaintext mismatch: %x", plaintext)
	}
}

func TestDecryptRejectsTamperingAndContextMismatch(t *testing.T) {
	message := mustRead(t, projectPath("tests", "vectors", "cose-encrypt-v1", "tcose-to-cosec.cbor"))
	tampered := bytes.Clone(message)
	tampered[len(tampered)/2] ^= 0x01

	for name, test := range map[string]struct {
		message []byte
		kid     []byte
		aad     []byte
	}{
		"ciphertext": {message: tampered, kid: interopKID, aad: interopAAD},
		"kid":        {message: message, kid: []byte("wrong-recipient"), aad: interopAAD},
		"aad":        {message: message, kid: interopKID, aad: []byte("wrong-aad")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(mustPrivateKey(t), test.kid, test.message, test.aad); err == nil {
				t.Fatal("accepted modified secure context")
			}
		})
	}
}

func TestBoundedDecryptPreservesLegacyLimitAndAttestationCeiling(t *testing.T) {
	key := mustPrivateKey(t)
	oversizedLegacy := make([]byte, maxMessage+1)
	if _, err := Decrypt(key, interopKID, oversizedLegacy, interopAAD); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("legacy oversized input: %v", err)
	}
	atCeiling := make([]byte, MaxAttestationMessage)
	if _, err := DecryptBounded(key, interopKID, atCeiling, interopAAD, MaxAttestationMessage); errors.Is(err, ErrInvalidArgument) || errors.Is(err, ErrLimit) {
		t.Fatalf("attestation ceiling was rejected as a size error: %v", err)
	}
	overCeiling := make([]byte, MaxAttestationMessage+1)
	if _, err := DecryptBounded(key, interopKID, overCeiling, interopAAD, MaxAttestationMessage); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("attestation ceiling + 1: %v", err)
	}
}

func TestConcurrentOperations(t *testing.T) {
	const workerCount = 8
	const iterations = 20
	publicKey := mustPublicKey(t)
	privateKey := mustPrivateKey(t)
	errorsFound := make(chan error, workerCount)
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for worker := 0; worker < workerCount; worker++ {
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				message, err := Encrypt(publicKey, interopKID, interopPlaintext, interopAAD)
				if err != nil {
					errorsFound <- fmt.Errorf("encrypt: %w", err)
					return
				}
				plaintext, err := Decrypt(privateKey, interopKID, message, interopAAD)
				if err != nil {
					errorsFound <- fmt.Errorf("decrypt: %w", err)
					return
				}
				if !bytes.Equal(interopPlaintext, plaintext) {
					errorsFound <- fmt.Errorf("plaintext mismatch: %x", plaintext)
					return
				}
			}
		}()
	}
	workers.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Error(err)
	}
}

func TestRejectsUnsupportedKeysAndInvalidArguments(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := mustRead(t, projectPath("tests", "vectors", "cose-encrypt-v1", "tcose-to-cosec.cbor"))

	if _, err := Encrypt(&p384.PublicKey, interopKID, interopPlaintext, interopAAD); !errors.Is(err, ErrKeyProfile) {
		t.Fatalf("P-384 encrypt: got %v, want ErrKeyProfile", err)
	}
	if _, err := Decrypt(p384, interopKID, message, interopAAD); !errors.Is(err, ErrKeyProfile) {
		t.Fatalf("P-384 decrypt: got %v, want ErrKeyProfile", err)
	}
	if _, err := Encrypt(nil, interopKID, interopPlaintext, interopAAD); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil encrypt key: got %v, want ErrInvalidArgument", err)
	}
	if _, err := Decrypt(nil, interopKID, message, interopAAD); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil decrypt key: got %v, want ErrInvalidArgument", err)
	}
}
