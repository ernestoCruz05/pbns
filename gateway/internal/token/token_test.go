package token

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestGenerateUsesExactEntropyAndStableDigest(t *testing.T) {
	entropy := make([]byte, ByteLength)
	for index := range entropy {
		entropy[index] = byte(index)
	}
	expiresAt := time.Unix(1_900_000_000, 0).UTC()
	issued, err := Generate(bytes.NewReader(entropy), expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	wantPlaintext := base64.RawURLEncoding.EncodeToString(entropy)
	if issued.Plaintext != wantPlaintext {
		t.Fatalf("got %q, want %q", issued.Plaintext, wantPlaintext)
	}
	if issued.Digest != sha256.Sum256(entropy) {
		t.Fatalf("unexpected digest: %x", issued.Digest)
	}
	if !issued.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("got expiry %v, want %v", issued.ExpiresAt, expiresAt)
	}
	parsed, err := Digest(issued.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != issued.Digest {
		t.Fatalf("parsed digest %x differs from issued digest %x", parsed, issued.Digest)
	}
}

func TestDigestSecretMatchesIssuedDigestWithoutTextConversion(t *testing.T) {
	secret := make([]byte, ByteLength)
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	got, err := DigestSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got != sha256.Sum256(secret) {
		t.Fatalf("digest got %x", got)
	}
	if _, err := DigestSecret(secret[:len(secret)-1]); !errors.Is(err, ErrFormat) {
		t.Fatalf("short secret got %v, want ErrFormat", err)
	}
}

func TestGenerateFailsClosedOnEntropyFailure(t *testing.T) {
	issued, err := Generate(failingReader{}, time.Unix(1_900_000_000, 0))
	if !errors.Is(err, ErrEntropy) {
		t.Fatalf("got %v, want ErrEntropy", err)
	}
	if issued != (Issued{}) {
		t.Fatalf("failure returned token material: %#v", issued)
	}
}

func TestDigestRejectsNonCanonicalOrWrongLengthTokens(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, ByteLength))
	for _, plaintext := range []string{
		"",
		valid + "=",
		valid[:len(valid)-1],
		valid + "A",
		strings.Repeat("!", len(valid)),
	} {
		t.Run(fmt.Sprintf("length-%d", len(plaintext)), func(t *testing.T) {
			if _, err := Digest(plaintext); !errors.Is(err, ErrFormat) {
				t.Fatalf("got %v, want ErrFormat", err)
			}
		})
	}
}

func TestIssuedCannotBeSerializedOrLogged(t *testing.T) {
	issued, err := Generate(bytes.NewReader(make([]byte, ByteLength)), time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(issued); !errors.Is(err, ErrSensitive) {
		t.Fatalf("json marshal got %v, want ErrSensitive", err)
	}
	if _, err := cbor.Marshal(issued); !errors.Is(err, ErrSensitive) {
		t.Fatalf("CBOR marshal got %v, want ErrSensitive", err)
	}
	for _, rendered := range []string{issued.String(), fmt.Sprint(issued), fmt.Sprintf("%#v", issued)} {
		if strings.Contains(rendered, issued.Plaintext) {
			t.Fatalf("rendered token leaked plaintext: %q", rendered)
		}
	}
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	logger.Info("issued", "token", issued)
	if strings.Contains(logOutput.String(), issued.Plaintext) {
		t.Fatalf("structured log leaked plaintext: %q", logOutput.String())
	}
}
