package token

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"
)

const ByteLength = 32

var (
	ErrArgument  = errors.New("invalid token argument")
	ErrEntropy   = errors.New("token entropy unavailable")
	ErrFormat    = errors.New("invalid token format")
	ErrSensitive = errors.New("sensitive token cannot be serialized")
)

type Issued struct {
	Plaintext string
	Digest    [sha256.Size]byte
	ExpiresAt time.Time
}

func Generate(random io.Reader, expiresAt time.Time) (Issued, error) {
	if random == nil || expiresAt.IsZero() {
		return Issued{}, ErrArgument
	}
	secret := make([]byte, ByteLength)
	if _, err := io.ReadFull(random, secret); err != nil {
		clear(secret)
		return Issued{}, fmt.Errorf("%w", ErrEntropy)
	}
	issued := Issued{
		Plaintext: base64.RawURLEncoding.EncodeToString(secret),
		Digest:    sha256.Sum256(secret),
		ExpiresAt: expiresAt.UTC(),
	}
	clear(secret)
	return issued, nil
}

func DigestSecret(secret []byte) ([sha256.Size]byte, error) {
	if len(secret) != ByteLength {
		return [sha256.Size]byte{}, ErrFormat
	}
	return sha256.Sum256(secret), nil
}

func Digest(plaintext string) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if plaintext == "" {
		return zero, ErrFormat
	}
	secret, err := base64.RawURLEncoding.DecodeString(plaintext)
	if err != nil || len(secret) != ByteLength ||
		base64.RawURLEncoding.EncodeToString(secret) != plaintext {
		clear(secret)
		return zero, ErrFormat
	}
	digest := sha256.Sum256(secret)
	clear(secret)
	return digest, nil
}

func (Issued) String() string {
	return "enrollment token [redacted]"
}

func (issued Issued) GoString() string {
	return issued.String()
}

func (Issued) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitive
}

func (Issued) MarshalCBOR() ([]byte, error) {
	return nil, ErrSensitive
}
