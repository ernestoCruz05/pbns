package cosebridge

/*
#cgo CXXFLAGS: -std=c++17 -pthread -DUSE_CBOR_CONTEXT -I${SRCDIR}/../../../build/dev/cose-c/install/include
#cgo LDFLAGS: -pthread -L${SRCDIR}/../../../build/dev/cose-c/install/lib -lcose-c -lcn-cbor -lcrypto -lstdc++
#include "bridge.h"
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

var (
	ErrInvalidArgument = errors.New("invalid COSE bridge argument")
	ErrKeyProfile      = errors.New("unsupported COSE key profile")
	ErrFormat          = errors.New("invalid COSE encryption format")
	ErrAuthentication  = errors.New("COSE decryption authentication failed")
	ErrCrypto          = errors.New("COSE cryptographic operation failed")
	ErrResource        = errors.New("COSE bridge resource failure")
	ErrLimit           = errors.New("COSE bridge size limit exceeded")
)

const (
	maxRecipientKID       = 64
	maxExternalAAD        = 256
	maxMessage            = 65536
	MaxAttestationMessage = 4_268_800
)

func bytesPointer(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(data)))
}

func bridgeError(operation string, status C.pbns_cosec_status) error {
	var target error
	switch status {
	case C.PBNS_COSEC_INVALID_ARGUMENT:
		target = ErrInvalidArgument
	case C.PBNS_COSEC_KEY_PROFILE:
		target = ErrKeyProfile
	case C.PBNS_COSEC_FORMAT:
		target = ErrFormat
	case C.PBNS_COSEC_AUTHENTICATION:
		target = ErrAuthentication
	case C.PBNS_COSEC_CRYPTO:
		target = ErrCrypto
	case C.PBNS_COSEC_MEMORY:
		target = ErrResource
	case C.PBNS_COSEC_LIMIT:
		target = ErrLimit
	default:
		target = ErrCrypto
	}
	return fmt.Errorf("%s: %w (bridge status %d)", operation, target, int(status))
}

func publicKeyHasProfile(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil &&
		key.Curve.IsOnCurve(key.X, key.Y)
}

func privateKeyHasProfile(key *ecdsa.PrivateKey) bool {
	return key != nil && key.D != nil && key.D.Sign() > 0 && publicKeyHasProfile(&key.PublicKey)
}

func copyOutput(operation string, output *C.pbns_cosec_output) ([]byte, error) {
	defer C.pbns_cosec_free(unsafe.Pointer(output.data))
	if output.len > maxMessage || (output.len > 0 && output.data == nil) {
		return nil, fmt.Errorf("%s: %w", operation, ErrLimit)
	}
	return C.GoBytes(unsafe.Pointer(output.data), C.int(output.len)), nil
}

func copyOutputBounded(operation string, output *C.pbns_cosec_output, maximumMessageSize int) ([]byte, error) {
	if output.len > C.size_t(maximumMessageSize) || (output.len > 0 && output.data == nil) {
		C.pbns_cosec_free(unsafe.Pointer(output.data))
		return nil, fmt.Errorf("%s: %w", operation, ErrLimit)
	}
	defer C.pbns_cosec_clear_free(unsafe.Pointer(output.data), output.len)
	return C.GoBytes(unsafe.Pointer(output.data), C.int(output.len)), nil
}

func Encrypt(recipient *ecdsa.PublicKey, recipientKID, plaintext, externalAAD []byte) ([]byte, error) {
	if !publicKeyHasProfile(recipient) {
		if recipient == nil {
			return nil, ErrInvalidArgument
		}
		return nil, ErrKeyProfile
	}
	if len(recipientKID) == 0 || len(recipientKID) > maxRecipientKID ||
		len(plaintext) > maxMessage || len(externalAAD) > maxExternalAAD {
		return nil, ErrInvalidArgument
	}
	publicDER, err := x509.MarshalPKIXPublicKey(recipient)
	if err != nil {
		return nil, fmt.Errorf("marshal recipient public key: %w", ErrKeyProfile)
	}

	var output C.pbns_cosec_output
	status := C.pbns_cosec_encrypt(
		bytesPointer(publicDER), C.size_t(len(publicDER)),
		bytesPointer(recipientKID), C.size_t(len(recipientKID)),
		bytesPointer(plaintext), C.size_t(len(plaintext)),
		bytesPointer(externalAAD), C.size_t(len(externalAAD)),
		&output,
	)
	runtime.KeepAlive(publicDER)
	runtime.KeepAlive(recipientKID)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(externalAAD)
	runtime.KeepAlive(recipient)
	if status != C.PBNS_COSEC_OK {
		C.pbns_cosec_free(unsafe.Pointer(output.data))
		return nil, bridgeError("encrypt", status)
	}
	return copyOutput("encrypt", &output)
}

func Decrypt(recipient *ecdsa.PrivateKey, expectedRecipientKID, message, externalAAD []byte) ([]byte, error) {
	return decrypt(recipient, expectedRecipientKID, message, externalAAD, maxMessage)
}

// DecryptBounded decrypts a canonical COSE_Encrypt message within the caller-provided bound.
func DecryptBounded(recipient *ecdsa.PrivateKey, expectedRecipientKID, message, externalAAD []byte, maximumMessageSize int) ([]byte, error) {
	if maximumMessageSize <= 0 || maximumMessageSize > MaxAttestationMessage {
		return nil, ErrInvalidArgument
	}
	return decrypt(recipient, expectedRecipientKID, message, externalAAD, maximumMessageSize)
}

func decrypt(recipient *ecdsa.PrivateKey, expectedRecipientKID, message, externalAAD []byte, maximumMessageSize int) ([]byte, error) {
	if !privateKeyHasProfile(recipient) {
		if recipient == nil {
			return nil, ErrInvalidArgument
		}
		return nil, ErrKeyProfile
	}
	if len(expectedRecipientKID) == 0 || len(expectedRecipientKID) > maxRecipientKID ||
		len(message) == 0 || len(message) > maximumMessageSize || len(externalAAD) > maxExternalAAD {
		return nil, ErrInvalidArgument
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(recipient)
	if err != nil {
		return nil, fmt.Errorf("marshal recipient private key: %w", ErrKeyProfile)
	}
	defer clear(privateDER)

	var output C.pbns_cosec_output
	status := C.pbns_cosec_decrypt_bounded(
		bytesPointer(privateDER), C.size_t(len(privateDER)), C.size_t(maximumMessageSize),
		bytesPointer(expectedRecipientKID), C.size_t(len(expectedRecipientKID)),
		bytesPointer(message), C.size_t(len(message)),
		bytesPointer(externalAAD), C.size_t(len(externalAAD)),
		&output,
	)
	runtime.KeepAlive(privateDER)
	runtime.KeepAlive(expectedRecipientKID)
	runtime.KeepAlive(message)
	runtime.KeepAlive(externalAAD)
	runtime.KeepAlive(recipient)
	if status != C.PBNS_COSEC_OK {
		C.pbns_cosec_free(unsafe.Pointer(output.data))
		return nil, bridgeError("decrypt", status)
	}
	return copyOutputBounded("decrypt", &output, maximumMessageSize)
}

// clearFreeCountForTest exposes no plaintext and exists solely to prove decrypt outputs use native cleanse-and-free.
func clearFreeCountForTest() uint64 { return uint64(C.pbns_cosec_clear_free_count()) }
