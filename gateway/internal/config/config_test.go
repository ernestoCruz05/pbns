package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixturePath(parts ...string) string {
	base := []string{"..", "..", "..", "tests", "fixtures", "keys"}
	return filepath.Join(append(base, parts...)...)
}

func validConfig() Config {
	return Config{
		ListenAddress:    "127.0.0.1:0",
		TLSCertFile:      fixturePath("tls-gateway-test-cert.pem"),
		TLSKeyFile:       fixturePath("tls-gateway-test-key.pem"),
		HandshakeTimeout: 2 * time.Second,
		ReadTimeout:      3 * time.Second,
		WriteTimeout:     4 * time.Second,
		MaxConnections:   8,
	}
}

func TestTLSConfigLoadsCertificateAndEnforcesTLS12(t *testing.T) {
	cfg := validConfig()
	tlsConfig, err := cfg.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion=%#x", tlsConfig.MinVersion)
	}
	if len(tlsConfig.Certificates) != 1 || len(tlsConfig.Certificates[0].Certificate) == 0 {
		t.Fatal("TLS certificate was not loaded")
	}
	if len(tlsConfig.CipherSuites) == 0 {
		t.Fatal("TLS 1.2 cipher profile is implicit")
	}
	for _, suiteID := range tlsConfig.CipherSuites {
		suite := tls.CipherSuiteName(suiteID)
		if !strings.Contains(suite, "_ECDHE_") ||
			(!strings.Contains(suite, "_GCM_") && !strings.Contains(suite, "CHACHA20_POLY1305")) {
			t.Fatalf("unapproved TLS 1.2 suite %s", suite)
		}
	}
	certificate, err := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	wantText, err := os.ReadFile(fixturePath("tls-gateway-test-spki.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(wantText)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest[:], want) {
		t.Fatalf("SPKI digest=%x, want %x", digest, want)
	}
}

func TestTLSConfigRejectsMissingOrMismatchedCredentials(t *testing.T) {
	tests := map[string]Config{
		"certificate": func() Config { cfg := validConfig(); cfg.TLSCertFile = ""; return cfg }(),
		"key":         func() Config { cfg := validConfig(); cfg.TLSKeyFile = ""; return cfg }(),
		"missing-file": func() Config {
			cfg := validConfig()
			cfg.TLSCertFile = filepath.Join(t.TempDir(), "missing.pem")
			return cfg
		}(),
		"mismatched-key": func() Config {
			cfg := validConfig()
			cfg.TLSKeyFile = fixturePath("cose-recipient-test-private.pem")
			return cfg
		}(),
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := cfg.TLSConfig(); !errors.Is(err, ErrTLSCredentials) {
				t.Fatalf("got %v, want ErrTLSCredentials", err)
			}
		})
	}
}

func TestParseRequiresExplicitTLSFilesAndHasNoPlaintextMode(t *testing.T) {
	if _, err := Parse([]string{"-listen", "127.0.0.1:0"}); !errors.Is(err, ErrTLSCredentials) {
		t.Fatalf("got %v, want ErrTLSCredentials", err)
	}
	if _, err := Parse([]string{"-plaintext"}); err == nil {
		t.Fatal("accepted a plaintext configuration flag")
	}

	cfg, err := Parse([]string{
		"-listen", "127.0.0.1:9443",
		"-tls-cert", fixturePath("tls-gateway-test-cert.pem"),
		"-tls-key", fixturePath("tls-gateway-test-key.pem"),
		"-handshake-timeout", "2s",
		"-read-timeout", "3s",
		"-write-timeout", "4s",
		"-max-connections", "9",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != "127.0.0.1:9443" || cfg.HandshakeTimeout != 2*time.Second ||
		cfg.ReadTimeout != 3*time.Second || cfg.WriteTimeout != 4*time.Second ||
		cfg.MaxConnections != 9 {
		t.Fatalf("unexpected parsed config: %#v", cfg)
	}
}

func TestTrustedTimeConfigurationRequiresEnrolledHostStoreAndRoleKey(t *testing.T) {
	config := validConfig()
	config.TimeSigningKeyFile = "/private/time.pem"
	if err := config.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial trusted time got %v", err)
	}
	config.EnrollmentStoreFile = "/private/gateway.db"
	config.TimeSigningKID = "time-1"
	config.TimeQuality = "ntp-synchronized"
	config.TimeUncertainty = 250 * time.Millisecond
	if err := config.Validate(); err != nil {
		t.Fatalf("complete trusted time rejected: %v", err)
	}
	if !config.TimeEnabled() {
		t.Fatal("complete trusted time configuration was not enabled")
	}
}

func TestAttestationConfigurationIsExplicitAllOrNothingAndKeySeparated(t *testing.T) {
	cfg := validConfig()
	cfg.EnrollmentStoreFile = "/private/gateway.db"
	cfg.AttestationRecipientKeyFile = "/private/attestation-recipient.pem"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial attestation config got %v, want ErrInvalid", err)
	}
	cfg.AttestationRecipientKID = "attestation-recipient-1"
	cfg.AttestationSigningKeyFile = "/private/attestation-signing.pem"
	cfg.AttestationSigningKID = "attestation-signing-1"
	cfg.AttestationReceiptSigningKeyFile = "/private/attestation-receipt.pem"
	cfg.AttestationReceiptSigningKID = "attestation-receipt-1"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("attestation without deployment trust got %v, want ErrInvalid", err)
	}
	cfg.DeploymentBundleFile = "/public/deployment.cbor"
	cfg.TimeSigningKeyFile = "/private/time.pem"
	cfg.TimeSigningKID = "time-1"
	cfg.TimeQuality = "ntp-synchronized"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.AttestationEnabled() {
		t.Fatal("complete bundle-bound attestation configuration is not enabled")
	}
	cfg.AttestationReceiptSigningKeyFile = cfg.AttestationSigningKeyFile
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("attestation key reuse got %v, want ErrInvalid", err)
	}

	parsed, err := Parse([]string{
		"-tls-cert", fixturePath("tls-gateway-test-cert.pem"),
		"-tls-key", fixturePath("tls-gateway-test-key.pem"),
		"-enrollment-store", "/private/gateway.db",
		"-deployment-bundle", "/public/deployment.cbor",
		"-time-signing-key", "/private/time.pem",
		"-time-signing-kid", "time-1",
		"-time-quality", "ntp-synchronized",
		"-attestation-recipient-key", "/private/attestation-recipient.pem",
		"-attestation-recipient-kid", "attestation-recipient-1",
		"-attestation-signing-key", "/private/attestation-signing.pem",
		"-attestation-signing-kid", "attestation-signing-1",
		"-attestation-receipt-signing-key", "/private/attestation-receipt.pem",
		"-attestation-receipt-signing-kid", "attestation-receipt-1",
	})
	if err != nil || !parsed.AttestationEnabled() {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestEnrollmentConfigurationIsExplicitAndAllOrNothing(t *testing.T) {
	cfg := validConfig()
	cfg.EnrollmentStoreFile = "/private/gateway.db"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("partial enrollment config got %v, want ErrInvalid", err)
	}
	cfg.EnrollmentRecipientKeyFile = "/private/recipient.pem"
	cfg.EnrollmentRecipientKID = "enrollment-recipient-1"
	cfg.EnrollmentSigningKeyFile = "/private/signing.pem"
	cfg.EnrollmentSigningKID = "enrollment-signing-1"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("enrollment without canonical bundle got %v, want ErrInvalid", err)
	}
	cfg.EnrollmentBundleFile = "/public/enrollment.cbor"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.EnrollmentEnabled() {
		t.Fatal("complete enrollment configuration is not enabled")
	}

	parsed, err := Parse([]string{
		"-tls-cert", fixturePath("tls-gateway-test-cert.pem"),
		"-tls-key", fixturePath("tls-gateway-test-key.pem"),
		"-enrollment-store", "/private/gateway.db",
		"-enrollment-recipient-key", "/private/recipient.pem",
		"-enrollment-recipient-kid", "enrollment-recipient-1",
		"-enrollment-signing-key", "/private/signing.pem",
		"-enrollment-signing-kid", "enrollment-signing-1",
		"-enrollment-bundle", "/public/enrollment.cbor",
		"-ek-roots", "/public/ek-roots.pem",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.EnrollmentEnabled() || parsed.EnrollmentBundleFile != "/public/enrollment.cbor" || parsed.EKRootsFile != "/public/ek-roots.pem" {
		t.Fatalf("unexpected enrollment config: %#v", parsed)
	}
	cfg = validConfig()
	cfg.EnrollmentBundleFile = "/public/enrollment.cbor"
	if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("enrollment bundle without enrollment got %v, want ErrInvalid", err)
	}
}

func validRecoveryConfig() Config {
	cfg := validConfig()
	cfg.EnrollmentStoreFile = "/private/gateway.db"
	cfg.RecoveryRepository = "/public/recovery"
	cfg.RecoveryArtifactSHA256 = strings.Repeat("a", 64)
	cfg.RecoveryTargetVersion = 5
	cfg.RecoveryMinimumVersion = 0
	cfg.RecoveryPolicyAuthorizationFile = "/public/policy.cbor"
	cfg.RecoveryPolicyPublicKeyFile = "/public/policy.pem"
	cfg.RecoveryPolicyKID = "recovery-policy-1"
	cfg.RecoveryManifestSigningKeyFile = "/private/recovery-manifest.pem"
	cfg.RecoveryManifestSigningKID = "recovery-manifest-1"
	cfg.RecoverySecureBootPublicKeyFile = "/public/secureboot.pem"
	cfg.RecoveryValidityLead = time.Minute
	cfg.RecoveryValidityTrailing = time.Minute
	cfg.RecoveryTransferTimeout = time.Minute
	return cfg
}

func TestRecoveryConfigurationIsExplicitAndAllOrNothing(t *testing.T) {
	cfg := validRecoveryConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !cfg.RecoveryEnabled() {
		t.Fatal("complete recovery configuration was not enabled")
	}
	cfg.RecoveryTransferTimeout = 60 * time.Minute
	if err := cfg.Validate(); err != nil {
		t.Fatalf("maximum recovery transfer timeout rejected: %v", err)
	}

	fields := map[string]func(*Config){
		"repository":            func(cfg *Config) { cfg.RecoveryRepository = "" },
		"artifact":              func(cfg *Config) { cfg.RecoveryArtifactSHA256 = "" },
		"target":                func(cfg *Config) { cfg.RecoveryTargetVersion = 0 },
		"authorization":         func(cfg *Config) { cfg.RecoveryPolicyAuthorizationFile = "" },
		"policy-public-key":     func(cfg *Config) { cfg.RecoveryPolicyPublicKeyFile = "" },
		"policy-kid":            func(cfg *Config) { cfg.RecoveryPolicyKID = "" },
		"manifest-signing-key":  func(cfg *Config) { cfg.RecoveryManifestSigningKeyFile = "" },
		"manifest-signing-kid":  func(cfg *Config) { cfg.RecoveryManifestSigningKID = "" },
		"secureboot-public-key": func(cfg *Config) { cfg.RecoverySecureBootPublicKeyFile = "" },
		"validity-lead":         func(cfg *Config) { cfg.RecoveryValidityLead = 0 },
		"validity-trailing":     func(cfg *Config) { cfg.RecoveryValidityTrailing = 0 },
		"transfer-timeout":      func(cfg *Config) { cfg.RecoveryTransferTimeout = 0 },
	}
	for name, omit := range fields {
		t.Run(name, func(t *testing.T) {
			incomplete := validRecoveryConfig()
			omit(&incomplete)
			if err := incomplete.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}

	for name, change := range map[string]func(*Config){
		"uppercase-digest":     func(cfg *Config) { cfg.RecoveryArtifactSHA256 = strings.Repeat("A", 64) },
		"short-digest":         func(cfg *Config) { cfg.RecoveryArtifactSHA256 = strings.Repeat("a", 63) },
		"minimum-after-target": func(cfg *Config) { cfg.RecoveryMinimumVersion = cfg.RecoveryTargetVersion + 1 },
		"long-policy-kid":      func(cfg *Config) { cfg.RecoveryPolicyKID = strings.Repeat("k", 65) },
		"long-manifest-kid":    func(cfg *Config) { cfg.RecoveryManifestSigningKID = strings.Repeat("k", 65) },
		"lead-too-short":       func(cfg *Config) { cfg.RecoveryValidityLead = time.Second - time.Nanosecond },
		"lead-too-long":        func(cfg *Config) { cfg.RecoveryValidityLead = time.Hour + time.Nanosecond },
		"trailing-too-short":   func(cfg *Config) { cfg.RecoveryValidityTrailing = time.Second - time.Nanosecond },
		"trailing-too-long":    func(cfg *Config) { cfg.RecoveryValidityTrailing = time.Hour + time.Nanosecond },
		"timeout-too-short":    func(cfg *Config) { cfg.RecoveryTransferTimeout = time.Second - time.Nanosecond },
		"timeout-too-long":     func(cfg *Config) { cfg.RecoveryTransferTimeout = 60*time.Minute + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := validRecoveryConfig()
			change(&invalid)
			if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRecoveryConfigurationRejectsRecoveryAndServiceKeyPathReuse(t *testing.T) {
	keyPaths := map[string]func(*Config) *string{
		"manifest":             func(cfg *Config) *string { return &cfg.RecoveryManifestSigningKeyFile },
		"policy":               func(cfg *Config) *string { return &cfg.RecoveryPolicyPublicKeyFile },
		"secureboot":           func(cfg *Config) *string { return &cfg.RecoverySecureBootPublicKeyFile },
		"enrollment-recipient": func(cfg *Config) *string { return &cfg.EnrollmentRecipientKeyFile },
		"enrollment":           func(cfg *Config) *string { return &cfg.EnrollmentSigningKeyFile },
		"time":                 func(cfg *Config) *string { return &cfg.TimeSigningKeyFile },
		"tls":                  func(cfg *Config) *string { return &cfg.TLSKeyFile },
	}
	for first, firstPath := range keyPaths {
		for second, secondPath := range keyPaths {
			if first >= second {
				continue
			}
			t.Run(first+"-"+second, func(t *testing.T) {
				cfg := validRecoveryConfig()
				cfg.EnrollmentRecipientKeyFile = "/private/enrollment-recipient.pem"
				cfg.EnrollmentRecipientKID = "enrollment-recipient-1"
				cfg.EnrollmentSigningKeyFile = "/private/enrollment-signing.pem"
				cfg.EnrollmentSigningKID = "enrollment-signing-1"
				cfg.TimeSigningKeyFile = "/private/time.pem"
				cfg.TimeSigningKID = "time-1"
				cfg.TimeQuality = "test-synchronized"
				*secondPath(&cfg) = *firstPath(&cfg)
				if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
					t.Fatalf("got %v, want ErrInvalid", err)
				}
			})
		}
	}
}

func TestParseRequiresEveryRecoveryFlagIncludingZeroMinimum(t *testing.T) {
	arguments := []string{
		"-tls-cert", fixturePath("tls-gateway-test-cert.pem"),
		"-tls-key", fixturePath("tls-gateway-test-key.pem"),
		"-enrollment-store", "/private/gateway.db",
		"-recovery-repository", "/public/recovery",
		"-recovery-artifact-sha256", strings.Repeat("a", 64),
		"-recovery-target-version", "5",
		"-recovery-minimum-version", "0",
		"-recovery-policy-authorization", "/public/policy.cbor",
		"-recovery-policy-public-key", "/public/policy.pem",
		"-recovery-policy-kid", "recovery-policy-1",
		"-recovery-manifest-signing-key", "/private/recovery-manifest.pem",
		"-recovery-manifest-signing-kid", "recovery-manifest-1",
		"-recovery-secureboot-public-key", "/public/secureboot.pem",
		"-recovery-validity-lead", "1m",
		"-recovery-validity-trailing", "1m",
		"-recovery-transfer-timeout", "1m",
	}
	parsed, err := Parse(arguments)
	if err != nil || !parsed.RecoveryEnabled() || parsed.RecoveryMinimumVersion != 0 {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for index := 6; index < len(arguments); index += 2 {
		t.Run(arguments[index], func(t *testing.T) {
			without := append([]string(nil), arguments[:index]...)
			without = append(without, arguments[index+2:]...)
			if _, err := Parse(without); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestValidateRejectsUnsafeOperationalLimits(t *testing.T) {
	tests := map[string]Config{
		"listen":            func() Config { cfg := validConfig(); cfg.ListenAddress = ""; return cfg }(),
		"handshake-timeout": func() Config { cfg := validConfig(); cfg.HandshakeTimeout = 0; return cfg }(),
		"read-timeout":      func() Config { cfg := validConfig(); cfg.ReadTimeout = -time.Second; return cfg }(),
		"write-timeout":     func() Config { cfg := validConfig(); cfg.WriteTimeout = 0; return cfg }(),
		"connections":       func() Config { cfg := validConfig(); cfg.MaxConnections = 0; return cfg }(),
	}
	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}
