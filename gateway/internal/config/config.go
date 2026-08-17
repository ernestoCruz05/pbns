package config

import (
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"pbns.local/gateway/internal/tlsprofile"
	"pbns.local/gateway/internal/wire"
)

var (
	ErrInvalid        = errors.New("invalid gateway configuration")
	ErrTLSCredentials = errors.New("invalid TLS credentials")
)

type Config struct {
	ListenAddress                    string
	TLSCertFile                      string
	TLSKeyFile                       string
	DeploymentBundleFile             string
	EnrollmentBundleFile             string
	HandshakeTimeout                 time.Duration
	ReadTimeout                      time.Duration
	WriteTimeout                     time.Duration
	MaxConnections                   int
	Limits                           wire.Limits
	EnrollmentStoreFile              string
	EnrollmentRecipientKeyFile       string
	EnrollmentRecipientKID           string
	EnrollmentSigningKeyFile         string
	EnrollmentSigningKID             string
	EKRootsFile                      string
	AttestationRecipientKeyFile      string
	AttestationRecipientKID          string
	AttestationSigningKeyFile        string
	AttestationSigningKID            string
	AttestationReceiptSigningKeyFile string
	AttestationReceiptSigningKID     string
	TimeSigningKeyFile               string
	TimeSigningKID                   string
	TimeUncertainty                  time.Duration
	TimeQuality                      string
	RecoveryRepository               string
	RecoveryArtifactSHA256           string
	RecoveryTargetVersion            uint64
	RecoveryMinimumVersion           uint64
	RecoveryPolicyAuthorizationFile  string
	RecoveryPolicyPublicKeyFile      string
	RecoveryPolicyKID                string
	RecoveryManifestSigningKeyFile   string
	RecoveryManifestSigningKID       string
	RecoverySecureBootPublicKeyFile  string
	RecoveryValidityLead             time.Duration
	RecoveryValidityTrailing         time.Duration
	RecoveryTransferTimeout          time.Duration
}

func Default() Config {
	return Config{
		ListenAddress:    "127.0.0.1:8443",
		HandshakeTimeout: 5 * time.Second,
		ReadTimeout:      15 * time.Second,
		WriteTimeout:     15 * time.Second,
		MaxConnections:   32,
		Limits:           wire.DefaultLimits(),
	}
}

func (config Config) Validate() error {
	if config.TLSCertFile == "" || config.TLSKeyFile == "" {
		return ErrTLSCredentials
	}
	if config.ListenAddress == "" || config.HandshakeTimeout <= 0 ||
		config.ReadTimeout <= 0 || config.WriteTimeout <= 0 || config.MaxConnections <= 0 {
		return ErrInvalid
	}
	if _, err := wire.NewDecoder(config.Limits); err != nil {
		return fmt.Errorf("%w: frame limits", ErrInvalid)
	}
	timeValues := []string{
		config.TimeSigningKeyFile,
		config.TimeSigningKID,
		config.TimeQuality,
	}
	timeConfigured := 0
	for _, value := range timeValues {
		if value != "" {
			timeConfigured++
		}
	}
	if timeConfigured != 0 && timeConfigured != len(timeValues) {
		return fmt.Errorf("%w: partial trusted-time configuration", ErrInvalid)
	}
	if timeConfigured != 0 && (config.EnrollmentStoreFile == "" ||
		len(config.TimeSigningKID) > 64 || config.TimeUncertainty < 0 ||
		config.TimeUncertainty > time.Hour) {
		return fmt.Errorf("%w: trusted-time configuration", ErrInvalid)
	}
	enrollmentValues := []string{
		config.EnrollmentBundleFile,
		config.EnrollmentRecipientKeyFile,
		config.EnrollmentRecipientKID,
		config.EnrollmentSigningKeyFile,
		config.EnrollmentSigningKID,
	}
	enrollmentConfigured := 0
	for _, value := range enrollmentValues {
		if value != "" {
			enrollmentConfigured++
		}
	}
	if enrollmentConfigured != 0 && enrollmentConfigured != len(enrollmentValues) {
		return fmt.Errorf("%w: partial enrollment configuration", ErrInvalid)
	}
	if enrollmentConfigured != 0 && config.EnrollmentStoreFile == "" {
		return fmt.Errorf("%w: enrollment store missing", ErrInvalid)
	}
	attestationValues := []string{
		config.AttestationRecipientKeyFile,
		config.AttestationRecipientKID,
		config.AttestationSigningKeyFile,
		config.AttestationSigningKID,
		config.AttestationReceiptSigningKeyFile,
		config.AttestationReceiptSigningKID,
	}
	attestationConfigured := 0
	for _, value := range attestationValues {
		if value != "" {
			attestationConfigured++
		}
	}
	if attestationConfigured != 0 && attestationConfigured != len(attestationValues) {
		return fmt.Errorf("%w: partial attestation configuration", ErrInvalid)
	}
	if attestationConfigured != 0 && (config.EnrollmentStoreFile == "" ||
		len(config.AttestationRecipientKID) > 64 || len(config.AttestationSigningKID) > 64 ||
		len(config.AttestationReceiptSigningKID) > 64 || config.DeploymentBundleFile == "" ||
		timeConfigured != len(timeValues) ||
		!distinctPaths([]string{config.AttestationRecipientKeyFile, config.AttestationSigningKeyFile, config.AttestationReceiptSigningKeyFile, config.TimeSigningKeyFile})) {
		return fmt.Errorf("%w: attestation deployment configuration", ErrInvalid)
	}
	if attestationConfigured == 0 && config.DeploymentBundleFile != "" {
		return fmt.Errorf("%w: deployment bundle without attestation", ErrInvalid)
	}
	if enrollmentConfigured == 0 && config.EnrollmentStoreFile != "" && timeConfigured == 0 &&
		attestationConfigured == 0 && !config.RecoveryEnabled() {
		return fmt.Errorf("%w: unused enrollment store", ErrInvalid)
	}
	if enrollmentConfigured == 0 && config.EKRootsFile != "" {
		return fmt.Errorf("%w: EK roots without enrollment", ErrInvalid)
	}
	if enrollmentConfigured != 0 && (len(config.EnrollmentRecipientKID) > 64 ||
		len(config.EnrollmentSigningKID) > 64 ||
		config.EnrollmentRecipientKeyFile == config.EnrollmentSigningKeyFile) {
		return fmt.Errorf("%w: enrollment key separation", ErrInvalid)
	}
	if timeConfigured != 0 && config.TimeSigningKeyFile == config.EnrollmentSigningKeyFile {
		return fmt.Errorf("%w: service key separation", ErrInvalid)
	}
	recoveryConfigured := config.recoveryConfigured()
	if recoveryConfigured && !config.RecoveryEnabled() {
		return fmt.Errorf("%w: partial recovery configuration", ErrInvalid)
	}
	if !distinctPaths(config.serviceKeyPaths()) {
		return fmt.Errorf("%w: service key separation", ErrInvalid)
	}
	if recoveryConfigured && (config.EnrollmentStoreFile == "" ||
		!validRecoveryDigest(config.RecoveryArtifactSHA256) ||
		config.RecoveryMinimumVersion > config.RecoveryTargetVersion ||
		len(config.RecoveryPolicyKID) > 64 || len(config.RecoveryManifestSigningKID) > 64 ||
		!boundedRecoveryDuration(config.RecoveryValidityLead, time.Hour) ||
		!boundedRecoveryDuration(config.RecoveryValidityTrailing, time.Hour) ||
		!boundedRecoveryDuration(config.RecoveryTransferTimeout, 60*time.Minute) ||
		!distinctPaths(config.recoveryKeyPaths())) {
		return fmt.Errorf("%w: recovery configuration", ErrInvalid)
	}
	return nil
}

func (config Config) recoveryConfigured() bool {
	return config.RecoveryRepository != "" || config.RecoveryArtifactSHA256 != "" ||
		config.RecoveryTargetVersion != 0 || config.RecoveryMinimumVersion != 0 ||
		config.RecoveryPolicyAuthorizationFile != "" || config.RecoveryPolicyPublicKeyFile != "" ||
		config.RecoveryPolicyKID != "" || config.RecoveryManifestSigningKeyFile != "" ||
		config.RecoveryManifestSigningKID != "" || config.RecoverySecureBootPublicKeyFile != "" ||
		config.RecoveryValidityLead != 0 || config.RecoveryValidityTrailing != 0 ||
		config.RecoveryTransferTimeout != 0
}

func validRecoveryDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func boundedRecoveryDuration(value, maximum time.Duration) bool {
	return value >= time.Second && value <= maximum
}

func distinctPaths(paths []string) bool {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, exists := seen[path]; exists {
			return false
		}
		seen[path] = struct{}{}
	}
	return true
}

func (config Config) recoveryKeyPaths() []string {
	return config.serviceKeyPaths()
}

func (config Config) serviceKeyPaths() []string {
	return []string{
		config.RecoveryManifestSigningKeyFile, config.RecoveryPolicyPublicKeyFile,
		config.RecoverySecureBootPublicKeyFile, config.EnrollmentRecipientKeyFile,
		config.EnrollmentSigningKeyFile, config.AttestationRecipientKeyFile,
		config.AttestationSigningKeyFile, config.AttestationReceiptSigningKeyFile,
		config.TimeSigningKeyFile, config.TLSCertFile, config.TLSKeyFile,
	}
}

func (config Config) TimeEnabled() bool {
	return config.EnrollmentStoreFile != "" && config.TimeSigningKeyFile != "" &&
		config.TimeSigningKID != "" && config.TimeQuality != ""
}

func (config Config) RecoveryEnabled() bool {
	return config.RecoveryRepository != "" && validRecoveryDigest(config.RecoveryArtifactSHA256) &&
		config.RecoveryTargetVersion > 0 && config.RecoveryPolicyAuthorizationFile != "" &&
		config.RecoveryPolicyPublicKeyFile != "" && config.RecoveryPolicyKID != "" &&
		config.RecoveryManifestSigningKeyFile != "" && config.RecoveryManifestSigningKID != "" &&
		config.RecoverySecureBootPublicKeyFile != "" && config.RecoveryValidityLead != 0 &&
		config.RecoveryValidityTrailing != 0 && config.RecoveryTransferTimeout != 0
}

func (config Config) EnrollmentEnabled() bool {
	return config.EnrollmentStoreFile != "" && config.EnrollmentBundleFile != "" && config.EnrollmentRecipientKeyFile != "" &&
		config.EnrollmentRecipientKID != "" && config.EnrollmentSigningKeyFile != "" &&
		config.EnrollmentSigningKID != ""
}

func (config Config) AttestationEnabled() bool {
	return config.EnrollmentStoreFile != "" && config.DeploymentBundleFile != "" && config.TimeEnabled() &&
		config.AttestationRecipientKeyFile != "" && config.AttestationRecipientKID != "" &&
		config.AttestationSigningKeyFile != "" && config.AttestationSigningKID != "" &&
		config.AttestationReceiptSigningKeyFile != "" && config.AttestationReceiptSigningKID != ""
}

func tlsConfig(certificate tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		CipherSuites: tlsprofile.TLS12CipherSuites(),
		NextProtos:   []string{"pbns/1"},
	}
}

func (config Config) TLSConfig() (*tls.Config, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate/key pair", ErrTLSCredentials)
	}
	return tlsConfig(certificate), nil
}

// TLSConfigWithCertificate preserves the exact accepted TLS profile while
// installing the already securely loaded and deployment-matched certificate.
func (config Config) TLSConfigWithCertificate(certificate *tls.Certificate) (*tls.Config, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if certificate == nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, ErrTLSCredentials
	}
	return tlsConfig(*certificate), nil
}

func Parse(arguments []string) (Config, error) {
	config := Default()
	flags := flag.NewFlagSet("pbns-gateway", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.ListenAddress, "listen", config.ListenAddress, "TCP listen address")
	flags.StringVar(&config.TLSCertFile, "tls-cert", "", "TLS certificate PEM")
	flags.StringVar(&config.TLSKeyFile, "tls-key", "", "TLS private-key PEM")
	flags.StringVar(&config.DeploymentBundleFile, "deployment-bundle", "", "canonical public deployment trust bundle")
	flags.StringVar(&config.EnrollmentBundleFile, "enrollment-bundle", "", "canonical public enrollment trust bundle")
	flags.DurationVar(
		&config.HandshakeTimeout,
		"handshake-timeout",
		config.HandshakeTimeout,
		"TLS handshake timeout",
	)
	flags.DurationVar(&config.ReadTimeout, "read-timeout", config.ReadTimeout, "frame read timeout")
	flags.DurationVar(&config.WriteTimeout, "write-timeout", config.WriteTimeout, "frame write timeout")
	flags.IntVar(
		&config.MaxConnections,
		"max-connections",
		config.MaxConnections,
		"maximum concurrent TLS connections",
	)
	flags.StringVar(&config.EnrollmentStoreFile, "enrollment-store", "", "enrollment database")
	flags.StringVar(
		&config.EnrollmentRecipientKeyFile,
		"enrollment-recipient-key",
		"",
		"enrollment ECDH recipient private key",
	)
	flags.StringVar(
		&config.EnrollmentRecipientKID,
		"enrollment-recipient-kid",
		"",
		"enrollment ECDH recipient key identifier",
	)
	flags.StringVar(
		&config.EnrollmentSigningKeyFile,
		"enrollment-signing-key",
		"",
		"enrollment signing private key",
	)
	flags.StringVar(
		&config.EnrollmentSigningKID,
		"enrollment-signing-kid",
		"",
		"enrollment signing key identifier",
	)
	flags.StringVar(&config.EKRootsFile, "ek-roots", "", "EK manufacturer root bundle")
	flags.StringVar(&config.AttestationRecipientKeyFile, "attestation-recipient-key", "", "attestation ECDH recipient private key")
	flags.StringVar(&config.AttestationRecipientKID, "attestation-recipient-kid", "", "attestation ECDH recipient key identifier")
	flags.StringVar(&config.AttestationSigningKeyFile, "attestation-signing-key", "", "attestation challenge signing private key")
	flags.StringVar(&config.AttestationSigningKID, "attestation-signing-kid", "", "attestation challenge signing key identifier")
	flags.StringVar(&config.AttestationReceiptSigningKeyFile, "attestation-receipt-signing-key", "", "attestation receipt signing private key")
	flags.StringVar(&config.AttestationReceiptSigningKID, "attestation-receipt-signing-kid", "", "attestation receipt signing key identifier")
	flags.StringVar(
		&config.TimeSigningKeyFile,
		"time-signing-key",
		"",
		"trusted-time signing private key",
	)
	flags.StringVar(&config.TimeSigningKID, "time-signing-kid", "", "trusted-time key identifier")
	flags.DurationVar(&config.TimeUncertainty, "time-uncertainty", 0, "trusted-time uncertainty")
	flags.StringVar(&config.TimeQuality, "time-quality", "", "trusted-time source quality")
	flags.StringVar(&config.RecoveryRepository, "recovery-repository", "", "recovery artifact repository")
	flags.StringVar(&config.RecoveryArtifactSHA256, "recovery-artifact-sha256", "", "active recovery artifact SHA-256")
	flags.Uint64Var(&config.RecoveryTargetVersion, "recovery-target-version", 0, "active recovery target version")
	flags.Uint64Var(&config.RecoveryMinimumVersion, "recovery-minimum-version", 0, "minimum accepted recovery version")
	flags.StringVar(&config.RecoveryPolicyAuthorizationFile, "recovery-policy-authorization", "", "recovery policy authorization")
	flags.StringVar(&config.RecoveryPolicyPublicKeyFile, "recovery-policy-public-key", "", "recovery policy public key PEM")
	flags.StringVar(&config.RecoveryPolicyKID, "recovery-policy-kid", "", "recovery policy key identifier")
	flags.StringVar(&config.RecoveryManifestSigningKeyFile, "recovery-manifest-signing-key", "", "mode-0600 recovery manifest signing key PEM")
	flags.StringVar(&config.RecoveryManifestSigningKID, "recovery-manifest-signing-kid", "", "recovery manifest signing key identifier")
	flags.StringVar(&config.RecoverySecureBootPublicKeyFile, "recovery-secureboot-public-key", "", "Secure Boot public key or certificate PEM")
	flags.DurationVar(&config.RecoveryValidityLead, "recovery-validity-lead", 0, "recovery manifest validity lead")
	flags.DurationVar(&config.RecoveryValidityTrailing, "recovery-validity-trailing", 0, "recovery manifest validity trailing")
	flags.DurationVar(&config.RecoveryTransferTimeout, "recovery-transfer-timeout", 0, "recovery transfer timeout")
	if err := flags.Parse(arguments); err != nil {
		return Config{}, fmt.Errorf("%w: command line", ErrInvalid)
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("%w: unexpected positional arguments", ErrInvalid)
	}
	visited := make(map[string]bool)
	flags.Visit(func(item *flag.Flag) { visited[item.Name] = true })
	recoveryFlags := []string{
		"recovery-repository", "recovery-artifact-sha256", "recovery-target-version",
		"recovery-minimum-version", "recovery-policy-authorization", "recovery-policy-public-key",
		"recovery-policy-kid", "recovery-manifest-signing-key", "recovery-manifest-signing-kid",
		"recovery-secureboot-public-key", "recovery-validity-lead", "recovery-validity-trailing",
		"recovery-transfer-timeout",
	}
	for _, name := range recoveryFlags {
		if !visited[name] {
			continue
		}
		for _, required := range recoveryFlags {
			if !visited[required] {
				return Config{}, fmt.Errorf("%w: partial recovery command line", ErrInvalid)
			}
		}
		break
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}
