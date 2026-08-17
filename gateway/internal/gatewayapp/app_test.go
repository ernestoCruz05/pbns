package gatewayapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pbns.local/gateway/internal/attestation"
	"pbns.local/gateway/internal/config"
	"pbns.local/gateway/internal/deployment"
	"pbns.local/gateway/internal/enrollmenttrust"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/store"
	"pbns.local/gateway/internal/wire"
)

func configuredHandlers(gatewayConfig config.Config) (map[wire.ServiceID]server.Handler, func(), error) {
	return ConfiguredHandlers(gatewayConfig, Options{})
}

func run(ctx context.Context, arguments []string) error {
	return Run(ctx, arguments, Options{})
}

func TestRunRejectsMissingTLSCredentials(t *testing.T) {
	if err := run(context.Background(), nil); !errors.Is(err, config.ErrTLSCredentials) {
		t.Fatalf("got %v, want ErrTLSCredentials", err)
	}
}

func writeEnrollmentBundle(t *testing.T, directory string, recipient, signer *ecdsa.PrivateKey, recipientKID, signerKID string) string {
	t.Helper()
	bundle := enrollmenttrust.Bundle{
		Domain: enrollmenttrust.Domain, Version: 1,
		Recipient: deployment.PublicKey{KID: []byte(recipientKID), X: recipient.X.FillBytes(make([]byte, 32)), Y: recipient.Y.FillBytes(make([]byte, 32))},
		Signer:    deployment.PublicKey{KID: []byte(signerKID), X: signer.X.FillBytes(make([]byte, 32)), Y: signer.Y.FillBytes(make([]byte, 32))},
	}
	encoded, err := enrollmenttrust.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(directory, "enrollment.cbor")
	if err := os.WriteFile(bundlePath, encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	return bundlePath
}

func enrollmentHandlerConfig(t *testing.T) config.Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientPath := filepath.Join(directory, "recipient.pem")
	signerPath := filepath.Join(directory, "signer.pem")
	if err := keys.SaveECPrivateKey(recipientPath, recipient); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPrivateKey(signerPath, signer); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.EnrollmentStoreFile = filepath.Join(directory, "gateway.db")
	cfg.EnrollmentBundleFile = writeEnrollmentBundle(t, directory, recipient, signer, "recipient-1", "signer-1")
	cfg.EnrollmentRecipientKeyFile = recipientPath
	cfg.EnrollmentRecipientKID = "recipient-1"
	cfg.EnrollmentSigningKeyFile = signerPath
	cfg.EnrollmentSigningKID = "signer-1"
	return cfg
}

func TestConfiguredHandlersInstallEnrollmentOnlyWithMatchedDistinctKeys(t *testing.T) {
	cfg := enrollmentHandlerConfig(t)
	handlers, cleanup, err := configuredHandlers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if handlers[wire.ServiceEnrollment] == nil {
		t.Fatal("enrollment handler missing")
	}
	err = handlers[wire.ServiceEnrollment].Handle(
		context.Background(), wire.Frame{Service: wire.ServiceEnrollment}, nil,
	)
	var protocolError *server.ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code == 17 {
		t.Fatalf("configured enrollment returned %v", err)
	}
}

func TestConfiguredHandlersRejectEnrollmentMismatchBeforeStoreOpen(t *testing.T) {
	cfg := enrollmentHandlerConfig(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.EnrollmentSigningKeyFile); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPrivateKey(cfg.EnrollmentSigningKeyFile, other); err != nil {
		t.Fatal(err)
	}
	if _, cleanup, err := configuredHandlers(cfg); !errors.Is(err, enrollmenttrust.ErrInvalid) || cleanup != nil {
		t.Fatalf("cleanup=%v err=%v", cleanup != nil, err)
	}
	if _, err := os.Stat(cfg.EnrollmentStoreFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("enrollment trust mismatch created store: %v", err)
	}
}

func TestConfiguredHandlersInstallAttestationWithMandatoryTPMVerifier(t *testing.T) {
	cfg := deploymentAttestationConfig(t)
	handlers, cleanup, err := configuredHandlers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, ok := handlers[wire.ServicePlatformAttestation].(*attestation.Handler); !ok {
		t.Fatalf("attestation handler=%T, want *attestation.Handler", handlers[wire.ServicePlatformAttestation])
	}
}

func TestConfiguredHandlersRejectDeploymentKeyKIDAndTLSMismatchBeforeStoreOpen(t *testing.T) {
	for _, name := range []string{"challenge-key", "receipt-kid", "tls"} {
		t.Run(name, func(t *testing.T) {
			cfg := deploymentAttestationConfig(t)
			switch name {
			case "challenge-key":
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(filepath.Dir(cfg.AttestationSigningKeyFile), "wrong-challenge.pem")
				if err := keys.SaveECPrivateKey(path, other); err != nil {
					t.Fatal(err)
				}
				cfg.AttestationSigningKeyFile = path
			case "receipt-kid":
				cfg.AttestationReceiptSigningKID += "-wrong"
			case "tls":
				other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &other.PublicKey, other)
				if err != nil {
					t.Fatal(err)
				}
				cfg.TLSCertFile = filepath.Join(filepath.Dir(cfg.TLSCertFile), "wrong-tls-cert.pem")
				cfg.TLSKeyFile = filepath.Join(filepath.Dir(cfg.TLSKeyFile), "wrong-tls-key.pem")
				privateDER, err := x509.MarshalECPrivateKey(other)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfg.TLSCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cfg.TLSKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, cleanup, err := configuredHandlers(cfg); !errors.Is(err, deployment.ErrInvalid) || cleanup != nil {
				t.Fatalf("cleanup=%v err=%v", cleanup != nil, err)
			}
			if _, err := os.Stat(cfg.EnrollmentStoreFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("deployment mismatch created store: %v", err)
			}
		})
	}
}

func TestPreparedRuntimeSharesExactTLSDeploymentObject(t *testing.T) {
	cfg := deploymentAttestationConfig(t)
	runtime, err := prepareRuntime(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.cleanup()
	if runtime.deployment == nil || len(runtime.tls.Certificates) != 1 ||
		runtime.tls.Certificates[0].PrivateKey != runtime.deployment.TLSCertificate.PrivateKey ||
		!bytes.Equal(runtime.tls.Certificates[0].Certificate[0], runtime.deployment.TLSCertificate.Certificate[0]) {
		t.Fatal("TLS server did not receive exact matched deployment certificate")
	}
}

func deploymentAttestationConfig(t *testing.T) config.Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PBNS test deployment"}, NotBefore: time.Unix(1_600_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsCertPath := filepath.Join(directory, "tls-cert.pem")
	tlsKeyPath := filepath.Join(directory, "tls-key.pem")
	if err := os.WriteFile(tlsCertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsKeyDER, _ := x509.MarshalECPrivateKey(tlsKey)
	if err := os.WriteFile(tlsKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: tlsKeyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := deployment.Bundle{Domain: deployment.Domain, Version: 1, TLSServerName: "127.0.0.1", TLSPublicKeyDER: spki, TLSSPKISHA256: sha256.Sum256(spki)}
	cfg := config.Default()
	cfg.TLSCertFile, cfg.TLSKeyFile = tlsCertPath, tlsKeyPath
	cfg.EnrollmentStoreFile = filepath.Join(directory, "gateway.db")
	cfg.DeploymentBundleFile = filepath.Join(directory, "deployment.cbor")
	for role, item := range map[deployment.Role]struct {
		key  *deployment.PublicKey
		path *string
		kid  *string
	}{
		deployment.RoleTime:      {&bundle.Time, &cfg.TimeSigningKeyFile, &cfg.TimeSigningKID},
		deployment.RoleChallenge: {&bundle.Challenge, &cfg.AttestationSigningKeyFile, &cfg.AttestationSigningKID},
		deployment.RoleRecipient: {&bundle.Recipient, &cfg.AttestationRecipientKeyFile, &cfg.AttestationRecipientKID},
		deployment.RoleReceipt:   {&bundle.Receipt, &cfg.AttestationReceiptSigningKeyFile, &cfg.AttestationReceiptSigningKID},
	} {
		private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, string(role)+"-key.pem")
		if err := keys.SaveECPrivateKey(path, private); err != nil {
			t.Fatal(err)
		}
		kid := "fresh-" + string(role)
		*item.key = deployment.PublicKey{KID: []byte(kid), X: private.X.FillBytes(make([]byte, 32)), Y: private.Y.FillBytes(make([]byte, 32))}
		*item.path, *item.kid = path, kid
	}
	cfg.TimeQuality = "test-synchronized"
	encoded, err := deployment.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.DeploymentBundleFile, encoded, 0o444); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestConfiguredHandlersInstallTrustedTimeWithEnrollmentStore(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	timeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	timePath := filepath.Join(directory, "time.pem")
	if err := keys.SaveECPrivateKey(timePath, timeKey); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.EnrollmentStoreFile = filepath.Join(directory, "gateway.db")
	cfg.TimeSigningKeyFile = timePath
	cfg.TimeSigningKID = "time-1"
	cfg.TimeQuality = "test-synchronized"
	handlers, cleanup, err := configuredHandlers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	err = handlers[wire.ServiceTrustedTime].Handle(
		context.Background(), wire.Frame{Service: wire.ServiceTrustedTime}, nil,
	)
	var protocolError *server.ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code == 17 {
		t.Fatalf("configured trusted time returned %v", err)
	}
}

func recoveryHandlerConfig(t *testing.T) config.Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secureBoot, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.pem")
	policyPath := filepath.Join(directory, "policy.pem")
	secureBootPath := filepath.Join(directory, "secureboot.pem")
	if err := keys.SaveECPrivateKey(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(policyPath, &policy.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(secureBootPath, &secureBoot.PublicKey); err != nil {
		t.Fatal(err)
	}
	authorization, err := recovery.CreateVersionAuthorization(policy, recovery.RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	authorizationPath := filepath.Join(directory, "policy.cbor")
	if err := os.WriteFile(authorizationPath, authorization, 0o644); err != nil {
		t.Fatal(err)
	}
	repositoryPath := filepath.Join(directory, "repository")
	repository, err := recovery.OpenRepository(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	artifactSource := filepath.Join(directory, "recovery.efi")
	if err := os.WriteFile(artifactSource, []byte("active recovery artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := repository.Publish(artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.EnrollmentStoreFile = filepath.Join(directory, "gateway.db")
	cfg.RecoveryRepository = repositoryPath
	cfg.RecoveryArtifactSHA256 = fmt.Sprintf("%x", artifact.Digest)
	cfg.RecoveryTargetVersion = 5
	cfg.RecoveryMinimumVersion = 0
	cfg.RecoveryPolicyAuthorizationFile = authorizationPath
	cfg.RecoveryPolicyPublicKeyFile = policyPath
	cfg.RecoveryPolicyKID = "policy-1"
	cfg.RecoveryManifestSigningKeyFile = manifestPath
	cfg.RecoveryManifestSigningKID = "manifest-1"
	cfg.RecoverySecureBootPublicKeyFile = secureBootPath
	cfg.RecoveryValidityLead = time.Second
	cfg.RecoveryValidityTrailing = time.Second
	cfg.RecoveryTransferTimeout = time.Second
	return cfg
}

// TestRecoveryEndToEndConfiguredHandlerRegistration keeps the integration
// command's gateway-side setup bound to the real immutable recovery handler.
func TestRecoveryEndToEndConfiguredHandlerRegistration(t *testing.T) {
	handlers, cleanup, err := configuredHandlers(config.Default())
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	err = handlers[wire.ServiceRecoveryArtifact].Handle(
		context.Background(), wire.Frame{Service: wire.ServiceRecoveryArtifact}, nil,
	)
	var protocolError *server.ProtocolError
	if !errors.As(err, &protocolError) || protocolError.Code != 17 {
		t.Fatalf("unconfigured recovery returned %v", err)
	}

	handlers, cleanup, err = configuredHandlers(recoveryHandlerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, ok := handlers[wire.ServiceRecoveryArtifact].(*recovery.Service); !ok {
		t.Fatalf("recovery handler=%T, want *recovery.Service", handlers[wire.ServiceRecoveryArtifact])
	}
	err = handlers[wire.ServicePlatformAttestation].Handle(
		context.Background(), wire.Frame{Service: wire.ServicePlatformAttestation}, nil,
	)
	if !errors.As(err, &protocolError) || protocolError.Code != 17 {
		t.Fatalf("attestation returned %v", err)
	}
}

func TestConfiguredHandlersRejectRecoveryActualKeyReuseAndClosesStoreOnFailure(t *testing.T) {
	cfg := recoveryHandlerConfig(t)
	manifest, err := keys.LoadECPrivateKey(cfg.RecoveryManifestSigningKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	policyAuthorization, err := recovery.CreateVersionAuthorization(
		manifest, recovery.RecoveryNVIndex, cfg.RecoveryTargetVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.RecoveryPolicyAuthorizationFile, policyAuthorization, 0o644); err != nil {
		t.Fatal(err)
	}
	policyCopy := filepath.Join(filepath.Dir(cfg.RecoveryPolicyPublicKeyFile), "same-public.pem")
	if err := keys.SaveECPublicKey(policyCopy, &manifest.PublicKey); err != nil {
		t.Fatal(err)
	}
	cfg.RecoveryPolicyPublicKeyFile = policyCopy
	if _, cleanup, err := configuredHandlers(cfg); !errors.Is(err, recovery.ErrKeyReuse) || cleanup != nil {
		t.Fatalf("handlers cleanup=%v err=%v", cleanup != nil, err)
	}
	opened, err := store.Open(cfg.EnrollmentStoreFile, store.DefaultOptions())
	if err != nil {
		t.Fatalf("recovery setup leaked store lock: %v", err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConfiguredHandlersRejectRecoveryActualReuseWithOtherServiceRoles(t *testing.T) {
	for _, role := range []string{"enrollment", "trusted-time"} {
		t.Run(role, func(t *testing.T) {
			cfg := recoveryHandlerConfig(t)
			manifest, err := keys.LoadECPrivateKey(cfg.RecoveryManifestSigningKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			copyPath := filepath.Join(filepath.Dir(cfg.RecoveryManifestSigningKeyFile), role+".pem")
			if err := keys.SaveECPrivateKey(copyPath, manifest); err != nil {
				t.Fatal(err)
			}
			switch role {
			case "enrollment":
				recipient, generateErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if generateErr != nil {
					t.Fatal(generateErr)
				}
				recipientPath := filepath.Join(filepath.Dir(copyPath), "recipient.pem")
				if err := keys.SaveECPrivateKey(recipientPath, recipient); err != nil {
					t.Fatal(err)
				}
				cfg.EnrollmentRecipientKeyFile = recipientPath
				cfg.EnrollmentRecipientKID = "recipient-1"
				cfg.EnrollmentSigningKeyFile = copyPath
				cfg.EnrollmentSigningKID = "enrollment-1"
				cfg.EnrollmentBundleFile = writeEnrollmentBundle(t, filepath.Dir(copyPath), recipient, manifest, "recipient-1", "enrollment-1")
			case "trusted-time":
				cfg.TimeSigningKeyFile = copyPath
				cfg.TimeSigningKID = "time-1"
				cfg.TimeQuality = "test-synchronized"
			}
			if _, cleanup, err := configuredHandlers(cfg); !errors.Is(err, keys.ErrInvalidKey) || cleanup != nil {
				t.Fatalf("handlers cleanup=%v err=%v", cleanup != nil, err)
			}
		})
	}
}

type appCandidateSink struct{}

func (appCandidateSink) WriteCandidate(attestation.BaselineCandidate) error { return nil }

type appReceiptSink struct{}

func (appReceiptSink) WriteReceipt([]byte, [32]byte) error { return nil }

func TestAttestationCheckpointComponentsAreMutuallyExclusive(t *testing.T) {
	options := Options{BaselineCandidateSink: appCandidateSink{}, ReceiptSink: appReceiptSink{}}
	if handlers, cleanup, err := ConfiguredHandlers(deploymentAttestationConfig(t), options); err == nil || handlers != nil || cleanup != nil {
		t.Fatalf("accepted both checkpoint components handlers=%t cleanup=%t err=%v", handlers != nil, cleanup != nil, err)
	}
}

func TestRecoveryWrapperIsExplicitAndRecoveryOnly(t *testing.T) {
	calls := 0
	options := Options{WrapRecovery: func(service *recovery.Service) (server.Handler, error) {
		calls++
		if service == nil {
			t.Fatal("nil recovery service")
		}
		return service, nil
	}}
	handlers, cleanup, err := ConfiguredHandlers(recoveryHandlerConfig(t), options)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if calls != 1 || handlers[wire.ServiceRecoveryArtifact] == nil {
		t.Fatal("recovery wrapper contract changed")
	}

	calls = 0
	handlers, cleanup, err = ConfiguredHandlers(config.Default(), options)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if calls != 0 || handlers[wire.ServiceRecoveryArtifact] == nil {
		t.Fatal("wrapper called without recovery")
	}
}

func TestPlaceholderRegistryCoversEveryService(t *testing.T) {
	handlers := placeholderHandlers()
	services := []wire.ServiceID{
		wire.ServiceTrustedTime,
		wire.ServiceRecoveryArtifact,
		wire.ServicePlatformAttestation,
		wire.ServiceEnrollment,
	}
	for _, service := range services {
		handler := handlers[service]
		if handler == nil {
			t.Fatalf("service %d has no placeholder", service)
		}
		err := handler.Handle(context.Background(), wire.Frame{Service: service}, nil)
		var protocolError *server.ProtocolError
		if !errors.As(err, &protocolError) || protocolError.Code != 17 {
			t.Fatalf("service %d returned %v", service, err)
		}
	}
}
