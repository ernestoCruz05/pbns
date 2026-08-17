package recovery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
)

type recoveryServiceFixture struct {
	config           ServiceConfig
	artifact         Artifact
	manifestKey      *ecdsa.PrivateKey
	policyKey        *ecdsa.PrivateKey
	secureBootKey    any
	manifestKeyID    []byte
	policyKeyID      []byte
	policyAuth       []byte
	request          Request
	manifestVerifier cose.Verifier
	hostSigner       cose.Signer
	content          []byte
}

func loadFixturePublicKey(t *testing.T, name string) any {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "keys", name))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid public key fixture")
	}
	if block.Type == "CERTIFICATE" {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return certificate.PublicKey
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}

func newRecoveryServiceFixture(t *testing.T) recoveryServiceFixture {
	t.Helper()
	return newRecoveryServiceFixtureWithContent(
		t, bytes.Repeat([]byte("PBNS-active-recovery-image"), 700),
	)
}

func newRecoveryServiceFixtureWithContent(t *testing.T, content []byte) recoveryServiceFixture {
	t.Helper()
	repository, err := OpenRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content = append([]byte(nil), content...)
	artifact, err := repository.Publish(writeArtifact(t, t.TempDir(), "recovery.efi", content))
	if err != nil {
		t.Fatal(err)
	}
	manifestKey := recoveryTestPrivateKey(t, "recovery-manifest-test-private.pem")
	policyKey := recoveryTestPrivateKey(t, "recovery-policy-test-private.pem")
	manifestKeyID := []byte("recovery-manifest-key-1")
	policyKeyID := []byte("recovery-policy-key-1")
	manifestSigner, err := keys.NewPinnedOnlineSigner(
		keys.RoleRecoveryManifest, manifestKeyID, manifestKey)
	if err != nil {
		t.Fatal(err)
	}
	policyAuth, err := CreateVersionAuthorization(policyKey, RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	_, hostSigner, hostVerifier := requestKeys(t)
	request, _ := loadRecoveryRequestVector(t, "manifest-request.json")
	request.HostFingerprint[0] ^= 0x55
	resolver := fixedHostResolver{fingerprint: request.HostFingerprint, verifier: hostVerifier}
	manifestVerifier, err := cose.NewVerifier(cose.AlgorithmES256, &manifestKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	secureBootKey := loadFixturePublicKey(t, "uki-secureboot-test-cert.pem")
	return recoveryServiceFixture{
		config: ServiceConfig{
			Repository: repository, ArtifactDigest: artifact.Digest,
			TargetVersion: 5, MinimumVersion: 4,
			PolicyAuthorization: policyAuth, PolicyKeyID: policyKeyID,
			PolicyPublicKey: &policyKey.PublicKey, ManifestSigner: manifestSigner,
			SecureBootImageKey: secureBootKey, Hosts: resolver,
			Clock:        func() time.Time { return time.Unix(100, 500).UTC() },
			ValidityLead: 10 * time.Second, ValidityTrailing: 20 * time.Second,
			TransferTimeout: 2 * time.Minute,
		},
		artifact: artifact, manifestKey: manifestKey, policyKey: policyKey,
		secureBootKey: secureBootKey, manifestKeyID: manifestKeyID,
		policyKeyID: policyKeyID, policyAuth: policyAuth, request: request,
		manifestVerifier: manifestVerifier, hostSigner: hostSigner, content: content,
	}
}

func TestRecoveryServiceManifestBindsActivePublicationAndRequest(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := service.Manifest(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	expectation := Expectation{
		RequestID:   fixture.request.RequestID,
		HostBinding: fixture.request.HostFingerprint, Nonce: fixture.request.Nonce,
		RecoverySigningKeyID: fixture.manifestKeyID,
		ExpectedPolicyKeyID:  fixture.policyKeyID, CurrentVersion: 0,
		TrustedEarliestNS: 90_000_000_500, TrustedLatestNS: 120_000_000_500,
	}
	manifest, err := VerifyManifest(signed, fixture.manifestVerifier, expectation)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ArtifactDigest != fixture.artifact.Digest ||
		manifest.ImageSize != fixture.artifact.Size || manifest.ArtifactVersion != 5 ||
		manifest.MinimumVersion != 4 || manifest.NotBeforeNS != 90_000_000_500 ||
		manifest.NotAfterNS != 120_000_000_500 ||
		!bytes.Equal(manifest.PolicyAuthorization, fixture.policyAuth) ||
		!bytes.Equal(manifest.PolicyKeyID, fixture.policyKeyID) {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if manifest.Context.RequestID != fixture.request.RequestID ||
		manifest.Context.HostBinding != fixture.request.HostFingerprint ||
		manifest.Context.Nonce != fixture.request.Nonce {
		t.Fatalf("request binding changed: %#v", manifest.Context)
	}
}

func TestRecoveryServiceConstructorRejectsInvalidPublication(t *testing.T) {
	maximum := newRecoveryServiceFixture(t)
	maximum.config.TransferTimeout = 60 * time.Minute
	if _, err := NewService(maximum.config); err != nil {
		t.Fatalf("maximum recovery transfer timeout rejected: %v", err)
	}

	for name, change := range map[string]func(*ServiceConfig){
		"repository":      func(config *ServiceConfig) { config.Repository = nil },
		"digest":          func(config *ServiceConfig) { config.ArtifactDigest[0] ^= 1 },
		"target-zero":     func(config *ServiceConfig) { config.TargetVersion = 0 },
		"minimum":         func(config *ServiceConfig) { config.MinimumVersion = 6 },
		"authorization":   func(config *ServiceConfig) { config.PolicyAuthorization = nil },
		"policy-kid":      func(config *ServiceConfig) { config.PolicyKeyID = nil },
		"policy-key":      func(config *ServiceConfig) { config.PolicyPublicKey = nil },
		"manifest-signer": func(config *ServiceConfig) { config.ManifestSigner = nil },
		"secureboot-key":  func(config *ServiceConfig) { config.SecureBootImageKey = nil },
		"hosts":           func(config *ServiceConfig) { config.Hosts = nil },
		"clock":           func(config *ServiceConfig) { config.Clock = nil },
		"lead-zero":       func(config *ServiceConfig) { config.ValidityLead = 0 },
		"lead-large":      func(config *ServiceConfig) { config.ValidityLead = time.Hour + time.Nanosecond },
		"trailing-zero":   func(config *ServiceConfig) { config.ValidityTrailing = 0 },
		"trailing-large":  func(config *ServiceConfig) { config.ValidityTrailing = time.Hour + time.Nanosecond },
		"timeout-zero":    func(config *ServiceConfig) { config.TransferTimeout = 0 },
		"timeout-large":   func(config *ServiceConfig) { config.TransferTimeout = 60*time.Minute + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecoveryServiceFixture(t)
			change(&fixture.config)
			if _, err := NewService(fixture.config); !errors.Is(err, ErrServiceConfig) {
				t.Fatalf("got %v, want ErrServiceConfig", err)
			}
		})
	}
}

func TestRecoveryServiceRejectsPolicyMismatchAndKeyReuse(t *testing.T) {
	t.Run("malformed-authorization", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		fixture.config.PolicyAuthorization = []byte{0xa0}
		if _, err := NewService(fixture.config); !errors.Is(err, ErrServicePolicy) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("target-mismatch", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		fixture.config.TargetVersion = 6
		if _, err := NewService(fixture.config); !errors.Is(err, ErrServicePolicy) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong-policy-key", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		wrong, err := ecdsa.GenerateKey(fixture.policyKey.Curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fixture.config.PolicyPublicKey = &wrong.PublicKey
		if _, err := NewService(fixture.config); !errors.Is(err, ErrServicePolicy) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong-manifest-role", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		signer, err := keys.NewPinnedOnlineSigner(
			keys.RoleTrustedTime, fixture.manifestKeyID, fixture.manifestKey)
		if err != nil {
			t.Fatal(err)
		}
		fixture.config.ManifestSigner = signer
		if _, err := NewService(fixture.config); !errors.Is(err, keys.ErrRole) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("manifest-secureboot-reuse", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		fixture.config.SecureBootImageKey = &fixture.manifestKey.PublicKey
		if _, err := NewService(fixture.config); !errors.Is(err, ErrKeyReuse) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("manifest-policy-reuse", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		authorization, err := CreateVersionAuthorization(fixture.manifestKey, RecoveryNVIndex, 5)
		if err != nil {
			t.Fatal(err)
		}
		fixture.config.PolicyAuthorization = authorization
		fixture.config.PolicyPublicKey = &fixture.manifestKey.PublicKey
		if _, err := NewService(fixture.config); !errors.Is(err, ErrKeyReuse) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("policy-secureboot-reuse", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		fixture.config.SecureBootImageKey = &fixture.policyKey.PublicKey
		if _, err := NewService(fixture.config); !errors.Is(err, ErrKeyReuse) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRecoveryManifestFixtureIsRoleDistinct(t *testing.T) {
	fixtures := []string{
		"recovery-manifest-test-public.pem",
		"recovery-policy-test-public.pem",
		"service-signing-test-public.pem",
		"enrollment-signing-test-public.pem",
		"tls-gateway-test-cert.pem",
		"uki-secureboot-test-cert.pem",
	}
	seen := make(map[[sha256.Size]byte]string)
	for _, name := range fixtures {
		publicKey := loadFixturePublicKey(t, name)
		encoded, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint := sha256.Sum256(encoded)
		if previous, exists := seen[fingerprint]; exists {
			t.Fatalf("fixtures %s and %s reuse one public key", previous, name)
		}
		seen[fingerprint] = name
	}
}

func TestRecoveryServiceCopiesPublicationInputs(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	expectedAuthorization := append([]byte(nil), fixture.policyAuth...)
	expectedPolicyKeyID := append([]byte(nil), fixture.policyKeyID...)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	fixture.config.PolicyAuthorization[0] ^= 0xff
	fixture.config.PolicyKeyID[0] ^= 0xff
	signed, err := service.Manifest(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	expectation := Expectation{
		RequestID:   fixture.request.RequestID,
		HostBinding: fixture.request.HostFingerprint, Nonce: fixture.request.Nonce,
		RecoverySigningKeyID: fixture.manifestKeyID,
		ExpectedPolicyKeyID:  expectedPolicyKeyID,
		TrustedEarliestNS:    90_000_000_500, TrustedLatestNS: 120_000_000_500,
	}
	manifest, err := VerifyManifest(signed, fixture.manifestVerifier, expectation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifest.PolicyAuthorization, expectedAuthorization) ||
		!bytes.Equal(manifest.PolicyKeyID, expectedPolicyKeyID) {
		t.Fatal("service retained caller-owned publication slices")
	}
}

func TestRecoveryServiceManifestRejectsInvalidRequestClockAndArtifact(t *testing.T) {
	t.Run("artifact-operation", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		service, err := NewService(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := loadRecoveryRequestVector(t, "artifact-request.json")
		if _, err := service.Manifest(context.Background(), request); !errors.Is(err, ErrRequest) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cancelled-context", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		service, err := NewService(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := service.Manifest(ctx, fixture.request); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("invalid-clock", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		fixture.config.Clock = func() time.Time { return time.Unix(-1, 0) }
		service, err := NewService(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Manifest(context.Background(), fixture.request); !errors.Is(err, ErrServiceClock) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("artifact-changed", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		service, err := NewService(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		path := fixture.config.Repository.artifactPath(fixture.artifact.Digest)
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Manifest(context.Background(), fixture.request); !errors.Is(err, ErrArtifactChanged) {
			t.Fatalf("got %v", err)
		}
	})
}
