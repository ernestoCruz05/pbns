package recovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"time"

	"pbns.local/gateway/internal/keys"
)

var (
	ErrServiceConfig = errors.New("invalid recovery service configuration")
	ErrServicePolicy = errors.New("invalid recovery service policy")
	ErrServiceClock  = errors.New("invalid recovery service clock")
)

type ServiceConfig struct {
	Repository          *Repository
	ArtifactDigest      [sha256.Size]byte
	TargetVersion       uint64
	MinimumVersion      uint64
	PolicyAuthorization []byte
	PolicyKeyID         []byte
	PolicyPublicKey     *ecdsa.PublicKey
	ManifestSigner      *keys.AuthorizedSigner
	SecureBootImageKey  any
	Hosts               HostResolver
	Clock               func() time.Time
	ValidityLead        time.Duration
	ValidityTrailing    time.Duration
	TransferTimeout     time.Duration
}

type Service struct {
	repository          *Repository
	artifact            Artifact
	targetVersion       uint64
	minimumVersion      uint64
	policyAuthorization []byte
	policyKeyID         []byte
	manifestSigner      *keys.AuthorizedSigner
	hosts               HostResolver
	clock               func() time.Time
	validityLead        time.Duration
	validityTrailing    time.Duration
	transferTimeout     time.Duration
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.Repository == nil || config.TargetVersion == 0 ||
		config.MinimumVersion > config.TargetVersion || len(config.PolicyAuthorization) == 0 ||
		len(config.PolicyAuthorization) > maximumPolicySize || len(config.PolicyKeyID) == 0 ||
		len(config.PolicyKeyID) > maximumKeyIDSize || config.PolicyPublicKey == nil ||
		config.ManifestSigner == nil || config.SecureBootImageKey == nil ||
		config.Hosts == nil || config.Clock == nil ||
		!boundedDuration(config.ValidityLead, time.Hour) ||
		!boundedDuration(config.ValidityTrailing, time.Hour) ||
		!boundedDuration(config.TransferTimeout, 60*time.Minute) {
		return nil, ErrServiceConfig
	}
	if err := config.ManifestSigner.RequireRole(keys.RoleRecoveryManifest); err != nil {
		return nil, err
	}
	authorization, err := VerifyVersionAuthorization(
		config.PolicyAuthorization, config.PolicyPublicKey, RecoveryNVIndex, 0,
	)
	if err != nil || authorization.TargetVersion != config.TargetVersion {
		return nil, ErrServicePolicy
	}
	manifestFingerprint := config.ManifestSigner.PublicKeyFingerprint()
	policyFingerprint, err := publicKeyFingerprint(config.PolicyPublicKey)
	if err != nil {
		return nil, ErrServicePolicy
	}
	secureBootFingerprint, err := publicKeyFingerprint(config.SecureBootImageKey)
	if err != nil {
		return nil, ErrServiceConfig
	}
	if manifestFingerprint == policyFingerprint ||
		manifestFingerprint == secureBootFingerprint ||
		policyFingerprint == secureBootFingerprint {
		return nil, ErrKeyReuse
	}
	file, artifact, err := config.Repository.OpenArtifact(config.ArtifactDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: open active recovery artifact: %v", ErrServiceConfig, err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("%w: close active recovery artifact", ErrServiceConfig)
	}
	return &Service{
		repository: config.Repository, artifact: artifact,
		targetVersion: config.TargetVersion, minimumVersion: config.MinimumVersion,
		policyAuthorization: append([]byte(nil), config.PolicyAuthorization...),
		policyKeyID:         append([]byte(nil), config.PolicyKeyID...),
		manifestSigner:      config.ManifestSigner, hosts: config.Hosts, clock: config.Clock,
		validityLead: config.ValidityLead, validityTrailing: config.ValidityTrailing,
		transferTimeout: config.TransferTimeout,
	}, nil
}

func boundedDuration(value, maximum time.Duration) bool {
	return value >= time.Second && value <= maximum
}

func publicKeyFingerprint(publicKey any) ([sha256.Size]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (service *Service) Manifest(ctx context.Context, request Request) ([]byte, error) {
	if service == nil || ctx == nil || !request.valid() ||
		request.Operation != OperationManifest {
		return nil, ErrRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, artifact, err := service.repository.OpenArtifact(service.artifact.Digest)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, ErrArtifactChanged
	}
	if artifact != service.artifact {
		return nil, ErrArtifactChanged
	}
	nowNS, err := validUnixNanoseconds(service.clock().UTC())
	if err != nil || nowNS < service.validityLead.Nanoseconds() ||
		nowNS > math.MaxInt64-service.validityTrailing.Nanoseconds() {
		return nil, ErrServiceClock
	}
	notBefore := nowNS - service.validityLead.Nanoseconds()
	notAfter := nowNS + service.validityTrailing.Nanoseconds()
	manifest := Manifest{
		Context: CommonContext{
			Domain: Domain, Version: Version, Service: ServiceRecoveryArtifact,
			RequestID: request.RequestID, HostBinding: request.HostFingerprint,
			Nonce: request.Nonce, IssuedAtNS: notBefore, ExpiresAtNS: notAfter,
			Body: []byte{},
		},
		ArtifactDigest: artifact.Digest, ArtifactVersion: service.targetVersion,
		Architecture: ArchitectureX8664, Format: FormatUKIPECOFF,
		ImageSize: artifact.Size, ChunkSize: ChunkSize,
		MinimumVersion: service.minimumVersion,
		NotBeforeNS:    notBefore, NotAfterNS: notAfter,
		PolicyAuthorization: append([]byte(nil), service.policyAuthorization...),
		PolicyKeyID:         append([]byte(nil), service.policyKeyID...),
	}
	return SignManifest(manifest, service.manifestSigner)
}

func validUnixNanoseconds(value time.Time) (int64, error) {
	seconds := value.Unix()
	nanoseconds := int64(value.Nanosecond())
	if seconds < 0 || seconds > (math.MaxInt64-nanoseconds)/1_000_000_000 {
		return 0, ErrServiceClock
	}
	return seconds*1_000_000_000 + nanoseconds, nil
}
