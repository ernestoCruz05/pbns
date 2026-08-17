package gatewayapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"pbns.local/gateway/internal/attestation"
	"pbns.local/gateway/internal/config"
	"pbns.local/gateway/internal/deployment"
	"pbns.local/gateway/internal/enrollment"
	"pbns.local/gateway/internal/enrollmenttrust"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/service"
	"pbns.local/gateway/internal/store"
	timeservice "pbns.local/gateway/internal/time"
	"pbns.local/gateway/internal/wire"
)

type RecoveryWrapper func(*recovery.Service) (server.Handler, error)

type Options struct {
	WrapRecovery          RecoveryWrapper
	BaselineCandidateSink attestation.BaselineCandidateSink
	ReceiptSink           attestation.ReceiptSink
}

func placeholderHandlers() map[wire.ServiceID]server.Handler {
	unimplemented := service.UnimplementedHandler()
	return map[wire.ServiceID]server.Handler{
		wire.ServiceTrustedTime:         unimplemented,
		wire.ServiceRecoveryArtifact:    unimplemented,
		wire.ServicePlatformAttestation: unimplemented,
		wire.ServiceEnrollment:          unimplemented,
	}
}

func deploymentCounterparts(gatewayConfig config.Config) deployment.Counterparts {
	return deployment.Counterparts{
		TLSCertFile: gatewayConfig.TLSCertFile, TLSKeyFile: gatewayConfig.TLSKeyFile,
		PrivateKeyFiles: map[deployment.Role]string{
			deployment.RoleTime:      gatewayConfig.TimeSigningKeyFile,
			deployment.RoleChallenge: gatewayConfig.AttestationSigningKeyFile,
			deployment.RoleRecipient: gatewayConfig.AttestationRecipientKeyFile,
			deployment.RoleReceipt:   gatewayConfig.AttestationReceiptSigningKeyFile,
		},
		KIDs: map[deployment.Role]string{
			deployment.RoleTime:      gatewayConfig.TimeSigningKID,
			deployment.RoleChallenge: gatewayConfig.AttestationSigningKID,
			deployment.RoleRecipient: gatewayConfig.AttestationRecipientKID,
			deployment.RoleReceipt:   gatewayConfig.AttestationReceiptSigningKID,
		},
	}
}

func loadDeployment(gatewayConfig config.Config) (*deployment.Objects, error) {
	if !gatewayConfig.AttestationEnabled() {
		return nil, nil
	}
	return deployment.LoadMatched(gatewayConfig.DeploymentBundleFile, deploymentCounterparts(gatewayConfig))
}

func enrollmentCounterparts(gatewayConfig config.Config) enrollmenttrust.Counterparts {
	return enrollmenttrust.Counterparts{
		RecipientKeyFile: gatewayConfig.EnrollmentRecipientKeyFile,
		RecipientKID:     gatewayConfig.EnrollmentRecipientKID,
		SignerKeyFile:    gatewayConfig.EnrollmentSigningKeyFile,
		SignerKID:        gatewayConfig.EnrollmentSigningKID,
	}
}

func loadEnrollment(gatewayConfig config.Config) (*enrollmenttrust.Objects, error) {
	if !gatewayConfig.EnrollmentEnabled() {
		return nil, nil
	}
	return enrollmenttrust.LoadMatched(gatewayConfig.EnrollmentBundleFile, enrollmentCounterparts(gatewayConfig))
}

func ConfiguredHandlers(gatewayConfig config.Config, options Options) (map[wire.ServiceID]server.Handler, func(), error) {
	objects, err := loadDeployment(gatewayConfig)
	if err != nil {
		return nil, nil, err
	}
	enrollmentObjects, err := loadEnrollment(gatewayConfig)
	if err != nil {
		return nil, nil, err
	}
	return configuredHandlersWithDeployment(gatewayConfig, options, objects, enrollmentObjects)
}

func configuredHandlersWithDeployment(gatewayConfig config.Config, options Options, objects *deployment.Objects, enrollmentObjects *enrollmenttrust.Objects) (map[wire.ServiceID]server.Handler, func(), error) {
	handlers := placeholderHandlers()
	if !gatewayConfig.EnrollmentEnabled() && !gatewayConfig.TimeEnabled() &&
		!gatewayConfig.AttestationEnabled() && !gatewayConfig.RecoveryEnabled() {
		return handlers, func() {}, nil
	}
	if gatewayConfig.AttestationEnabled() && objects == nil {
		return nil, nil, deployment.ErrInvalid
	}
	if options.BaselineCandidateSink != nil && options.ReceiptSink != nil {
		return nil, nil, server.ErrArgument
	}
	if gatewayConfig.EnrollmentEnabled() && enrollmentObjects == nil {
		return nil, nil, enrollmenttrust.ErrInvalid
	}
	database, err := store.Open(gatewayConfig.EnrollmentStoreFile, store.DefaultOptions())
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = database.Close() }
	fail := func(err error) (map[wire.ServiceID]server.Handler, func(), error) {
		cleanup()
		return nil, nil, err
	}
	keyRoles := make([]configuredKey, 0, 9)
	var enrollmentSigningKey *ecdsa.PrivateKey
	if gatewayConfig.EnrollmentEnabled() {
		recipient := enrollmentObjects.Recipient
		enrollmentSigningKey = enrollmentObjects.Signer
		if recipient == nil || enrollmentSigningKey == nil || recipient.PublicKey.Equal(&enrollmentSigningKey.PublicKey) {
			return fail(keys.ErrInvalidKey)
		}
		keyRoles = append(keyRoles,
			configuredKey{role: "enrollment recipient", key: &recipient.PublicKey},
			configuredKey{role: "enrollment", key: &enrollmentSigningKey.PublicKey},
		)
		signer, signerErr := keys.NewPinnedOnlineSigner(
			keys.RoleEnrollment, []byte(gatewayConfig.EnrollmentSigningKID),
			enrollmentSigningKey,
		)
		if signerErr != nil {
			return fail(signerErr)
		}
		var roots *x509.CertPool
		if gatewayConfig.EKRootsFile != "" {
			encoded, readErr := os.ReadFile(gatewayConfig.EKRootsFile)
			if readErr != nil {
				return fail(readErr)
			}
			roots = x509.NewCertPool()
			if !roots.AppendCertsFromPEM(encoded) {
				return fail(enrollment.ErrEKPublic)
			}
		}
		tpmVerifier, verifierErr := enrollment.NewGoAttestationVerifier(rand.Reader)
		if verifierErr != nil {
			return fail(verifierErr)
		}
		enrollmentService, serviceErr := enrollment.NewService(enrollment.Config{
			Store: database, RecipientKey: recipient,
			RecipientKID: []byte(gatewayConfig.EnrollmentRecipientKID), Signer: signer,
			Clock: timeNow, Random: rand.Reader, Activator: tpmVerifier,
			Certifier: tpmVerifier, EKRoots: roots,
		})
		if serviceErr != nil {
			return fail(serviceErr)
		}
		handlers[wire.ServiceEnrollment] = enrollmentService
	}
	if gatewayConfig.AttestationEnabled() {
		recipient := objects.PrivateKeys[deployment.RoleRecipient]
		challengeKey := objects.PrivateKeys[deployment.RoleChallenge]
		receiptKey := objects.PrivateKeys[deployment.RoleReceipt]
		if recipient == nil || challengeKey == nil || receiptKey == nil {
			return fail(deployment.ErrInvalid)
		}
		keyRoles = append(keyRoles,
			configuredKey{role: "attestation recipient", key: &recipient.PublicKey},
			configuredKey{role: "attestation challenge", key: &challengeKey.PublicKey},
			configuredKey{role: "attestation receipt", key: &receiptKey.PublicKey},
		)
		challengeSigner, signerErr := keys.NewPinnedOnlineSigner(keys.RoleAttestation, []byte(gatewayConfig.AttestationSigningKID), challengeKey)
		if signerErr != nil {
			return fail(signerErr)
		}
		receiptSigner, signerErr := keys.NewPinnedOnlineSigner(keys.RoleAttestationReceipt, []byte(gatewayConfig.AttestationReceiptSigningKID), receiptKey)
		if signerErr != nil {
			return fail(signerErr)
		}
		verifier, verifierErr := attestation.NewVerifier(database)
		if verifierErr != nil {
			return fail(verifierErr)
		}
		consumer := attestation.EvidenceConsumer(verifier)
		if options.BaselineCandidateSink != nil {
			consumer = attestation.NewBaselineCandidateVerifier(verifier, options.BaselineCandidateSink)
			if consumer == nil {
				return fail(server.ErrArgument)
			}
		}
		attestationService, serviceErr := attestation.NewService(attestation.Config{
			Store: database, RecipientKey: recipient,
			RecipientKID: []byte(gatewayConfig.AttestationRecipientKID), Signer: challengeSigner,
			Clock: timeNow, Random: rand.Reader, Verifier: consumer,
		})
		if serviceErr != nil {
			return fail(serviceErr)
		}
		handler, handlerErr := attestation.NewHandler(attestationService, verifier, receiptSigner, rand.Reader)
		if handlerErr != nil {
			return fail(handlerErr)
		}
		if options.ReceiptSink != nil {
			checkpointHandler := attestation.NewCheckpointHandler(handler, options.ReceiptSink)
			if checkpointHandler == nil {
				return fail(server.ErrArgument)
			}
			handlers[wire.ServicePlatformAttestation] = checkpointHandler
		} else {
			handlers[wire.ServicePlatformAttestation] = handler
		}
	}
	if gatewayConfig.TimeEnabled() {
		var timeKey *ecdsa.PrivateKey
		var loadErr error
		if objects != nil {
			timeKey = objects.PrivateKeys[deployment.RoleTime]
		} else {
			timeKey, loadErr = keys.LoadECPrivateKey(gatewayConfig.TimeSigningKeyFile)
		}
		if loadErr != nil || timeKey == nil || (enrollmentSigningKey != nil &&
			timeKey.PublicKey.Equal(&enrollmentSigningKey.PublicKey)) {
			return fail(keys.ErrInvalidKey)
		}
		keyRoles = append(keyRoles, configuredKey{role: "trusted-time", key: &timeKey.PublicKey})
		timeSigner, signerErr := keys.NewPinnedOnlineSigner(
			keys.RoleTrustedTime, []byte(gatewayConfig.TimeSigningKID), timeKey,
		)
		if signerErr != nil {
			return fail(signerErr)
		}
		clock, clockErr := timeservice.NewSystemClock(
			gatewayConfig.TimeUncertainty, gatewayConfig.TimeQuality,
		)
		if clockErr != nil {
			return fail(clockErr)
		}
		trustedTime, serviceErr := timeservice.NewService(
			clock, timeservice.StoreHostResolver{Store: database}, timeSigner,
		)
		if serviceErr != nil {
			return fail(serviceErr)
		}
		handlers[wire.ServiceTrustedTime] = timeservice.ServerHandler{Service: trustedTime}
	}
	if gatewayConfig.RecoveryEnabled() {
		recoveryService, recoveryKeys, recoveryErr := newRecoveryService(gatewayConfig, database)
		if recoveryErr != nil {
			return fail(recoveryErr)
		}
		keyRoles = append(keyRoles, recoveryKeys...)
		handler := server.Handler(recoveryService)
		if options.WrapRecovery != nil {
			handler, err = options.WrapRecovery(recoveryService)
			if err != nil || handler == nil {
				if err == nil {
					err = server.ErrArgument
				}
				return fail(err)
			}
		}
		handlers[wire.ServiceRecoveryArtifact] = handler
	}
	if len(keyRoles) > 0 && gatewayConfig.TLSCertFile != "" {
		var tlsPublicKey any
		var tlsErr error
		if objects != nil && objects.TLSCertificate != nil && objects.TLSCertificate.Leaf != nil {
			tlsPublicKey = objects.TLSCertificate.Leaf.PublicKey
		} else {
			tlsPublicKey, tlsErr = loadCertificatePublicKey(gatewayConfig.TLSCertFile)
		}
		if tlsErr != nil {
			return fail(tlsErr)
		}
		if tlsPublicKey == nil {
			return fail(keys.ErrInvalidKey)
		}
		keyRoles = append(keyRoles, configuredKey{role: "TLS", key: tlsPublicKey})
	}
	if err := distinctConfiguredKeys(keyRoles); err != nil {
		return fail(err)
	}
	return handlers, cleanup, nil
}

type configuredKey struct {
	role string
	key  any
}

func distinctConfiguredKeys(configuredKeys []configuredKey) error {
	seen := make(map[[sha256.Size]byte]string, len(configuredKeys))
	for _, configured := range configuredKeys {
		encoded, err := x509.MarshalPKIXPublicKey(configured.key)
		if err != nil {
			return keys.ErrInvalidKey
		}
		fingerprint := sha256.Sum256(encoded)
		if _, exists := seen[fingerprint]; exists {
			return keys.ErrInvalidKey
		}
		seen[fingerprint] = configured.role
	}
	return nil
}

func newRecoveryService(gatewayConfig config.Config, database *store.Store) (*recovery.Service,
	[]configuredKey, error) {
	policyAuthorization, err := readBoundedRegularFile(
		gatewayConfig.RecoveryPolicyAuthorizationFile, 1, 4096,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("recovery policy authorization: %w", err)
	}
	policyPublicKey, err := keys.LoadECPublicKey(gatewayConfig.RecoveryPolicyPublicKeyFile)
	if err != nil {
		return nil, nil, err
	}
	manifestPrivateKey, err := keys.LoadECPrivateKey(gatewayConfig.RecoveryManifestSigningKeyFile)
	if err != nil {
		return nil, nil, err
	}
	manifestSigner, err := keys.NewPinnedOnlineSigner(
		keys.RoleRecoveryManifest, []byte(gatewayConfig.RecoveryManifestSigningKID), manifestPrivateKey,
	)
	if err != nil {
		return nil, nil, err
	}
	secureBootPublicKey, err := loadPublicKeyOrCertificate(gatewayConfig.RecoverySecureBootPublicKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("recovery Secure Boot public key: %w", err)
	}
	repository, err := recovery.OpenRepository(gatewayConfig.RecoveryRepository)
	if err != nil {
		return nil, nil, err
	}
	decodedDigest, err := hex.DecodeString(gatewayConfig.RecoveryArtifactSHA256)
	if err != nil || len(decodedDigest) != sha256.Size {
		return nil, nil, recovery.ErrArtifactID
	}
	var digest [sha256.Size]byte
	copy(digest[:], decodedDigest)
	service, err := recovery.NewService(recovery.ServiceConfig{
		Repository: repository, ArtifactDigest: digest,
		TargetVersion:       gatewayConfig.RecoveryTargetVersion,
		MinimumVersion:      gatewayConfig.RecoveryMinimumVersion,
		PolicyAuthorization: policyAuthorization, PolicyKeyID: []byte(gatewayConfig.RecoveryPolicyKID),
		PolicyPublicKey: policyPublicKey, ManifestSigner: manifestSigner,
		SecureBootImageKey: secureBootPublicKey,
		Hosts:              timeservice.StoreHostResolver{Store: database}, Clock: timeNow,
		ValidityLead:     gatewayConfig.RecoveryValidityLead,
		ValidityTrailing: gatewayConfig.RecoveryValidityTrailing,
		TransferTimeout:  gatewayConfig.RecoveryTransferTimeout,
	})
	if err != nil {
		return nil, nil, err
	}
	return service, []configuredKey{
		{role: "recovery manifest", key: &manifestPrivateKey.PublicKey},
		{role: "recovery policy", key: policyPublicKey},
		{role: "Secure Boot", key: secureBootPublicKey},
	}, nil
}

func readBoundedRegularFile(path string, minimum, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < minimum || info.Size() > maximum {
		return nil, errors.New("invalid regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil || int64(len(encoded)) != info.Size() {
		return nil, errors.New("file changed while reading")
	}
	return encoded, nil
}

func loadPublicKeyOrCertificate(path string) (any, error) {
	encoded, err := readBoundedRegularFile(path, 1, 64*1024)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 {
		return nil, errors.New("invalid PEM")
	}
	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return certificate.PublicKey, nil
	default:
		return nil, errors.New("PEM is not a public key or certificate")
	}
}

func loadCertificatePublicKey(path string) (any, error) {
	encoded, err := readBoundedRegularFile(path, 1, 64*1024)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid TLS certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate.PublicKey, nil
}

var timeNow = func() time.Time { return time.Now() }

type preparedGatewayRuntime struct {
	tls        *tls.Config
	handlers   map[wire.ServiceID]server.Handler
	cleanup    func()
	deployment *deployment.Objects
}

func prepareRuntime(gatewayConfig config.Config, options Options) (*preparedGatewayRuntime, error) {
	objects, err := loadDeployment(gatewayConfig)
	if err != nil {
		return nil, err
	}
	enrollmentObjects, err := loadEnrollment(gatewayConfig)
	if err != nil {
		return nil, err
	}
	var tlsConfig *tls.Config
	if objects != nil {
		tlsConfig, err = gatewayConfig.TLSConfigWithCertificate(objects.TLSCertificate)
	} else {
		tlsConfig, err = gatewayConfig.TLSConfig()
	}
	if err != nil {
		return nil, err
	}
	handlers, cleanup, err := configuredHandlersWithDeployment(gatewayConfig, options, objects, enrollmentObjects)
	if err != nil {
		return nil, err
	}
	return &preparedGatewayRuntime{tls: tlsConfig, handlers: handlers, cleanup: cleanup, deployment: objects}, nil
}

func Run(ctx context.Context, arguments []string, options Options) error {
	if ctx == nil {
		return server.ErrArgument
	}
	gatewayConfig, err := config.Parse(arguments)
	if err != nil {
		return err
	}
	runtime, err := prepareRuntime(gatewayConfig, options)
	if err != nil {
		return err
	}
	defer runtime.cleanup()
	instance, err := server.New(server.Config{
		TLS:              runtime.tls,
		Handlers:         runtime.handlers,
		Limits:           gatewayConfig.Limits,
		HandshakeTimeout: gatewayConfig.HandshakeTimeout,
		ReadTimeout:      gatewayConfig.ReadTimeout,
		WriteTimeout:     gatewayConfig.WriteTimeout,
		MaxConnections:   gatewayConfig.MaxConnections,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", gatewayConfig.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for PBNS TLS: %w", err)
	}
	defer listener.Close()
	return instance.Serve(ctx, listener)
}
