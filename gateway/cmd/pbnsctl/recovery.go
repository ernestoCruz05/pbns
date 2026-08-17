package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
)

func runRecovery(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: recovery publish|policy ...")
	}
	switch arguments[0] {
	case "publish":
		return runRecoveryPublish(arguments[1:], stdout)
	case "policy":
		return runRecoveryPolicy(arguments[1:], stdout)
	default:
		return errors.New("usage: recovery publish|policy ...")
	}
}

func runRecoveryPublish(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("recovery publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var artifactPath string
	var repositoryPath string
	var requestIDHex string
	var hostBindingHex string
	var nonceHex string
	var notBeforeText string
	var notAfterText string
	var policyAuthorizationPath string
	var policyKeyID string
	var manifestPrivateKeyPath string
	var manifestKeyID string
	var secureBootPublicKeyPath string
	var outputPath string
	var version uint64
	var minimumVersion uint64
	flags.StringVar(&artifactPath, "artifact", "", "recovery UKI")
	flags.StringVar(&repositoryPath, "repository", "", "immutable artifact repository")
	flags.StringVar(&requestIDHex, "request-id", "", "16-byte request identifier in hex")
	flags.StringVar(&hostBindingHex, "host-binding", "", "32-byte host binding in hex")
	flags.StringVar(&nonceHex, "nonce", "", "32-byte request nonce in hex")
	flags.StringVar(&notBeforeText, "not-before", "", "RFC3339Nano lower validity bound")
	flags.StringVar(&notAfterText, "not-after", "", "RFC3339Nano upper validity bound")
	flags.StringVar(&policyAuthorizationPath, "policy-authorization", "", "TPM policy authorization")
	flags.StringVar(&policyKeyID, "policy-key-id", "", "recovery policy key identifier")
	flags.StringVar(&manifestPrivateKeyPath, "manifest-private-key", "", "mode-0600 P-256 manifest key")
	flags.StringVar(&manifestKeyID, "manifest-key-id", "", "manifest signing key identifier")
	flags.StringVar(&secureBootPublicKeyPath, "secureboot-public-key", "", "Secure Boot public key or certificate")
	flags.StringVar(&outputPath, "output", "", "new signed manifest file")
	flags.Uint64Var(&version, "version", 0, "monotonic artifact version")
	flags.Uint64Var(&minimumVersion, "minimum-version", 0, "minimum accepted artifact version")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid recovery publish arguments")
	}
	if artifactPath == "" || repositoryPath == "" || notBeforeText == "" ||
		notAfterText == "" || policyAuthorizationPath == "" || policyKeyID == "" ||
		manifestPrivateKeyPath == "" || manifestKeyID == "" ||
		secureBootPublicKeyPath == "" || outputPath == "" || version == 0 {
		return errors.New("recovery publish requires every key, binding, policy, time, repository, and output option")
	}
	requestID, err := decodeFixedHex(requestIDHex, 16)
	if err != nil {
		return fmt.Errorf("request id: %w", err)
	}
	hostBinding, err := decodeFixedHex(hostBindingHex, 32)
	if err != nil {
		return fmt.Errorf("host binding: %w", err)
	}
	nonce, err := decodeFixedHex(nonceHex, 32)
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	notBefore, err := parseManifestTime(notBeforeText)
	if err != nil {
		return fmt.Errorf("not-before: %w", err)
	}
	notAfter, err := parseManifestTime(notAfterText)
	if err != nil || notBefore >= notAfter {
		return errors.New("invalid recovery manifest validity interval")
	}
	policyAuthorization, err := readBoundedRegularFile(policyAuthorizationPath, 1, 4096)
	if err != nil {
		return fmt.Errorf("policy authorization: %w", err)
	}
	privateKey, err := keys.LoadECPrivateKey(manifestPrivateKeyPath)
	if err != nil {
		return fmt.Errorf("manifest private key: %w", err)
	}
	signer, err := keys.NewPinnedOnlineSigner(
		keys.RoleRecoveryManifest, []byte(manifestKeyID), privateKey)
	if err != nil {
		return err
	}
	secureBootPublicKey, err := loadPublicKeyOrCertificate(secureBootPublicKeyPath)
	if err != nil {
		return fmt.Errorf("Secure Boot public key: %w", err)
	}
	repository, err := recovery.OpenRepository(repositoryPath)
	if err != nil {
		return err
	}
	publisher, err := recovery.NewPublisher(repository, signer, secureBootPublicKey)
	if err != nil {
		return err
	}
	manifest := recovery.Manifest{
		Context: recovery.CommonContext{
			Domain: recovery.Domain, Version: recovery.Version,
			Service:    recovery.ServiceRecoveryArtifact,
			IssuedAtNS: notBefore, ExpiresAtNS: notAfter, Body: []byte{},
		},
		ArtifactVersion: version, Architecture: recovery.ArchitectureX8664,
		Format: recovery.FormatUKIPECOFF, ChunkSize: recovery.ChunkSize,
		MinimumVersion: minimumVersion, NotBeforeNS: notBefore, NotAfterNS: notAfter,
		PolicyAuthorization: policyAuthorization, PolicyKeyID: []byte(policyKeyID),
	}
	copy(manifest.Context.RequestID[:], requestID)
	copy(manifest.Context.HostBinding[:], hostBinding)
	copy(manifest.Context.Nonce[:], nonce)
	publication, err := publisher.Publish(artifactPath, manifest)
	if err != nil {
		return err
	}
	if err := writeNewSyncedFile(outputPath, publication.Signed, 0o644); err != nil {
		return err
	}
	result := struct {
		ArtifactSHA256 string `json:"artifact_sha256"`
		ArtifactSize   uint64 `json:"artifact_size"`
		ManifestPath   string `json:"manifest_path"`
		Version        uint64 `json:"version"`
	}{
		ArtifactSHA256: hex.EncodeToString(publication.Artifact.Digest[:]),
		ArtifactSize:   publication.Artifact.Size, ManifestPath: outputPath,
		Version: publication.Manifest.ArtifactVersion,
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func decodeFixedHex(encoded string, size int) ([]byte, error) {
	if len(encoded) != size*2 {
		return nil, errors.New("wrong encoded length")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || hex.EncodeToString(decoded) != encoded {
		return nil, errors.New("value must be lowercase hexadecimal")
	}
	var combined byte
	for _, value := range decoded {
		combined |= value
	}
	if combined == 0 {
		return nil, errors.New("all-zero value")
	}
	return decoded, nil
}

func parseManifestTime(encoded string) (int64, error) {
	value, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil || value.Unix() < 0 {
		return 0, errors.New("invalid RFC3339Nano time")
	}
	seconds := value.Unix()
	if seconds > (int64(^uint64(0)>>1)-int64(value.Nanosecond()))/1_000_000_000 {
		return 0, errors.New("time outside nanosecond range")
	}
	return seconds*1_000_000_000 + int64(value.Nanosecond()), nil
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

func writeNewSyncedFile(path string, content []byte, mode os.FileMode) error {
	if path == "" || len(content) == 0 {
		return errors.New("invalid output file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create signed manifest: %w", err)
	}
	writeErr := file.Chmod(mode)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return fmt.Errorf("write signed manifest: %w", errors.Join(writeErr, closeErr))
	}
	return nil
}
