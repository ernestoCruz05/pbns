package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
)

func runRecoveryPolicy(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || (arguments[0] != "initialize" && arguments[0] != "advance") {
		return errors.New("usage: recovery policy initialize|advance ...")
	}
	operation := arguments[0]
	flags := flag.NewFlagSet("recovery policy "+operation, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var policyPrivatePath string
	var policyPublicPath string
	var manifestPublicPath string
	var secureBootPublicPath string
	var indexText string
	var materialDirectory string
	var outputPath string
	var initialVersion uint64
	var currentVersion uint64
	var targetVersion uint64
	flags.StringVar(&policyPrivatePath, "policy-private-key", "", "mode-0600 P-256 policy key")
	flags.StringVar(&policyPublicPath, "policy-public-key", "", "policy public key")
	flags.StringVar(&manifestPublicPath, "manifest-public-key", "", "manifest public key")
	flags.StringVar(&secureBootPublicPath, "secureboot-public-key", "", "Secure Boot public key")
	flags.StringVar(&indexText, "nv-index", "", "exact TPM recovery NV index")
	flags.StringVar(&materialDirectory, "material-dir", "", "new public tpm2-tools material directory")
	flags.StringVar(&outputPath, "output", "", "new canonical authorization file")
	flags.Uint64Var(&initialVersion, "initial-version", 0, "initial recovery version")
	flags.Uint64Var(&currentVersion, "current-version", 0, "current recovery version")
	flags.Uint64Var(&targetVersion, "target-version", 0, "target recovery version")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("invalid recovery policy arguments")
	}
	if policyPrivatePath == "" || policyPublicPath == "" || manifestPublicPath == "" ||
		secureBootPublicPath == "" || materialDirectory == "" || outputPath == "" ||
		indexText != "0x01801000" {
		return errors.New("recovery policy requires exact key, index, material, and output options")
	}
	if operation == "initialize" {
		if initialVersion == 0 || currentVersion != 0 || targetVersion != 0 {
			return errors.New("initialization requires only a non-zero --initial-version")
		}
	} else if currentVersion == 0 || targetVersion <= currentVersion || initialVersion != 0 {
		return errors.New("advance requires current < target and no initial version")
	}

	privateKey, err := keys.LoadECPrivateKey(policyPrivatePath)
	if err != nil {
		return fmt.Errorf("policy private key: %w", err)
	}
	policyPublicValue, err := loadPublicKeyOrCertificate(policyPublicPath)
	if err != nil {
		return fmt.Errorf("policy public key: %w", err)
	}
	policyPublic, ok := policyPublicValue.(*ecdsa.PublicKey)
	if !ok || !policyPublic.Equal(&privateKey.PublicKey) {
		return errors.New("policy private/public key mismatch")
	}
	manifestPublic, err := loadPublicKeyOrCertificate(manifestPublicPath)
	if err != nil {
		return fmt.Errorf("manifest public key: %w", err)
	}
	secureBootPublic, err := loadPublicKeyOrCertificate(secureBootPublicPath)
	if err != nil {
		return fmt.Errorf("Secure Boot public key: %w", err)
	}
	fingerprints := make([][sha256.Size]byte, 0, 3)
	for _, publicKey := range []any{policyPublic, manifestPublic, secureBootPublic} {
		fingerprint, fingerprintErr := publicKeyFingerprint(publicKey)
		if fingerprintErr != nil {
			return fingerprintErr
		}
		fingerprints = append(fingerprints, fingerprint)
	}
	if fingerprints[0] == fingerprints[1] || fingerprints[0] == fingerprints[2] ||
		fingerprints[1] == fingerprints[2] {
		return errors.New("recovery policy, manifest, and Secure Boot keys must be distinct")
	}

	var encoded []byte
	var authorization recovery.VersionAuthorization
	if operation == "initialize" {
		encoded, err = recovery.CreateInitializationAuthorization(
			privateKey, recovery.RecoveryNVIndex, initialVersion)
		if err == nil {
			authorization, err = recovery.VerifyInitializationAuthorization(
				encoded, policyPublic, recovery.RecoveryNVIndex, false)
		}
	} else {
		encoded, err = recovery.CreateVersionAuthorization(
			privateKey, recovery.RecoveryNVIndex, targetVersion)
		if err == nil {
			authorization, err = recovery.VerifyVersionAuthorization(
				encoded, policyPublic, recovery.RecoveryNVIndex, currentVersion)
		}
	}
	if err != nil {
		return err
	}
	if err := writeNewSyncedFile(outputPath, encoded, 0o644); err != nil {
		return err
	}
	removeOutput := true
	defer func() {
		if removeOutput {
			_ = os.Remove(outputPath)
		}
	}()
	if err := writePolicyMaterial(materialDirectory, policyPublic, authorization); err != nil {
		return err
	}
	removeOutput = false
	digest := sha256.Sum256(encoded)
	result := struct {
		Kind                string `json:"kind"`
		TargetVersion       uint64 `json:"target_version"`
		AuthorizationSHA256 string `json:"authorization_sha256"`
		NVName              string `json:"nv_name"`
		FinalPolicy         string `json:"final_policy"`
	}{
		Kind: operation, TargetVersion: authorization.TargetVersion,
		AuthorizationSHA256: hex.EncodeToString(digest[:]),
		NVName:              hex.EncodeToString(authorization.NVName),
		FinalPolicy:         hex.EncodeToString(authorization.FinalPolicy),
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(result)
}

func publicKeyFingerprint(publicKey any) ([sha256.Size]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return [sha256.Size]byte{}, errors.New("invalid role public key")
	}
	return sha256.Sum256(encoded), nil
}

func writePolicyMaterial(directory string, policyPublic *ecdsa.PublicKey,
	authorization recovery.VersionAuthorization) error {
	if directory == "" || policyPublic == nil {
		return errors.New("invalid policy material directory")
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		return fmt.Errorf("create policy material directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(directory)
		}
	}()
	if err := os.Chmod(directory, 0o755); err != nil {
		return fmt.Errorf("protect policy material directory: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(policyPublic)
	if err != nil {
		return errors.New("marshal policy public key")
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	approval := recovery.PolicyApprovalDigest(
		authorization.ApprovedPolicy, authorization.PolicyRef)
	files := map[string][]byte{
		"target.bin":        authorization.Operand,
		"nv.public":         authorization.NVPublic,
		"nv.name":           authorization.NVName,
		"policy-key.pem":    publicPEM,
		"policy-key.public": authorization.PolicyKeyPublic,
		"policy-key.name":   authorization.PolicyKeyName,
		"policy.ref":        authorization.PolicyRef,
		"write.cphash":      authorization.CPHash,
		"approved.policy":   authorization.ApprovedPolicy,
		"approval.digest":   approval[:],
		"signature.tss":     authorization.Signature,
		"final.policy":      authorization.FinalPolicy,
	}
	for name, content := range files {
		if name != filepath.Base(name) || len(content) == 0 {
			return errors.New("invalid policy material")
		}
		if err := writeNewSyncedFile(filepath.Join(directory, name), content, 0o644); err != nil {
			return err
		}
	}
	if err := syncOutputDirectory(directory); err != nil {
		return err
	}
	for name, expected := range files {
		actual, readErr := os.ReadFile(filepath.Join(directory, name))
		if readErr != nil || !bytes.Equal(actual, expected) {
			return errors.New("policy material reread mismatch")
		}
	}
	complete = true
	return nil
}

func syncOutputDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("sync output directory: %w", errors.Join(syncErr, closeErr))
	}
	return nil
}
