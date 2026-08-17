package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pbns.local/gateway/internal/keys"
)

func runKeys(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return fmt.Errorf("usage: keys root-create|issue ...")
	}
	switch arguments[0] {
	case "root-create":
		return runRootCreate(arguments[1:], output)
	case "issue":
		return runKeyIssue(arguments[1:], output)
	default:
		return fmt.Errorf("unknown keys command")
	}
}

func runRootCreate(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("keys root-create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var offlineDirectory string
	flags.StringVar(&offlineDirectory, "offline-dir", "", "new private offline-root directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || offlineDirectory == "" {
		return fmt.Errorf("usage: keys root-create --offline-dir DIR")
	}
	if err := os.Mkdir(offlineDirectory, 0o700); err != nil {
		return fmt.Errorf("create offline directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(offlineDirectory)
		}
	}()
	if err := os.Chmod(offlineDirectory, 0o700); err != nil {
		return fmt.Errorf("protect offline directory: %w", err)
	}
	root, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate offline root: %w", err)
	}
	privatePath := filepath.Join(offlineDirectory, "root-private.pem")
	publicPath := filepath.Join(offlineDirectory, "root-public.pem")
	if err := keys.SaveECPrivateKey(privatePath, root); err != nil {
		return err
	}
	if err := keys.SaveECPublicKey(publicPath, &root.PublicKey); err != nil {
		return err
	}
	fingerprint, err := publicFingerprint(&root.PublicKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "root_public=%s\nroot_fingerprint=%s\n", publicPath, fingerprint)
	complete = err == nil
	return err
}

func runKeyIssue(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("keys issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var rootPath, onlineDirectory, publicDirectory, roleName, keyID string
	var validFor time.Duration
	flags.StringVar(&rootPath, "offline-root-private", "", "offline root private key")
	flags.StringVar(&onlineDirectory, "online-dir", "", "new private online-key directory")
	flags.StringVar(&publicDirectory, "public-dir", "", "new public pin-bundle directory")
	flags.StringVar(&roleName, "role", "", "online key role")
	flags.StringVar(&keyID, "kid", "", "online key identifier")
	flags.DurationVar(&validFor, "valid-for", 365*24*time.Hour, "certificate validity")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || rootPath == "" ||
		onlineDirectory == "" || publicDirectory == "" || keyID == "" || validFor <= 0 {
		return fmt.Errorf("usage: keys issue --offline-root-private FILE --online-dir DIR --public-dir DIR --role ROLE --kid ID")
	}
	role, err := parseOnlineRole(roleName)
	if err != nil {
		return err
	}
	if directoriesOverlap(onlineDirectory, publicDirectory) {
		return fmt.Errorf("online and public directories must be disjoint")
	}
	root, err := keys.LoadECPrivateKey(rootPath)
	if err != nil {
		return err
	}
	if err := os.Mkdir(onlineDirectory, 0o700); err != nil {
		return fmt.Errorf("create online private directory: %w", err)
	}
	complete := false
	publicCreated := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(onlineDirectory)
			if publicCreated {
				_ = os.RemoveAll(publicDirectory)
			}
		}
	}()
	if err := os.Chmod(onlineDirectory, 0o700); err != nil {
		return fmt.Errorf("protect online private directory: %w", err)
	}
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		return fmt.Errorf("create public pin directory: %w", err)
	}
	publicCreated = true
	online, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate online service key: %w", err)
	}
	now := time.Now().UTC()
	certificate, err := keys.IssueOnlineCertificate(root, role, []byte(keyID), &online.PublicKey,
		now.Add(-5*time.Minute), now.Add(validFor))
	if err != nil {
		return err
	}
	privatePath := filepath.Join(onlineDirectory, roleName+"-private.pem")
	publicPath := filepath.Join(publicDirectory, roleName+"-public.pem")
	certificatePath := filepath.Join(publicDirectory, roleName+"-certificate.cbor")
	rootPublicPath := filepath.Join(publicDirectory, "root-public.pem")
	if err := keys.SaveECPrivateKey(privatePath, online); err != nil {
		return err
	}
	if err := keys.SaveECPublicKey(publicPath, &online.PublicKey); err != nil {
		return err
	}
	if err := keys.SaveOnlineCertificate(certificatePath, certificate); err != nil {
		return err
	}
	if err := keys.SaveECPublicKey(rootPublicPath, &root.PublicKey); err != nil {
		return err
	}
	fingerprint, err := publicFingerprint(&online.PublicKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output,
		"role=%s\nkid=%s\nonline_public=%s\ncertificate=%s\nroot_public=%s\nonline_fingerprint=%s\n",
		role, keyID, publicPath, certificatePath, rootPublicPath, fingerprint)
	complete = err == nil
	return err
}

func directoriesOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if left == right {
		return true
	}
	leftToRight, leftErr := filepath.Rel(left, right)
	rightToLeft, rightErr := filepath.Rel(right, left)
	return (leftErr == nil && leftToRight != ".." && !strings.HasPrefix(leftToRight, ".."+string(os.PathSeparator))) ||
		(rightErr == nil && rightToLeft != ".." && !strings.HasPrefix(rightToLeft, ".."+string(os.PathSeparator)))
}

func parseOnlineRole(value string) (keys.Role, error) {
	role := keys.Role(value)
	switch role {
	case keys.RoleTrustedTime, keys.RoleRecoveryManifest, keys.RoleEnrollment, keys.RoleAttestation, keys.RoleAttestationReceipt:
		return role, nil
	default:
		return "", keys.ErrRole
	}
}

func publicFingerprint(key *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal public fingerprint: %w", err)
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}
