package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"pbns.local/gateway/internal/deployment"
	"pbns.local/gateway/internal/enrollmenttrust"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: pbns-deployment generate|render-c|generate-enrollment|render-enrollment-c")
	}
	switch arguments[0] {
	case "generate":
		flags := flag.NewFlagSet("generate", flag.ContinueOnError)
		out := flags.String("out-dir", "", "new private deployment directory")
		server := flags.String("server-name", "", "TLS DNS name or IP address")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *out == "" || *server == "" {
			return errors.New("generate requires --out-dir and --server-name")
		}
		return generate(*out, *server)
	case "render-c":
		return render(arguments[1:], false)
	case "generate-enrollment":
		flags := flag.NewFlagSet("generate-enrollment", flag.ContinueOnError)
		out := flags.String("out-dir", "", "new private enrollment trust directory")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *out == "" {
			return errors.New("generate-enrollment requires --out-dir")
		}
		return generateEnrollment(*out)
	case "render-enrollment-c":
		return render(arguments[1:], true)
	default:
		return errors.New("unknown deployment command")
	}
}

func render(arguments []string, enrollment bool) error {
	name := "render-c"
	if enrollment {
		name = "render-enrollment-c"
	}
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	bundlePath := flags.String("bundle", "", "canonical public trust bundle")
	headerPath := flags.String("header", "", "generated C header")
	sourcePath := flags.String("source", "", "generated C source")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *bundlePath == "" || *headerPath == "" || *sourcePath == "" {
		return fmt.Errorf("%s requires --bundle, --header, and --source", name)
	}
	var header, source []byte
	var err error
	if enrollment {
		var bundle enrollmenttrust.Bundle
		bundle, err = enrollmenttrust.Load(*bundlePath)
		if err == nil {
			header, source, err = enrollmenttrust.RenderC(bundle)
		}
	} else {
		var bundle deployment.Bundle
		bundle, err = deployment.Load(*bundlePath)
		if err == nil {
			header, source, err = deployment.RenderC(bundle)
		}
	}
	if err != nil {
		return err
	}
	if err := writeGenerated(*headerPath, header); err != nil {
		return err
	}
	if err := writeGenerated(*sourcePath, source); err != nil {
		_ = os.Remove(*headerPath)
		return err
	}
	return nil
}

func generateEnrollment(directory string) error {
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create enrollment trust directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.Remove(directory)
		return err
	}
	paths := []string{
		filepath.Join(directory, "recipient-key.pem"),
		filepath.Join(directory, "signer-key.pem"),
		filepath.Join(directory, "enrollment.cbor"),
	}
	complete := false
	defer func() {
		if complete {
			return
		}
		for _, path := range paths {
			_ = os.Remove(path)
		}
		_ = os.Remove(directory)
	}()
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if err := writePrivateKey(paths[0], recipient); err != nil {
		return err
	}
	if err := writePrivateKey(paths[1], signer); err != nil {
		return err
	}
	bundle := enrollmenttrust.Bundle{
		Domain: enrollmenttrust.Domain, Version: 1,
		Recipient: deployment.PublicKey{KID: []byte("pbns-enrollment-recipient-v1"), X: recipient.X.FillBytes(make([]byte, 32)), Y: recipient.Y.FillBytes(make([]byte, 32))},
		Signer:    deployment.PublicKey{KID: []byte("pbns-enrollment-signer-v1"), X: signer.X.FillBytes(make([]byte, 32)), Y: signer.Y.FillBytes(make([]byte, 32))},
	}
	encoded, err := enrollmenttrust.Marshal(bundle)
	if err != nil {
		return err
	}
	if err := writeNew(paths[2], 0o444, encoded); err != nil {
		return err
	}
	complete = true
	return nil
}

func generate(directory, serverName string) error {
	if net.ParseIP(serverName) == nil {
		if err := (&x509.Certificate{DNSNames: []string{serverName}}).VerifyHostname(serverName); err != nil {
			return fmt.Errorf("invalid server name: %w", err)
		}
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return fmt.Errorf("create deployment directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(directory)
		}
	}()
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil || serial.Sign() == 0 {
		return errors.New("generate TLS certificate serial")
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "PBNS deployment gateway"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{serverName}
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		return err
	}
	if err := writePrivateKey(filepath.Join(directory, "tls-key.pem"), tlsKey); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(directory, "tls-cert.pem"), 0o600, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})); err != nil {
		return err
	}
	tlsSPKI, err := x509.MarshalPKIXPublicKey(&tlsKey.PublicKey)
	if err != nil {
		return err
	}
	bundle := deployment.Bundle{Domain: deployment.Domain, Version: 1, TLSServerName: serverName, TLSPublicKeyDER: tlsSPKI, TLSSPKISHA256: sha256.Sum256(tlsSPKI)}
	roles := map[deployment.Role]*deployment.PublicKey{
		deployment.RoleTime: &bundle.Time, deployment.RoleChallenge: &bundle.Challenge,
		deployment.RoleRecipient: &bundle.Recipient, deployment.RoleReceipt: &bundle.Receipt,
	}
	for _, role := range deployment.SortedRoles() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		if err := writePrivateKey(filepath.Join(directory, string(role)+"-key.pem"), key); err != nil {
			return err
		}
		*roles[role] = deployment.PublicKey{KID: []byte("pbns-" + string(role) + "-v1"), X: key.X.FillBytes(make([]byte, 32)), Y: key.Y.FillBytes(make([]byte, 32))}
	}
	encoded, err := deployment.Marshal(bundle)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(directory, "deployment.cbor"), 0o444, encoded); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func writePrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writeNew(path, 0o600, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func writeNew(path string, mode os.FileMode, content []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	writeErr := file.Chmod(mode)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeGenerated(path string, content []byte) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("generated output directory must be private, owned, and non-symlink")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("generated output directory has wrong owner")
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("open generated output")
	}
	writeErr := file.Chmod(0o600)
	if writeErr == nil {
		_, writeErr = file.Write(content)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if writeErr == nil {
		writeErr = file.Chmod(0o444)
	}
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return nil
}
