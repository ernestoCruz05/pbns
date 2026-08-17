package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"pbns.local/gateway/internal/deployment"
	"pbns.local/gateway/internal/enrollmenttrust"
)

func TestGenerateCreatesPrivateDeploymentAndDeterministicPublicC(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "deployment")
	if err := run([]string{"generate", "--out-dir", directory, "--server-name", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%v err=%v", info.Mode().Perm(), err)
	}
	bundlePath := filepath.Join(directory, "deployment.cbor")
	if info, err := os.Lstat(bundlePath); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
		t.Fatalf("bundle mode=%v err=%v", info.Mode(), err)
	}
	if _, err := deployment.Load(bundlePath); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tls-key.pem", "time-key.pem", "challenge-key.pem", "recipient-key.pem", "receipt-key.pem"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%v err=%v", name, info.Mode().Perm(), err)
		}
	}
	firstHeader := filepath.Join(directory, "first.h")
	firstSource := filepath.Join(directory, "first.c")
	secondHeader := filepath.Join(directory, "second.h")
	secondSource := filepath.Join(directory, "second.c")
	for _, output := range [][2]string{{firstHeader, firstSource}, {secondHeader, secondSource}} {
		if err := run([]string{"render-c", "--bundle", bundlePath, "--header", output[0], "--source", output[1]}); err != nil {
			t.Fatal(err)
		}
	}
	first, _ := os.ReadFile(firstSource)
	second, _ := os.ReadFile(secondSource)
	if !bytes.Equal(first, second) {
		t.Fatal("rendered C changed for same bundle")
	}
	if bytes.Contains(first, []byte("PRIVATE KEY")) || bytes.Contains(first, []byte("BEGIN EC")) {
		t.Fatal("private material rendered into C")
	}
}

func TestRenderUsesExclusiveImmutableFilesInPrivateOwnedDirectory(t *testing.T) {
	deploymentDirectory := filepath.Join(t.TempDir(), "deployment")
	if err := run([]string{"generate", "--out-dir", deploymentDirectory, "--server-name", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(outputDirectory, "trust.h")
	source := filepath.Join(outputDirectory, "trust.c")
	if err := run([]string{"render-c", "--bundle", filepath.Join(deploymentDirectory, "deployment.cbor"), "--header", header, "--source", source}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{header, source} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			t.Fatalf("generated file %s mode=%v err=%v", path, info.Mode(), err)
		}
	}
	if err := run([]string{"render-c", "--bundle", filepath.Join(deploymentDirectory, "deployment.cbor"), "--header", header, "--source", source}); err == nil {
		t.Fatal("stale generated output was overwritten")
	}

	maliciousDirectory := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(maliciousDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	maliciousSource := filepath.Join(maliciousDirectory, "trust.c")
	if err := os.Symlink(victim, maliciousSource); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"render-c", "--bundle", filepath.Join(deploymentDirectory, "deployment.cbor"), "--header", filepath.Join(maliciousDirectory, "trust.h"), "--source", maliciousSource}); err == nil {
		t.Fatal("generated-source symlink accepted")
	}
	contents, err := os.ReadFile(victim)
	if err != nil || string(contents) != "unchanged" {
		t.Fatalf("generated-source symlink modified victim: %q %v", contents, err)
	}
}

func TestRenderRefusesBundleSymlinkAndUnsafeImmediateAuthority(t *testing.T) {
	deploymentDirectory := filepath.Join(t.TempDir(), "deployment")
	if err := run([]string{"generate", "--out-dir", deploymentDirectory, "--server-name", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(deploymentDirectory, "deployment.cbor")
	outputDirectory := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, bundle := range map[string]string{
		"symlink":       filepath.Join(deploymentDirectory, "bundle-link.cbor"),
		"unsafe-parent": filepath.Join(t.TempDir(), "bundle.cbor"),
	} {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "symlink":
				if err := os.Symlink(bundlePath, bundle); err != nil {
					t.Fatal(err)
				}
			case "unsafe-parent":
				encoded, err := os.ReadFile(bundlePath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(bundle, encoded, 0o444); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Dir(bundle), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := run([]string{"render-c", "--bundle", bundle, "--header", filepath.Join(outputDirectory, name+".h"), "--source", filepath.Join(outputDirectory, name+".c")}); err == nil {
				t.Fatal("unsafe bundle path accepted")
			}
		})
	}
}

func TestGenerateEnrollmentCreatesFreshDistinctTrustAndPublicC(t *testing.T) {
	first := filepath.Join(t.TempDir(), "enrollment-first")
	second := filepath.Join(t.TempDir(), "enrollment-second")
	for _, directory := range []string{first, second} {
		if err := run([]string{"generate-enrollment", "--out-dir", directory}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("enrollment directory mode=%v", info.Mode().Perm())
		}
		bundlePath := filepath.Join(directory, "enrollment.cbor")
		info, err = os.Stat(bundlePath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("enrollment bundle mode=%v", info.Mode().Perm())
		}
		for _, name := range []string{"recipient-key.pem", "signer-key.pem"} {
			info, err = os.Stat(filepath.Join(directory, name))
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode=%v", name, info.Mode().Perm())
			}
		}
	}
	firstBundle, err := enrollmenttrust.Load(filepath.Join(first, "enrollment.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	secondBundle, err := enrollmenttrust.Load(filepath.Join(second, "enrollment.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstBundle.Recipient.X, secondBundle.Recipient.X) ||
		bytes.Equal(firstBundle.Signer.X, secondBundle.Signer.X) {
		t.Fatal("two fresh enrollment generations reused a role key")
	}

	outputDirectory := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(outputDirectory, "PbnsEnrollmentTrust.h")
	source := filepath.Join(outputDirectory, "PbnsEnrollmentTrust.c")
	if err := run([]string{"render-enrollment-c", "--bundle", filepath.Join(first, "enrollment.cbor"), "--header", header, "--source", source}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{header, source} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o444 {
			t.Fatalf("generated enrollment file mode=%v", info.Mode().Perm())
		}
	}
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte("BEGIN EC")) {
		t.Fatal("private enrollment material rendered into C")
	}
}

func TestGenerateRefusesExistingDirectoryAndRenderRefusesMalformedBundle(t *testing.T) {
	directory := t.TempDir()
	if err := run([]string{"generate", "--out-dir", directory, "--server-name", "127.0.0.1"}); err == nil {
		t.Fatal("existing directory accepted")
	}
	malformed := filepath.Join(t.TempDir(), "bad.cbor")
	if err := os.WriteFile(malformed, []byte{0xbf, 0xff}, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"render-c", "--bundle", malformed, "--header", malformed + ".h", "--source", malformed + ".c"}); err == nil {
		t.Fatal("malformed bundle rendered")
	}
}
