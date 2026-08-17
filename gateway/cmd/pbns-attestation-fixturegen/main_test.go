package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	modern "github.com/google/go-tpm/tpm2"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "attestation"))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func copySource(t *testing.T, root string) string {
	t.Helper()
	target := t.TempDir()
	for _, name := range []string{"metadata.json", "ak.pub", "ak.name", "ak-rsa.pub", "quote.bin", "signature.bin"} {
		b, err := os.ReadFile(filepath.Join(root, "source", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return target
}
func replaceMetadata(t *testing.T, source, old, replacement string) {
	t.Helper()
	p := filepath.Join(source, "metadata.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(old)) {
		t.Fatalf("missing metadata text %q", old)
	}
	if err := os.WriteFile(p, bytes.Replace(b, []byte(old), []byte(replacement), 1), 0600); err != nil {
		t.Fatal(err)
	}
}
func compareGenerated(t *testing.T, output, root string) {
	t.Helper()
	for _, name := range []string{"valid-swtpm-evidence.cbor", "expected/eventlog.bin", "expected/extend-digests.hex", "expected/pcrvals.hex", "expected/qual.hex"} {
		expectedName, actualName := name, name
		if strings.HasPrefix(name, "expected/") {
			actualName = strings.TrimPrefix(name, "expected/")
		}
		want, err := os.ReadFile(filepath.Join(root, expectedName))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(output, actualName))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("generated %s differs", actualName)
		}
	}
	invalid, err := filepath.Glob(filepath.Join(root, "invalid", "*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, wantPath := range invalid {
		got, err := os.ReadFile(filepath.Join(output, "invalid", filepath.Base(wantPath)))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(wantPath)
		if !bytes.Equal(got, want) {
			t.Fatalf("generated invalid %s differs", filepath.Base(wantPath))
		}
	}
}
func TestGenerateMatchesCheckedInOutputs(t *testing.T) {
	root := fixtureRoot(t)
	out := t.TempDir()
	if err := generate(filepath.Join(root, "source"), out); err != nil {
		t.Fatal(err)
	}
	compareGenerated(t, out, root)
}
func TestPrepareMatchesExpectedPreQuoteOutputs(t *testing.T) {
	root := fixtureRoot(t)
	out := t.TempDir()
	if err := prepare(filepath.Join(root, "source"), out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"eventlog.bin", "extend-digests.hex", "pcrvals.hex", "qual.hex"} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := os.ReadFile(filepath.Join(root, "expected", name))
		if !bytes.Equal(got, want) {
			t.Fatalf("prepare %s differs", name)
		}
	}
}
func TestMetadataStrictRejectionForPrepareAndGenerate(t *testing.T) {
	root := fixtureRoot(t)
	cases := map[string][2]string{
		"domain": {"\"domain\": \"PBNS-ATTESTATION-v1\"", "\"domain\": \"other\""}, "protocol": {"\"protocol_version\": 1", "\"protocol_version\": 2"}, "service": {"\"service\": 3", "\"service\": 4"}, "selection": {"\"pcr_selection\": [0, 2, 4, 7]", "\"pcr_selection\": [0, 2, 7, 4]"}, "reordered-event": {"\"pcr\": 0, \"type\": 5", "\"pcr\": 2, \"type\": 5"}, "duplicate-event": {"\"pcr\": 4, \"type\": 5", "\"pcr\": 2, \"type\": 5"}, "missing-event": {"\"pcr\": 7, \"type\": 5", "\"pcr\": 8, \"type\": 5"},
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			src := copySource(t, root)
			replaceMetadata(t, src, mutation[0], mutation[1])
			if err := prepare(src, t.TempDir()); err == nil {
				t.Fatal("prepare accepted invalid metadata")
			}
			if err := generate(src, t.TempDir()); err == nil {
				t.Fatal("generate accepted invalid metadata")
			}
		})
	}
	for _, tail := range []string{" {}", "\n{\"unknown\":true}"} {
		t.Run("trailing-"+strings.ReplaceAll(tail, " ", "space"), func(t *testing.T) {
			src := copySource(t, root)
			p := filepath.Join(src, "metadata.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, []byte(tail)...), 0600)
			if err := prepare(src, t.TempDir()); err == nil {
				t.Fatal("prepare accepted trailing JSON")
			}
			if err := generate(src, t.TempDir()); err == nil {
				t.Fatal("generate accepted trailing JSON")
			}
		})
	}
	t.Run("unknown-field", func(t *testing.T) {
		src := copySource(t, root)
		p := filepath.Join(src, "metadata.json")
		b, _ := os.ReadFile(p)
		b = bytes.Replace(b, []byte("\n}"), []byte(",\n  \"unknown\": 1\n}"), 1)
		os.WriteFile(p, b, 0600)
		if err := prepare(src, t.TempDir()); err == nil {
			t.Fatal("prepare accepted unknown field")
		}
		if err := generate(src, t.TempDir()); err == nil {
			t.Fatal("generate accepted unknown field")
		}
	})
}
func TestRound5DuplicateJSONAndMissingSHA256BankRejectedBeforeOutput(t *testing.T) {
	root := fixtureRoot(t)
	cases := map[string]func(string){
		"duplicate-top-level": func(source string) {
			replaceMetadata(t, source, "\"domain\": \"PBNS-ATTESTATION-v1\"", "\"domain\": \"PBNS-ATTESTATION-v1\", \"domain\": \"PBNS-ATTESTATION-v1\"")
		},
		"duplicate-outcomes": func(source string) {
			replaceMetadata(t, source, "\"outcomes\": {\"1\": 1", "\"outcomes\": {\"1\": 1, \"1\": 1")
		},
		"duplicate-timings": func(source string) {
			replaceMetadata(t, source, "\"timings\": {\"1\": 1}", "\"timings\": {\"1\": 1, \"1\": 1}")
		},
		"duplicate-event-member": func(source string) {
			replaceMetadata(t, source, "\"pcr\": 0, \"type\": 5", "\"pcr\": 0, \"pcr\": 0, \"type\": 5")
		},
		"missing-sha256-bank": func(source string) {
			replaceMetadata(t, source, "\"tpm_active_banks\": [11]", "\"tpm_active_banks\": [4]")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			source := copySource(t, root)
			mutate(source)
			output := filepath.Join(t.TempDir(), "new-output")
			if err := prepare(source, output); err == nil {
				t.Fatal("prepare accepted invalid source")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("prepare created output before rejecting source")
			}
			if err := generate(source, output); err == nil {
				t.Fatal("generate accepted invalid source")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("generate created output before rejecting source")
			}
		})
	}
}

func TestSortedMultiBankWithSHA256ChangesPrepareAndStalesQuote(t *testing.T) {
	root := fixtureRoot(t)
	source := copySource(t, root)
	before := t.TempDir()
	if err := prepare(source, before); err != nil {
		t.Fatal(err)
	}
	replaceMetadata(t, source, "\"tpm_active_banks\": [11]", "\"tpm_active_banks\": [4, 11]")
	after := t.TempDir()
	if err := prepare(source, after); err != nil {
		t.Fatal(err)
	}
	left, _ := os.ReadFile(filepath.Join(before, "qual.hex"))
	right, _ := os.ReadFile(filepath.Join(after, "qual.hex"))
	if bytes.Equal(left, right) {
		t.Fatal("active bank change did not bind qualifying data")
	}
	if err := generate(source, t.TempDir()); err == nil {
		t.Fatal("multi-bank metadata accepted against stale quote")
	}
}

func TestLegitimateMetadataMutationChangesPrepareAndFailsStaleQuote(t *testing.T) {
	root := fixtureRoot(t)
	src := copySource(t, root)
	before := t.TempDir()
	if err := prepare(src, before); err != nil {
		t.Fatal(err)
	}
	replaceMetadata(t, src, "\"firmware_version\": \"2.0\"", "\"firmware_version\": \"2.1\"")
	after := t.TempDir()
	if err := prepare(src, after); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(before, "qual.hex"))
	b, _ := os.ReadFile(filepath.Join(after, "qual.hex"))
	if bytes.Equal(a, b) {
		t.Fatal("legitimate metadata mutation did not affect prepare output")
	}
	if err := generate(src, t.TempDir()); err == nil {
		t.Fatal("mutated metadata accepted against stale quote")
	}
}
func TestSourceOutputSeparation(t *testing.T) {
	root := fixtureRoot(t)
	src := copySource(t, root)
	marker := filepath.Join(src, "marker")
	os.WriteFile(marker, []byte("preserve"), 0600)
	cases := []struct{ name, source, out string }{{"equal", src, src}, {"output-under-source", src, filepath.Join(src, "out")}, {"source-under-output", filepath.Join(src, "source"), src}}
	nested := filepath.Join(src, "source")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := prepare(tc.source, tc.out); err == nil {
				t.Fatal("accepted overlapping trees")
			}
			got, _ := os.ReadFile(marker)
			if string(got) != "preserve" {
				t.Fatal("source overwritten")
			}
		})
	}
	aliasRoot := t.TempDir()
	link := filepath.Join(aliasRoot, "source-alias")
	if err := os.Symlink(src, link); err == nil {
		t.Run("symlink-alias", func(t *testing.T) {
			if err := prepare(src, link); err == nil {
				t.Fatal("accepted symlink alias")
			}
		})
		t.Run("symlink-output-under-source", func(t *testing.T) {
			if err := prepare(link, filepath.Join(link, "child")); err == nil {
				t.Fatal("accepted output below symlink source")
			}
		})
	}
	if err := prepare(copySource(t, root), t.TempDir()); err != nil {
		t.Fatalf("valid sibling directories rejected: %v", err)
	}
}
func TestRelativeSourceOutputSeparation(t *testing.T) {
	root := fixtureRoot(t)
	parent := t.TempDir()
	source := filepath.Join(parent, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"metadata.json", "ak.pub", "ak.name", "ak-rsa.pub", "quote.bin", "signature.bin"} {
		b, err := os.ReadFile(filepath.Join(root, "source", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(source, "marker")
	os.WriteFile(marker, []byte("preserve"), 0600)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(parent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	if err := os.MkdirAll("out/source", 0700); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"source", "source"}, {"source", "source/generated"}, {"out/source", "out"}} {
		if err := prepare(pair[0], pair[1]); err == nil {
			t.Fatalf("accepted relative overlap %q/%q", pair[0], pair[1])
		}
		got, _ := os.ReadFile(marker)
		if string(got) != "preserve" {
			t.Fatal("source marker overwritten")
		}
	}
	if err := os.Symlink("source", "alias"); err == nil {
		if err := prepare("source", "alias"); err == nil {
			t.Fatal("accepted relative symlink alias")
		}
		if err := prepare("alias", "alias/child"); err == nil {
			t.Fatal("accepted relative symlink containment")
		}
	}
	if err := prepare("source", "sibling-output"); err != nil {
		t.Fatalf("valid relative sibling rejected: %v", err)
	}
}

func TestTask1MetadataBoundsForPrepareAndGenerate(t *testing.T) {
	root := fixtureRoot(t)
	cases := map[string][2]string{
		"outcome-missing":   {"\"outcomes\": {\"1\": 1, \"2\": 1, \"3\": 1, \"4\": 1, \"5\": 1}", "\"outcomes\": {\"1\": 1, \"2\": 1, \"3\": 1, \"4\": 1}"},
		"outcome-extra":     {"\"outcomes\": {\"1\": 1, \"2\": 1, \"3\": 1, \"4\": 1, \"5\": 1}", "\"outcomes\": {\"1\": 1, \"2\": 1, \"3\": 1, \"4\": 1, \"5\": 1, \"6\": 1}"},
		"outcome-bad":       {"\"outcomes\": {\"1\": 1, \"2\": 1, \"3\": 1, \"4\": 1, \"5\": 1}", "\"outcomes\": {\"1\": 6, \"2\": 1, \"3\": 1, \"4\": 1, \"5\": 1}"},
		"timings-omitted":   {"  \"timings\": {\"1\": 1},\n", ""},
		"timings-nine":      {"\"timings\": {\"1\": 1}", "\"timings\": {\"1\": 1, \"2\": 1, \"3\": 1, \"4\": 1, \"5\": 1, \"6\": 1, \"7\": 1, \"8\": 1, \"9\": 1}"},
		"timing-zero":       {"\"timings\": {\"1\": 1}", "\"timings\": {\"0\": 1}"},
		"expiry-overflow":   {"\"expires_at_unix_ns\": 2", "\"expires_at_unix_ns\": 9223372036854775808"},
		"text-control":      {"\"cpu_class\": \"fixture\"", "\"cpu_class\": \"bad\\u001f\""},
		"text-leading":      {"\"firmware_vendor\": \"Fixture Vendor\"", "\"firmware_vendor\": \" Fixture Vendor\""},
		"text-trailing":     {"\"firmware_version\": \"2.0\"", "\"firmware_version\": \"2.0 \""},
		"text-double-space": {"\"cpu_class\": \"fixture\"", "\"cpu_class\": \"two  spaces\""},
		"text-overlong":     {"\"cpu_class\": \"fixture\"", "\"cpu_class\": \"" + strings.Repeat("x", 97) + "\""},
		"bank-order":        {"\"tpm_active_banks\": [11]", "\"tpm_active_banks\": [12, 11]"},
		"bank-duplicate":    {"\"tpm_active_banks\": [11]", "\"tpm_active_banks\": [11, 11]"},
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			source := copySource(t, root)
			replaceMetadata(t, source, mutation[0], mutation[1])
			if err := prepare(source, t.TempDir()); err == nil {
				t.Fatal("prepare accepted invalid inventory metadata")
			}
			if err := generate(source, t.TempDir()); err == nil {
				t.Fatal("generate accepted invalid inventory metadata")
			}
		})
	}
}

func TestGenerateRejectsNoncanonicalQuoteAndSignature(t *testing.T) {
	root := fixtureRoot(t)
	for _, tc := range []struct {
		file string
		want string
	}{{"quote.bin", "noncanonical quote"}, {"signature.bin", "noncanonical signature"}} {
		t.Run(tc.file, func(t *testing.T) {
			source := copySource(t, root)
			path := filepath.Join(source, tc.file)
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(encoded, 0xaa), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "output")
			err = generate(source, output)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v want %q", err, tc.want)
			}
			if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
				t.Fatalf("generator created output before rejecting %s", tc.file)
			}
		})
	}
}

func TestCanonicalTPM2BArtifacts(t *testing.T) {
	root := fixtureRoot(t)
	ecc, _ := os.ReadFile(filepath.Join(root, "source", "ak.pub"))
	rsa, _ := os.ReadFile(filepath.Join(root, "source", "ak-rsa.pub"))
	dir := t.TempDir()
	check := func(name string, b []byte, rsaProfile bool, want bool) {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0600)
		_, err := readCanonicalAK(p, rsaProfile)
		if (err == nil) != want {
			t.Fatalf("%s err=%v want success=%v", name, err, want)
		}
	}
	check("ecc", ecc, false, true)
	check("rsa", rsa, true, true)
	check("short", []byte{0}, false, false)
	bad := append([]byte(nil), ecc...)
	bad[0] ^= 1
	check("false-size", bad, false, false)
	check("trailing", append(ecc, 0), false, false)
	check("bare", ecc[2:], false, false)
	check("rsa-one", []byte{0}, true, false)
	check("rsa-as-ecc", ecc, true, false)
	check("rsa-malformed", append(rsa, 0), true, false)
	mutate := func(name string, artifact []byte, rsaProfile bool, change func(*legacy.Public)) {
		t.Helper()
		public, _, err := unwrapCanonicalTPM2B(artifact)
		if err != nil {
			t.Fatal(err)
		}
		change(&public)
		inner, err := public.Encode()
		if err != nil {
			t.Fatal(err)
		}
		modernPublic, err := modern.Unmarshal[modern.TPMTPublic](inner)
		if err != nil {
			t.Fatal(err)
		}
		wrapped := modern.Marshal(modern.New2B(*modernPublic))
		check(name, wrapped, rsaProfile, false)
	}
	mutate("ecc-attributes", ecc, false, func(p *legacy.Public) { p.Attributes = 0 })
	mutate("ecc-namealg", ecc, false, func(p *legacy.Public) { p.NameAlg = legacy.AlgSHA1 })
	mutate("ecc-curve", ecc, false, func(p *legacy.Public) { p.ECCParameters.CurveID = legacy.CurveNISTP384 })
	mutate("ecc-scheme", ecc, false, func(p *legacy.Public) { p.ECCParameters.Sign.Alg = legacy.AlgECDH })
	mutate("ecc-hash", ecc, false, func(p *legacy.Public) { p.ECCParameters.Sign.Hash = legacy.AlgSHA1 })
	mutate("ecc-policy", ecc, false, func(p *legacy.Public) { p.AuthPolicy = []byte{1} })
	mutate("rsa-attributes", rsa, true, func(p *legacy.Public) { p.Attributes = 0 })
	mutate("rsa-namealg", rsa, true, func(p *legacy.Public) { p.NameAlg = legacy.AlgSHA1 })
	mutate("rsa-scheme", rsa, true, func(p *legacy.Public) { p.RSAParameters.Sign.Alg = legacy.AlgRSAPSS })
	mutate("rsa-hash", rsa, true, func(p *legacy.Public) { p.RSAParameters.Sign.Hash = legacy.AlgSHA1 })
	mutate("rsa-key-size", rsa, true, func(p *legacy.Public) { p.RSAParameters.KeyBits = 1024 })
	mutate("rsa-policy", rsa, true, func(p *legacy.Public) { p.AuthPolicy = []byte{1} })
}
