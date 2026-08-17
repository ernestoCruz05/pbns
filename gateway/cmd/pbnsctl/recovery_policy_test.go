package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
)

type policyCLIKeys struct {
	policyPrivate    string
	policyPublic     string
	manifestPublic   string
	secureBootPublic string
	policyKey        *ecdsa.PrivateKey
}

func makePolicyCLIKeys(t *testing.T) policyCLIKeys {
	t.Helper()
	directory := t.TempDir()
	makeKey := func(name string) (*ecdsa.PrivateKey, string, string) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privatePath := filepath.Join(directory, name+"-private.pem")
		publicPath := filepath.Join(directory, name+"-public.pem")
		if err := keys.SaveECPrivateKey(privatePath, key); err != nil {
			t.Fatal(err)
		}
		if err := keys.SaveECPublicKey(publicPath, &key.PublicKey); err != nil {
			t.Fatal(err)
		}
		return key, privatePath, publicPath
	}
	policyKey, policyPrivate, policyPublic := makeKey("policy")
	_, _, manifestPublic := makeKey("manifest")
	_, _, secureBootPublic := makeKey("secureboot")
	return policyCLIKeys{
		policyPrivate: policyPrivate, policyPublic: policyPublic,
		manifestPublic: manifestPublic, secureBootPublic: secureBootPublic,
		policyKey: policyKey,
	}
}

func policyCLIArguments(keys policyCLIKeys, operation, output, material string) []string {
	arguments := []string{
		"policy", operation,
		"--policy-private-key", keys.policyPrivate,
		"--policy-public-key", keys.policyPublic,
		"--manifest-public-key", keys.manifestPublic,
		"--secureboot-public-key", keys.secureBootPublic,
		"--nv-index", "0x01801000", "--material-dir", material,
		"--output", output,
	}
	if operation == "initialize" {
		arguments = append(arguments, "--initial-version", "4")
	} else {
		arguments = append(arguments, "--current-version", "4", "--target-version", "5")
	}
	return arguments
}

func TestRecoveryPolicyCLIProducesVerifiedAuthorizationAndPublicMaterial(t *testing.T) {
	keys := makePolicyCLIKeys(t)
	for _, operation := range []string{"initialize", "advance"} {
		t.Run(operation, func(t *testing.T) {
			directory := t.TempDir()
			output := filepath.Join(directory, operation+".cbor")
			material := filepath.Join(directory, operation+"-material")
			var stdout bytes.Buffer
			if err := runRecovery(
				policyCLIArguments(keys, operation, output, material), &stdout); err != nil {
				t.Fatal(err)
			}
			var result struct {
				Kind                string `json:"kind"`
				Target              uint64 `json:"target_version"`
				AuthorizationSHA256 string `json:"authorization_sha256"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Kind != operation || result.AuthorizationSHA256 == "" {
				t.Fatalf("wrong result: %#v", result)
			}
			encoded, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var authorization recovery.VersionAuthorization
			if operation == "initialize" {
				authorization, err = recovery.VerifyInitializationAuthorization(
					encoded, &keys.policyKey.PublicKey, recovery.RecoveryNVIndex, false)
			} else {
				authorization, err = recovery.VerifyVersionAuthorization(
					encoded, &keys.policyKey.PublicKey, recovery.RecoveryNVIndex, 4)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertPolicyMaterial(t, material, keys.policyPublic, authorization)
			privatePEM, err := os.ReadFile(keys.policyPrivate)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(stdout.Bytes(), privatePEM) {
				t.Fatal("private policy key leaked to stdout")
			}
			if err := runRecovery(
				policyCLIArguments(keys, operation, output, material), &bytes.Buffer{}); err == nil {
				t.Fatal("existing policy output replaced")
			}
		})
	}
}

func assertPolicyMaterial(t *testing.T, directory, policyPublicPath string,
	authorization recovery.VersionAuthorization) {
	t.Helper()
	expected := map[string][]byte{
		"target.bin":        authorization.Operand,
		"nv.public":         authorization.NVPublic,
		"nv.name":           authorization.NVName,
		"policy-key.public": authorization.PolicyKeyPublic,
		"policy-key.name":   authorization.PolicyKeyName,
		"policy.ref":        authorization.PolicyRef,
		"write.cphash":      authorization.CPHash,
		"approved.policy":   authorization.ApprovedPolicy,
		"signature.tss":     authorization.Signature,
		"final.policy":      authorization.FinalPolicy,
	}
	approval := recovery.PolicyApprovalDigest(
		authorization.ApprovedPolicy, authorization.PolicyRef)
	expected["approval.digest"] = approval[:]
	policyPEM, err := os.ReadFile(policyPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	expected["policy-key.pem"] = policyPEM
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(expected) {
		t.Fatalf("material entries=%d, expected=%d", len(entries), len(expected))
	}
	for name, wanted := range expected {
		path := filepath.Join(directory, name)
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, wanted) {
			t.Fatalf("material %s differs", name)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("material %s mode=%o", name, info.Mode().Perm())
		}
	}
}

func TestRecoveryPolicyCLIRejectsRoleReuseAndWeakPrivatePermissions(t *testing.T) {
	keys := makePolicyCLIKeys(t)
	directory := t.TempDir()
	output := filepath.Join(directory, "authorization.cbor")
	material := filepath.Join(directory, "material")
	keys.manifestPublic = keys.policyPublic
	if err := runRecovery(
		policyCLIArguments(keys, "advance", output, material), &bytes.Buffer{}); err == nil {
		t.Fatal("policy and manifest key reuse accepted")
	}
	keys = makePolicyCLIKeys(t)
	if err := os.Chmod(keys.policyPrivate, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runRecovery(
		policyCLIArguments(keys, "advance", output, material), &bytes.Buffer{}); err == nil {
		t.Fatal("group/world-readable policy private key accepted")
	}
}

func TestRecoveryPolicyCLIRejectsWrongIndexAndMissingVersions(t *testing.T) {
	keys := makePolicyCLIKeys(t)
	arguments := policyCLIArguments(
		keys, "advance", filepath.Join(t.TempDir(), "out"), filepath.Join(t.TempDir(), "material"))
	for index, value := range arguments {
		if value == "0x01801000" {
			arguments[index] = "0x01801001"
		}
	}
	if err := runRecovery(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("wrong NV index accepted")
	}
	arguments = policyCLIArguments(
		keys, "initialize", filepath.Join(t.TempDir(), "out"), filepath.Join(t.TempDir(), "material"))
	arguments = arguments[:len(arguments)-2]
	if err := runRecovery(arguments, &bytes.Buffer{}); err == nil {
		t.Fatal("missing initial version accepted")
	}
}
