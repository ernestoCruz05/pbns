package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"golang.org/x/sys/unix"

	controlled "pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/baselineupdate"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/store"
)

func validControlledBaseline(t *testing.T, marker byte) []byte {
	t.Helper()
	var measurement, db, dbx, firmware [32]byte
	measurement[0], db[0], dbx[0], firmware[0] = marker, marker+1, marker+2, marker+3
	encoded, err := controlled.Encode(controlled.Controlled{Record: controlled.Record{Version: 1,
		MeasurementDigest: measurement, SecureBoot: true, DBDigest: db, DBXDigest: dbx,
		FirmwareDigest: firmware}, MemoryMiB: 4096, StorageGiB: 128, BlockDevices: 1})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func baselineStoreWithHost(t *testing.T) (*store.Store, model.HostRecord, string) {
	t.Helper()
	path := privateDatabasePath(t)
	database, err := store.Open(path, store.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	issued, err := database.CreateEnrollment(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var transcript [32]byte
	transcript[0] = 1
	pending, err := database.BeginEnrollment(issued.Plaintext, transcript)
	if err != nil {
		t.Fatal(err)
	}
	initial := validControlledBaseline(t, 1)
	host := model.HostRecord{Fingerprint: [32]byte{1}, IdentityCOSEKey: []byte{0xa1, 1, 1},
		Assurance: model.AssuranceSoftware, BaselineID: sha256.Sum256(initial), EnrolledAtUnix: time.Now().Unix()}
	if err := database.CompleteEnrollmentEvidence(pending.ID, host, initial, []byte{1}); err != nil {
		t.Fatal(err)
	}
	return database, host, path
}

func adminKey(t *testing.T) (*ecdsa.PrivateKey, [32]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, sha256.Sum256(der)
}

func signBaselineProposal(t *testing.T, proposal []byte, key *ecdsa.PrivateKey, kid [32]byte) []byte {
	t.Helper()
	decoded, err := decodeBaselineProposal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = kid[:]
	message.Payload = append([]byte(nil), proposal...)
	if err := message.Sign(rand.Reader, baselineProposalAAD(decoded), signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestBaselineProposalIsCanonicalPublicDataAndDoesNotMutateStore(t *testing.T) {
	database, host, _ := baselineStoreWithHost(t)
	admin, kid := adminKey(t)
	_ = admin
	before, err := database.GetHost(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := createBaselineProposal(database, host.Fingerprint, validControlledBaseline(t, 9), ChangeSecurity,
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), kid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeBaselineProposal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.ParentBaselineID != host.BaselineID || decoded.HostFingerprint != host.Fingerprint {
		t.Fatal("proposal bindings differ")
	}
	after, err := database.GetHost(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if before.BaselineID != after.BaselineID {
		t.Fatal("proposal activated baseline")
	}
	if _, err := database.GetBaseline(decoded.NewBaselineID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("proposal wrote baseline: %v", err)
	}
}

func TestBaselineApprovalRequiresTrustedAdminAndAtomicallyActivatesOnce(t *testing.T) {
	database, host, _ := baselineStoreWithHost(t)
	admin, kid := adminKey(t)
	proposal, err := createBaselineProposal(database, host.Fingerprint, validControlledBaseline(t, 9), ChangeSecurity,
		time.Now().Add(-time.Minute), time.Now().Add(time.Hour), kid)
	if err != nil {
		t.Fatal(err)
	}
	signature := signBaselineProposal(t, proposal, admin, kid)
	wrong, _ := adminKey(t)
	if err := approveBaselineProposal(database, proposal, signature, &wrong.PublicKey, time.Now()); !errors.Is(err, ErrBaselineAuthorization) {
		t.Fatalf("wrong trusted key accepted: %v", err)
	}
	if err := approveBaselineProposal(database, proposal, nil, &admin.PublicKey, time.Now()); err == nil {
		t.Fatal("unsigned approval accepted")
	}
	const workers = 8
	var group sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- approveBaselineProposal(database, proposal, signature, &admin.PublicKey, time.Now())
		}()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("successful concurrent approvals=%d, want 1", success)
	}
	updated, err := database.GetHost(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := decodeBaselineProposal(proposal)
	if updated.BaselineID != decoded.NewBaselineID {
		t.Fatal("active baseline not updated")
	}
	history, err := database.ListBaselineHistory(host.Fingerprint)
	if err != nil || len(history) != 1 {
		t.Fatalf("history=%v err=%v", history, err)
	}
}

func TestBaselineApprovalRejectsTimeDigestCanonicalClassificationStaleAndRollback(t *testing.T) {
	database, host, _ := baselineStoreWithHost(t)
	admin, kid := adminKey(t)
	now := time.Now()
	security := validControlledBaseline(t, 9)
	proposal, _ := createBaselineProposal(database, host.Fingerprint, security, ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	signature := signBaselineProposal(t, proposal, admin, kid)
	mutants := [][]byte{append(append([]byte(nil), proposal...), 0), append([]byte{0xbf}, proposal...)}
	for _, mutant := range mutants {
		if err := approveBaselineProposal(database, mutant, signature, &admin.PublicKey, now); err == nil {
			t.Fatal("noncanonical proposal accepted")
		}
	}
	expired, _ := createBaselineProposal(database, host.Fingerprint, validControlledBaseline(t, 10), ChangeSecurity, now.Add(-2*time.Hour), now.Add(-time.Hour), kid)
	if err := approveBaselineProposal(database, expired, signBaselineProposal(t, expired, admin, kid), &admin.PublicKey, now); err == nil {
		t.Fatal("expired proposal accepted")
	}
	future, _ := createBaselineProposal(database, host.Fingerprint, validControlledBaseline(t, 11), ChangeSecurity, now.Add(time.Hour), now.Add(2*time.Hour), kid)
	if err := approveBaselineProposal(database, future, signBaselineProposal(t, future, admin, kid), &admin.PublicKey, now); err == nil {
		t.Fatal("future proposal accepted")
	}
	inventoryMislabel, err := createBaselineProposal(database, host.Fingerprint, security, ChangeInventory, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err == nil || inventoryMislabel != nil {
		t.Fatal("security change mislabeled inventory")
	}
	if err := approveBaselineProposal(database, proposal, signature, &admin.PublicKey, now); err != nil {
		t.Fatal(err)
	}
	initial, _ := database.GetBaseline(host.BaselineID)
	stale, _ := baselineupdate.CreateProposal(host.Fingerprint, host.BaselineID, initial, validControlledBaseline(t, 12), ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err := approveBaselineProposal(database, stale, signBaselineProposal(t, stale, admin, kid), &admin.PublicKey, now); !errors.Is(err, store.ErrBaselineStale) {
		t.Fatalf("stale parent: %v", err)
	}
	rollback, _ := baselineupdate.CreateProposal(host.Fingerprint, sha256.Sum256(security), security, validControlledBaseline(t, 1), ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err := approveBaselineProposal(database, rollback, signBaselineProposal(t, rollback, admin, kid), &admin.PublicKey, now); err == nil {
		t.Fatal("rollback to prior baseline accepted")
	}
}

func rawApprovalEnvelope(t *testing.T, protected []byte, unprotected map[int]int, payload, signature []byte) []byte {
	t.Helper()
	encoded, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	result, err := encoded.Marshal(cbor.Tag{Number: 18, Content: []any{protected, unprotected, payload, signature}})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestBaselineApprovalRejectsEverySign1ProfileMutantWithoutMutation(t *testing.T) {
	database, host, _ := baselineStoreWithHost(t)
	admin, kid := adminKey(t)
	now := time.Now()
	updated := validControlledBaseline(t, 9)
	proposal, err := createBaselineProposal(database, host.Fingerprint, updated, ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err != nil {
		t.Fatal(err)
	}
	valid := signBaselineProposal(t, proposal, admin, kid)
	parsed := cose.NewSign1Message()
	if err := parsed.UnmarshalCBOR(valid); err != nil {
		t.Fatal(err)
	}
	canonicalProtected := append([]byte{0xa2, 0x01, 0x26, 0x04, 0x58, 0x20}, kid[:]...)
	wrongKid := append([]byte(nil), canonicalProtected...)
	wrongKid[len(wrongKid)-1] ^= 0x80
	wrongAlg := append([]byte(nil), canonicalProtected...)
	wrongAlg[2] = 0x27
	unknown := append([]byte{0xa3, 0x01, 0x26, 0x04, 0x58, 0x20}, kid[:]...)
	unknown = append(unknown, 0x18, 0x63, 0x00)
	noncanonical := append([]byte{0xa2, 0x04, 0x58, 0x20}, kid[:]...)
	noncanonical = append(noncanonical, 0x01, 0x26)
	duplicate := append([]byte{0xa3, 0x01, 0x26, 0x01, 0x26, 0x04, 0x58, 0x20}, kid[:]...)
	mutants := map[string][]byte{
		"trailing":               append(append([]byte(nil), valid...), 0),
		"wrong-alg":              rawApprovalEnvelope(t, wrongAlg, map[int]int{}, proposal, parsed.Signature),
		"wrong-kid":              rawApprovalEnvelope(t, wrongKid, map[int]int{}, proposal, parsed.Signature),
		"unknown-protected":      rawApprovalEnvelope(t, unknown, map[int]int{}, proposal, parsed.Signature),
		"noncanonical-protected": rawApprovalEnvelope(t, noncanonical, map[int]int{}, proposal, parsed.Signature),
		"duplicate-protected":    rawApprovalEnvelope(t, duplicate, map[int]int{}, proposal, parsed.Signature),
		"nonempty-unprotected":   rawApprovalEnvelope(t, canonicalProtected, map[int]int{5: 1}, proposal, parsed.Signature),
		"wrong-payload":          rawApprovalEnvelope(t, canonicalProtected, map[int]int{}, []byte{0xa0}, parsed.Signature),
	}
	for name, mutant := range mutants {
		t.Run(name, func(t *testing.T) {
			if err := approveBaselineProposal(database, proposal, mutant, &admin.PublicKey, now); err == nil {
				t.Fatal("profile mutant accepted")
			}
			stored, err := database.GetHost(host.Fingerprint)
			if err != nil || stored.BaselineID != host.BaselineID {
				t.Fatalf("host mutated: %v %#v", err, stored)
			}
			if _, err := database.GetBaseline(sha256.Sum256(updated)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("baseline mutation: %v", err)
			}
			history, err := database.ListBaselineHistory(host.Fingerprint)
			if err != nil || len(history) != 0 {
				t.Fatalf("history mutation: %v %v", history, err)
			}
		})
	}
}

func TestBaselineProposalRejectsDigestKidNoChangeAndClassificationMutants(t *testing.T) {
	database, host, _ := baselineStoreWithHost(t)
	admin, kid := adminKey(t)
	now := time.Now()
	if proposal, err := createBaselineProposal(database, host.Fingerprint, []byte{0xbf, 0xff}, ChangeSecurity, now, now.Add(time.Hour), kid); err == nil || proposal != nil {
		t.Fatal("noncanonical baseline accepted")
	}
	parent, err := database.GetBaseline(host.BaselineID)
	if err != nil {
		t.Fatal(err)
	}
	if proposal, err := createBaselineProposal(database, host.Fingerprint, parent, ChangeSecurity, now, now.Add(time.Hour), kid); err == nil || proposal != nil {
		t.Fatal("no-change proposal accepted")
	}
	inventory, err := controlled.Decode(parent)
	if err != nil {
		t.Fatal(err)
	}
	inventory.MemoryMiB++
	inventoryBytes, err := controlled.Encode(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if proposal, err := createBaselineProposal(database, host.Fingerprint, inventoryBytes, ChangeSecurity, now, now.Add(time.Hour), kid); err == nil || proposal != nil {
		t.Fatal("pure inventory change labeled security")
	}
	proposal, err := createBaselineProposal(database, host.Fingerprint, validControlledBaseline(t, 9), ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err != nil {
		t.Fatal(err)
	}
	wrongKid := kid
	wrongKid[0] ^= 0x80
	if err := approveBaselineProposal(database, proposal, signBaselineProposal(t, proposal, admin, wrongKid), &admin.PublicKey, now); !errors.Is(err, ErrBaselineAuthorization) {
		t.Fatalf("wrong kid accepted: %v", err)
	}
	decoded, _ := decodeBaselineProposal(proposal)
	decoded.NewBaselineID[0] ^= 0x80
	canonical, _ := cbor.CanonicalEncOptions().EncMode()
	mismatch, _ := canonical.Marshal(decoded)
	if err := approveBaselineProposal(database, mismatch, []byte{1}, &admin.PublicKey, now); !errors.Is(err, ErrBaselineInvalid) {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
}

func TestBaselineReadsUseOneBoundedNoFollowDescriptor(t *testing.T) {
	directory := t.TempDir()
	original := filepath.Join(directory, "artifact")
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(original, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readRegularFileAfterOpen(original, 32, func(path string) {
		if path != original {
			return
		}
		if err := os.Rename(path, replacement); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil || string(got) != "original" {
		t.Fatalf("same descriptor got=%q err=%v", got, err)
	}
	symlink := filepath.Join(directory, "link")
	if err := os.Symlink(replacement, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(symlink, 32); err == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(directory, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(fifo, 32); err == nil {
		t.Fatal("FIFO accepted")
	}
	oversize := filepath.Join(directory, "oversize")
	file, err := os.Create(oversize)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(33); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(oversize, 32); err == nil {
		t.Fatal("oversize accepted")
	}
	oversizePEM := filepath.Join(directory, "admin.pem")
	if err := os.WriteFile(oversizePEM, bytes.Repeat([]byte{'x'}, adminPublicKeyMaxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAdminPublicKey(oversizePEM); !errors.Is(err, ErrBaselineAuthorization) {
		t.Fatalf("oversize admin key accepted: %v", err)
	}
}

func TestBaselineCLIRequiresAdminPublicKeyAndRejectsUnsafeOverwrite(t *testing.T) {
	database, host, path := baselineStoreWithHost(t)
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	admin, kid := adminKey(t)
	publicPath := filepath.Join(t.TempDir(), "admin.pem")
	if err := keys.SaveECPublicKey(publicPath, &admin.PublicKey); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(t.TempDir(), "baseline.cbor")
	if err := os.WriteFile(baselinePath, validControlledBaseline(t, 9), 0o600); err != nil {
		t.Fatal(err)
	}
	proposalPath := filepath.Join(t.TempDir(), "proposal.cbor")
	args := []string{"--db", path, "baseline", "propose", "--host", formatDigest(host.Fingerprint), "--baseline", baselinePath, "--classification", "security", "--admin-key-id", formatDigest(kid), "--output", proposalPath, "--valid-for", "1h"}
	var out, stderr bytes.Buffer
	if status := run(args, &out, &stderr); status != 0 {
		t.Fatalf("propose: %s", stderr.String())
	}
	if status := run(args, &out, &stderr); status == 0 {
		t.Fatal("proposal overwrite accepted")
	}
	proposal, _ := os.ReadFile(proposalPath)
	signature := signBaselineProposal(t, proposal, admin, kid)
	signaturePath := filepath.Join(t.TempDir(), "signature.cose")
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	if status := run([]string{"--db", path, "baseline", "approve", "--proposal", proposalPath, "--signature", signaturePath}, &out, &stderr); status == 0 {
		t.Fatal("approval without admin public key accepted")
	}
	if status := run([]string{"--db", path, "baseline", "approve", "--proposal", proposalPath, "--signature", signaturePath, "--admin-public-key", publicPath}, &out, &stderr); status != 0 {
		t.Fatalf("approve: %s", stderr.String())
	}
}
