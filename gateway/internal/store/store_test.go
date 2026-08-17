package store

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/veraison/go-cose"
	"go.etcd.io/bbolt"

	controlled "pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/baselineupdate"
	"pbns.local/gateway/internal/model"
)

func deterministicEntropy() *bytes.Reader {
	entropy := make([]byte, 4096)
	for index := range entropy {
		entropy[index] = byte(index + 1)
	}
	return bytes.NewReader(entropy)
}

func openTestStore(t *testing.T) (*Store, *time.Time, string) {
	t.Helper()
	now := time.Unix(1_900_000_000, 123_000_000).UTC()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "gateway.db")
	database, err := Open(path, Options{
		Clock:       func() time.Time { return now },
		Random:      deterministicEntropy(),
		OpenTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil && !errors.Is(err, bbolt.ErrDatabaseNotOpen) {
			t.Errorf("close store: %v", err)
		}
	})
	return database, &now, path
}

func digestWithFirstByte(value byte) [32]byte {
	var digest [32]byte
	digest[0] = value
	return digest
}

func softwareHost(now time.Time, fingerprint byte) model.HostRecord {
	return model.HostRecord{
		Fingerprint:     digestWithFirstByte(fingerprint),
		IdentityCOSEKey: []byte{0xa1, 0x01, fingerprint},
		Assurance:       model.AssuranceSoftware,
		BaselineID:      digestWithFirstByte(fingerprint + 1),
		EnrolledAtUnix:  now.Unix(),
	}
}

func TestOpenCreatesPrivateSchemaAndAllBuckets(t *testing.T) {
	database, _, path := openTestStore(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode %o, want 600", info.Mode().Perm())
	}
	if err := database.view(func(transaction *bbolt.Tx) error {
		for _, name := range requiredBuckets {
			if transaction.Bucket(name) == nil {
				t.Fatalf("missing bucket %q", name)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestOpenUpgradesLegacySchemaOneWithBaselineHistoryBucket(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "legacy.db")
	legacy, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Update(func(tx *bbolt.Tx) error {
		meta, err := tx.CreateBucket(bucketMeta)
		if err != nil {
			return err
		}
		encoded := make([]byte, 8)
		binary.BigEndian.PutUint64(encoded, SchemaVersion)
		if err := meta.Put(keySchemaVersion, encoded); err != nil {
			return err
		}
		for _, name := range requiredBuckets[1:] {
			if bytes.Equal(name, bucketBaselineHistory) {
				continue
			}
			if _, err := tx.CreateBucket(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	database, err := Open(path, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.view(func(tx *bbolt.Tx) error {
		if tx.Bucket(bucketBaselineHistory) == nil {
			t.Fatal("missing initialized history bucket")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entries, err := database.ListBaselineHistory([32]byte{1})
	if err != nil || len(entries) != 0 {
		t.Fatalf("legacy history operation=%v err=%v", entries, err)
	}
}

func TestOpenRejectsNewerSchemaAndUnsafeDirectory(t *testing.T) {
	privateDirectory := t.TempDir()
	if err := os.Chmod(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(privateDirectory, "newer.db")
	database, err := bbolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Update(func(transaction *bbolt.Tx) error {
		meta, createErr := transaction.CreateBucket(bucketMeta)
		if createErr != nil {
			return createErr
		}
		encoded := make([]byte, 8)
		binary.BigEndian.PutUint64(encoded, SchemaVersion+1)
		return meta.Put(keySchemaVersion, encoded)
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, DefaultOptions()); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("got %v, want ErrNewerSchema", err)
	}

	unsafeDirectory := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Mkdir(unsafeDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafeDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(unsafeDirectory, "gateway.db"), DefaultOptions()); !errors.Is(err, ErrPermissions) {
		t.Fatalf("unsafe directory got %v, want ErrPermissions", err)
	}
}

func TestBeginEnrollmentSecretAvoidsPlaintextStringStorage(t *testing.T) {
	database, _, _ := openTestStore(t)
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base64.RawURLEncoding.DecodeString(issued.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := database.BeginEnrollmentSecret(secret, digestWithFirstByte(0x18))
	if err != nil {
		t.Fatal(err)
	}
	clear(secret)
	if pending.TokenDigest != issued.Digest {
		t.Fatalf("token digest got %x, want %x", pending.TokenDigest, issued.Digest)
	}
}

func TestCompleteEnrollmentConsumesTokenAtomically(t *testing.T) {
	database, now, path := openTestStore(t)
	issued, err := database.CreateEnrollment(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transcript := digestWithFirstByte(9)
	pending, err := database.BeginEnrollment(issued.Plaintext, transcript)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := database.BeginEnrollment(issued.Plaintext, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate != pending {
		t.Fatalf("duplicate begin changed pending record: %#v != %#v", duplicate, pending)
	}
	host := softwareHost(*now, 4)
	if err := database.CompleteEnrollment(pending.ID, host); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BeginEnrollment(issued.Plaintext, transcript); !errors.Is(err, ErrTokenConsumed) {
		t.Fatalf("got %v, want ErrTokenConsumed", err)
	}
	stored, err := database.GetHost(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if stored.String() != host.String() || !bytes.Equal(stored.IdentityCOSEKey, host.IdentityCOSEKey) {
		t.Fatalf("stored host differs: %#v", stored)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(issued.Plaintext)) {
		t.Fatal("database contains plaintext enrollment token")
	}
}

func TestExpiryRevocationTranscriptCollisionAndRateLimit(t *testing.T) {
	database, now, _ := openTestStore(t)
	expiring, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if _, err := database.BeginEnrollment(expiring.Plaintext, digestWithFirstByte(1)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expiry boundary got %v, want ErrTokenExpired", err)
	}

	*now = now.Add(-time.Minute)
	revoked, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RevokeEnrollment(revoked.Digest); err != nil {
		t.Fatal(err)
	}
	if _, err := database.BeginEnrollment(revoked.Plaintext, digestWithFirstByte(2)); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("revoked token got %v, want ErrTokenRevoked", err)
	}

	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(3)); err != nil {
		t.Fatal(err)
	}
	for attempt := uint32(0); attempt < MaxTranscriptMismatches; attempt++ {
		if _, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(byte(10+attempt))); !errors.Is(err, ErrTranscriptMismatch) {
			t.Fatalf("attempt %d got %v, want ErrTranscriptMismatch", attempt, err)
		}
	}
	if _, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(99)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("got %v, want ErrRateLimited", err)
	}
}

func TestCompleteEnrollmentRollbackAndConcurrency(t *testing.T) {
	database, now, _ := openTestStore(t)
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(7))
	if err != nil {
		t.Fatal(err)
	}
	host := softwareHost(*now, 7)
	injected := errors.New("injected transaction failure")
	database.completeHook = func() error { return injected }
	if err := database.CompleteEnrollment(pending.ID, host); !errors.Is(err, injected) {
		t.Fatalf("got %v, want injected failure", err)
	}
	if _, err := database.GetHost(host.Fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback left host record: %v", err)
	}
	enrollment, err := database.GetEnrollment(issued.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.State != EnrollmentPending {
		t.Fatalf("rollback left state %q, want pending", enrollment.State)
	}
	database.completeHook = nil

	var wait sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- database.CompleteEnrollment(pending.ID, host)
		}()
	}
	wait.Wait()
	close(results)
	var successes, completed int
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrEnrollmentComplete):
			completed++
		default:
			t.Fatalf("unexpected concurrent result: %v", result)
		}
	}
	if successes != 1 || completed != 1 {
		t.Fatalf("successes=%d completed=%d", successes, completed)
	}
}

func TestCompleteEnrollmentEvidenceIsAtomic(t *testing.T) {
	database, now, _ := openTestStore(t)
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(0x31))
	if err != nil {
		t.Fatal(err)
	}
	baseline := []byte("canonical-controlled-baseline")
	host := softwareHost(*now, 0x32)
	host.BaselineID = sha256.Sum256(baseline)
	receipt := []byte{0xd2, 0x84, 0x01, 0x02}
	injected := errors.New("evidence transaction failure")
	database.completeHook = func() error { return injected }
	if err := database.CompleteEnrollmentEvidence(pending.ID, host, baseline, receipt); !errors.Is(err, injected) {
		t.Fatalf("rollback got %v, want injected error", err)
	}
	if _, err := database.GetHost(host.Fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback left host: %v", err)
	}
	if _, err := database.GetBaseline(host.BaselineID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback left baseline: %v", err)
	}
	if _, err := database.GetReceipt(host.Fingerprint); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rollback left receipt: %v", err)
	}
	database.completeHook = nil
	if err := database.CompleteEnrollmentEvidence(pending.ID, host, baseline, receipt); err != nil {
		t.Fatal(err)
	}
	storedBaseline, err := database.GetBaseline(host.BaselineID)
	if err != nil || !bytes.Equal(storedBaseline, baseline) {
		t.Fatalf("baseline got %x, %v", storedBaseline, err)
	}
	storedReceipt, err := database.GetReceipt(host.Fingerprint)
	if err != nil || !bytes.Equal(storedReceipt, receipt) {
		t.Fatalf("receipt got %x, %v", storedReceipt, err)
	}
	baseline[0] ^= 0xff
	receipt[0] ^= 0xff
	storedBaseline, _ = database.GetBaseline(host.BaselineID)
	storedReceipt, _ = database.GetReceipt(host.Fingerprint)
	if bytes.Equal(storedBaseline, baseline) || bytes.Equal(storedReceipt, receipt) {
		t.Fatal("stored enrollment evidence aliases caller buffers")
	}
}

func TestCompletedEnrollmentTranscriptSurvivesRestartForExactRetry(t *testing.T) {
	database, now, path := openTestStore(t)
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(0x39))
	if err != nil {
		t.Fatal(err)
	}
	baseline := []byte("durable-enrollment-baseline")
	host := softwareHost(*now, 0x3a)
	host.BaselineID = sha256.Sum256(baseline)
	receipt := []byte{0xd2, 0x84, 0x18, 0x29}
	var requestID [16]byte
	requestID[0] = 0x3b
	envelopeDigest := digestWithFirstByte(0x3c)
	if err := database.CompleteEnrollmentTranscript(
		pending.ID, host, baseline, receipt, requestID, envelopeDigest,
	); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, Options{
		Clock: func() time.Time { return *now }, Random: deterministicEntropy(), OpenTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	stored, err := reopened.GetCompletedEnrollment(requestID, envelopeDigest)
	if err != nil || !bytes.Equal(stored, receipt) {
		t.Fatalf("completed retry got %x, %v", stored, err)
	}
	wrongDigest := envelopeDigest
	wrongDigest[0] ^= 1
	if _, err := reopened.GetCompletedEnrollment(requestID, wrongDigest); !errors.Is(err, ErrTranscriptMismatch) {
		t.Fatalf("wrong retry digest got %v", err)
	}
}

func TestCompleteEnrollmentEvidenceRejectsDigestMismatch(t *testing.T) {
	database, now, _ := openTestStore(t)
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := database.BeginEnrollment(issued.Plaintext, digestWithFirstByte(0x41))
	if err != nil {
		t.Fatal(err)
	}
	host := softwareHost(*now, 0x42)
	if err := database.CompleteEnrollmentEvidence(
		pending.ID, host, []byte("wrong baseline"), []byte{1}); !errors.Is(err, ErrArgument) {
		t.Fatalf("digest mismatch got %v, want ErrArgument", err)
	}
}

func TestCanonicalRecordsListingAndAntiRollbackPolicy(t *testing.T) {
	database, now, _ := openTestStore(t)
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.view(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(bucketTokens).Get(issued.Digest[:])
		if encoded == nil {
			t.Fatal("missing token record")
		}
		var record tokenRecord
		if err := database.decodeCanonical(encoded, &record); err != nil {
			t.Fatal(err)
		}
		reencoded, err := database.encode(record)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatal("stored token record is not canonical")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, fingerprint := range []byte{9, 3} {
		created, err := database.CreateEnrollment(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := database.BeginEnrollment(created.Plaintext, digestWithFirstByte(fingerprint))
		if err != nil {
			t.Fatal(err)
		}
		if err := database.CompleteEnrollment(pending.ID, softwareHost(*now, fingerprint)); err != nil {
			t.Fatal(err)
		}
	}
	hosts, err := database.ListHosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0].Fingerprint[0] != 3 || hosts[1].Fingerprint[0] != 9 {
		t.Fatalf("hosts not deterministically ordered: %#v", hosts)
	}

	policyID := digestWithFirstByte(0x44)
	policy := []byte{0xa1, 0x01, 0x02}
	if err := database.PutAntiRollbackPolicy(policyID, policy); err != nil {
		t.Fatal(err)
	}
	policy[0] = 0
	if err := database.view(func(transaction *bbolt.Tx) error {
		stored := transaction.Bucket(bucketAntiRollback).Get(policyID[:])
		if !bytes.Equal(stored, []byte{0xa1, 0x01, 0x02}) {
			t.Fatalf("stored policy aliases caller: %x", stored)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func controlledBytes(t *testing.T, marker byte) []byte {
	t.Helper()
	var measurement, db, dbx, firmware [32]byte
	measurement[0], db[0], dbx[0], firmware[0] = marker, marker+1, marker+2, marker+3
	encoded, err := controlled.Encode(controlled.Controlled{Record: controlled.Record{Version: 1, MeasurementDigest: measurement,
		SecureBoot: true, DBDigest: db, DBXDigest: dbx, FirmwareDigest: firmware}, MemoryMiB: 4096, StorageGiB: 128, BlockDevices: 1})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signedStoreApproval(t *testing.T, host [32]byte, parent, updated []byte, now time.Time) baselineupdate.Approval {
	t.Helper()
	return signedStoreApprovalWindow(t, host, parent, updated, now.Add(-time.Minute), now.Add(time.Hour), now)
}

func signedStoreApprovalWindow(t *testing.T, host [32]byte, parent, updated []byte, issued, expires, verifiedAt time.Time) baselineupdate.Approval {
	t.Helper()
	admin, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&admin.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kid := sha256.Sum256(der)
	proposal, err := baselineupdate.CreateProposal(host, sha256.Sum256(parent), parent, updated, baselineupdate.ChangeSecurity, issued, expires, kid)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := baselineupdate.DecodeProposal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, admin)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Headers.Protected[cose.HeaderLabelKeyID] = kid[:]
	message.Payload = proposal
	if err := message.Sign(rand.Reader, baselineupdate.ApprovalAAD(decoded), signer); err != nil {
		t.Fatal(err)
	}
	signature, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := baselineupdate.VerifyApproval(proposal, signature, &admin.PublicKey, verifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	return approval
}

func TestBaselineUpdateAtomicRollbackAndAppendOnlyHistory(t *testing.T) {
	database, now, _ := openTestStore(t)
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
	initial, updated := controlledBytes(t, 1), controlledBytes(t, 9)
	host := softwareHost(*now, 0x61)
	host.BaselineID = sha256.Sum256(initial)
	if err := database.CompleteEnrollmentEvidence(pending.ID, host, initial, []byte{1}); err != nil {
		t.Fatal(err)
	}
	verificationNow := *now
	approval := signedStoreApproval(t, host.Fingerprint, initial, updated, verificationNow)
	*now = now.Add(time.Minute)
	updatedID := sha256.Sum256(updated)
	injected := errors.New("baseline transaction failure")
	database.baselineUpdateHook = func() error { return injected }
	if err := database.ApplyBaselineApproval(approval); !errors.Is(err, injected) {
		t.Fatalf("got %v", err)
	}
	stored, _ := database.GetHost(host.Fingerprint)
	if stored.BaselineID != host.BaselineID {
		t.Fatal("rollback changed active baseline")
	}
	if _, err := database.GetBaseline(updatedID); !errors.Is(err, ErrNotFound) {
		t.Fatal("rollback retained baseline")
	}
	entries, err := database.ListBaselineHistory(host.Fingerprint)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rollback history=%v err=%v", entries, err)
	}
	database.baselineUpdateHook = nil
	if err := database.ApplyBaselineApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := database.ApplyBaselineApproval(approval); !errors.Is(err, ErrBaselineStale) {
		t.Fatalf("stale repeat=%v", err)
	}
	entries, err = database.ListBaselineHistory(host.Fingerprint)
	if err != nil || len(entries) != 1 || entries[0].NewBaselineID != updatedID || entries[0].ParentBaselineID != host.BaselineID {
		t.Fatalf("history=%v err=%v", entries, err)
	}
	if entries[0].ApprovedAtUnixNS != now.UnixNano() || entries[0].ApprovedAtUnixNS == verificationNow.UnixNano() {
		t.Fatalf("history timestamp=%d want later transaction clock %d, not verification %d", entries[0].ApprovedAtUnixNS, now.UnixNano(), verificationNow.UnixNano())
	}
}

func TestBaselineApprovalRechecksTransactionClockWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		advance   func(time.Time) time.Time
		wrapClock bool
	}{
		{"expiry", func(now time.Time) time.Time { return now.Add(time.Hour) }, false},
		{"zero", func(time.Time) time.Time { return time.Time{} }, false},
		{"pre-range", func(time.Time) time.Time { return time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC) }, false},
		{"post-range", func(time.Time) time.Time { return time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC) }, false},
		{"post-range-wrap", func(time.Time) time.Time { return time.Date(2614, time.January, 1, 0, 0, 0, 0, time.UTC) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			database, now, _ := openTestStore(t)
			issued, err := database.CreateEnrollment(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := database.BeginEnrollment(issued.Plaintext, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			initial, updated := controlledBytes(t, 1), controlledBytes(t, 9)
			host := softwareHost(*now, 0x71)
			host.BaselineID = sha256.Sum256(initial)
			if err := database.CompleteEnrollmentEvidence(pending.ID, host, initial, []byte{1}); err != nil {
				t.Fatal(err)
			}
			transactionClock := tc.advance(*now)
			verificationClock := *now
			if tc.wrapClock {
				verificationClock = time.Unix(0, transactionClock.UnixNano()).UTC()
			}
			expires := verificationClock.Add(time.Hour)
			approval := signedStoreApprovalWindow(t, host.Fingerprint, initial, updated, verificationClock, expires, expires.Add(-time.Nanosecond))
			*now = transactionClock
			if err := database.ApplyBaselineApproval(approval); !errors.Is(err, baselineupdate.ErrAuthorization) {
				t.Fatalf("invalid transaction clock approval=%v", err)
			}
			stored, err := database.GetHost(host.Fingerprint)
			if err != nil || stored.BaselineID != host.BaselineID {
				t.Fatalf("host mutated after invalid clock: %#v %v", stored, err)
			}
			if _, err := database.GetBaseline(sha256.Sum256(updated)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("invalid clock wrote baseline: %v", err)
			}
			history, err := database.ListBaselineHistory(host.Fingerprint)
			if err != nil || len(history) != 0 {
				t.Fatalf("invalid clock wrote history=%v err=%v", history, err)
			}
		})
	}
}
