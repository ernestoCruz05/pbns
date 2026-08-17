package enrollment

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	controlledbaseline "pbns.local/gateway/internal/baseline"
	"pbns.local/gateway/internal/cosebridge"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/store"
)

func canonicalBaseline(t *testing.T) []byte {
	t.Helper()
	encoded, err := controlledbaseline.Encode(controlledbaseline.Controlled{
		Record: controlledbaseline.Record{
			Version: 1, MeasurementDigest: sha256.Sum256([]byte("measured")),
			SecureBoot: true, SetupMode: false,
			DBDigest: sha256.Sum256([]byte("db")), DBXDigest: sha256.Sum256([]byte("dbx")),
			FirmwareDigest: controlledbaseline.FirmwareIdentity("vendor", "1"),
			Inventory:      controlledbaseline.InventoryRule{},
		},
		MemoryMiB: 4096, StorageGiB: 64, BlockDevices: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type serviceFixture struct {
	service        *Service
	database       *store.Store
	token          [32]byte
	recipient      *ecdsa.PrivateKey
	recipientKID   []byte
	hostKey        *ecdsa.PrivateKey
	identityCOSE   []byte
	fingerprint    [32]byte
	enrollmentKey  *ecdsa.PrivateKey
	enrollmentKID  []byte
	now            time.Time
	requestID      [16]byte
	hostNonce      [32]byte
	baseline       []byte
	baselineDigest [32]byte
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	now := time.Unix(1_900_000_000, 0).UTC()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(directory, "gateway.db"), store.Options{
		Clock: func() time.Time { return now }, Random: rand.Reader, OpenTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(issued.Plaintext)
	if err != nil || len(tokenBytes) != 32 {
		t.Fatal("decode issued token")
	}
	var token [32]byte
	copy(token[:], tokenBytes)
	clear(tokenBytes)
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentKID := []byte("enrollment-signing-key-1")
	signer, err := keys.NewPinnedOnlineSigner(keys.RoleEnrollment, enrollmentKID, enrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityCOSE := encodeIdentityCOSEKey(t, &hostKey.PublicKey)
	fingerprint := sha256.Sum256(identityCOSE)
	fixture := &serviceFixture{
		database: database, token: token, recipient: recipient,
		recipientKID: []byte("enrollment-recipient-1"), hostKey: hostKey,
		identityCOSE: identityCOSE, fingerprint: fingerprint,
		enrollmentKey: enrollmentKey, enrollmentKID: enrollmentKID, now: now,
		baseline: canonicalBaseline(t),
	}
	fixture.baselineDigest = sha256.Sum256(fixture.baseline)
	for index := range fixture.requestID {
		fixture.requestID[index] = byte(index + 1)
	}
	for index := range fixture.hostNonce {
		fixture.hostNonce[index] = byte(index + 0x21)
	}
	fixture.service, err = NewService(Config{
		Store: database, RecipientKey: recipient, RecipientKID: fixture.recipientKID,
		Signer: signer, Clock: func() time.Time { return now }, Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func encodeIdentityCOSEKey(t *testing.T, public *ecdsa.PublicKey) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	x := public.X.FillBytes(make([]byte, 32))
	y := public.Y.FillBytes(make([]byte, 32))
	encoded, err := mode.Marshal(map[int64]any{
		1: int64(2), -1: int64(1), -2: x, -3: y,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (fixture *serviceFixture) init() Init {
	return Init{
		Context: CommonContext{
			Domain: Domain, Version: 1, Service: ServiceEnrollment,
			RequestID: fixture.requestID, HostFingerprint: fixture.fingerprint,
			Nonce: fixture.hostNonce, Stage: StageInit, Sequence: 0,
			KeyID: append([]byte(nil), fixture.recipientKID...),
		},
		Token: fixture.token, IdentityCOSEKey: append([]byte(nil), fixture.identityCOSE...),
		InitialEvidenceDigest: fixture.baselineDigest, HostNonce: fixture.hostNonce,
		Flow: FlowSoftware,
	}
}

func (fixture *serviceFixture) sealInit(t *testing.T, init Init) ([]byte, []byte) {
	t.Helper()
	plaintext, err := encodeCanonical(init)
	if err != nil {
		t.Fatal(err)
	}
	envelope := fixture.seal(t, plaintext)
	return envelope, plaintext
}

func (fixture *serviceFixture) seal(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	aad := envelopeAAD(fixture.requestID, fixture.hostNonce, fixture.recipientKID)
	ciphertext, err := cosebridge.Encrypt(
		&fixture.recipient.PublicKey, fixture.recipientKID, plaintext, aad,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeCanonical(EncryptedEnvelope{
		RequestID: fixture.requestID, HostNonce: fixture.hostNonce,
		RecipientKID: append([]byte(nil), fixture.recipientKID...), Ciphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEnvelopeAADMatchesPortableProfile(t *testing.T) {
	requestID := [16]byte{1, 2, 3, 4}
	hostNonce := [32]byte{5, 6, 7, 8}
	keyID := []byte("enrollment-recipient-1")
	expected := make([]byte, 0, len("PBNS-ENROLLMENT-ENVELOPE-v1")+
		len(requestID)+len(hostNonce)+len(keyID))
	expected = append(expected, []byte("PBNS-ENROLLMENT-ENVELOPE-v1")...)
	expected = append(expected, requestID[:]...)
	expected = append(expected, hostNonce[:]...)
	expected = append(expected, keyID...)
	if actual := envelopeAAD(requestID, hostNonce, keyID); !bytes.Equal(actual, expected) {
		t.Fatal("enrollment envelope AAD differs from the portable profile")
	}
}

func (fixture *serviceFixture) proof(t *testing.T, challenge Challenge) Proof {
	t.Helper()
	return Proof{
		Context: CommonContext{
			Domain: Domain, Version: 1, Service: ServiceEnrollment,
			RequestID: fixture.requestID, HostFingerprint: fixture.fingerprint,
			Nonce: fixture.hostNonce, Stage: StageProof, Sequence: 1,
			KeyID: append([]byte(nil), fixture.recipientKID...),
		},
		ServerNonce: challenge.ServerNonce, InitDigest: challenge.InitDigest,
		BaselineDigest:   fixture.baselineDigest,
		BaselineEvidence: append([]byte(nil), fixture.baseline...), Flow: FlowSoftware,
	}
}

func (fixture *serviceFixture) signedProof(t *testing.T, proof Proof, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignProof(proof, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (fixture *serviceFixture) verifyChallenge(t *testing.T, signed []byte) Challenge {
	t.Helper()
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &fixture.enrollmentKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := VerifyChallenge(
		signed, verifier, fixture.enrollmentKID, fixture.requestID, fixture.hostNonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	return challenge
}

func TestPortableCEnrollmentVectorsAreCanonicalGoObjects(t *testing.T) {
	vectors := []struct {
		name  string
		value any
	}{
		{"software-init.cbor", &Init{}},
		{"software-challenge.cbor", &Challenge{}},
		{"software-proof.cbor", &Proof{}},
		{"software-receipt.cbor", &Receipt{}},
	}
	for _, vector := range vectors {
		encoded, err := os.ReadFile(filepath.Join(
			"..", "..", "..", "tests", "vectors", "enrollment-v1", vector.name,
		))
		if err != nil {
			t.Fatal(err)
		}
		if err := decodeMode.Unmarshal(encoded, vector.value); err != nil {
			t.Fatalf("decode %s: %v", vector.name, err)
		}
		canonical, err := encodeMode.Marshal(vector.value)
		if err != nil {
			t.Fatalf("encode %s: %v", vector.name, err)
		}
		if !bytes.Equal(canonical, encoded) {
			t.Fatalf("%s is not byte-identical canonical CBOR", vector.name)
		}
	}
}

func TestEnrollmentInitCannotLeakTokenThroughFormattingOrStructuredLog(t *testing.T) {
	fixture := newServiceFixture(t)
	initObject := fixture.init()
	for _, rendered := range []string{
		fmt.Sprint(initObject), fmt.Sprintf("%#v", initObject),
	} {
		if rendered != "PBNS enrollment init [redacted]" {
			t.Fatalf("formatted init was not redacted: %s", rendered)
		}
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logger.Info("init", "object", initObject)
	if !strings.Contains(output.String(), "PBNS enrollment init [redacted]") {
		t.Fatalf("structured log did not redact init: %s", output.String())
	}
}

func TestSoftwareEnrollmentCompletesEncryptedTranscript(t *testing.T) {
	fixture := newServiceFixture(t)
	envelope, plaintext := fixture.sealInit(t, fixture.init())
	if bytes.Contains(envelope, fixture.token[:]) ||
		bytes.Contains(envelope, []byte(base64.RawURLEncoding.EncodeToString(fixture.token[:]))) {
		t.Fatal("encrypted envelope contains plaintext enrollment token")
	}
	signedChallenge, err := fixture.service.Begin(envelope)
	if err != nil {
		t.Fatal(err)
	}
	challenge := fixture.verifyChallenge(t, signedChallenge)
	if challenge.Flow != FlowSoftware || len(challenge.CredentialBlob) != 0 ||
		len(challenge.EncryptedSecret) != 0 || challenge.HostNonce != fixture.hostNonce ||
		challenge.InitDigest != sha256.Sum256(plaintext) {
		t.Fatalf("invalid software challenge: %#v", challenge)
	}
	proof := fixture.proof(t, challenge)
	signedProof := fixture.signedProof(t, proof, fixture.hostKey)
	proofEnvelope := fixture.seal(t, signedProof)
	receiptBytes, err := fixture.service.Complete(proofEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	retryReceipt, err := fixture.service.Complete(proofEnvelope)
	if err != nil || !bytes.Equal(retryReceipt, receiptBytes) {
		t.Fatalf("same-process complete retry got %x, %v", retryReceipt, err)
	}
	restartSigner, err := keys.NewPinnedOnlineSigner(
		keys.RoleEnrollment, fixture.enrollmentKID, fixture.enrollmentKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewService(Config{
		Store: fixture.database, RecipientKey: fixture.recipient,
		RecipientKID: fixture.recipientKID, Signer: restartSigner,
		Clock: func() time.Time { return fixture.now }, Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	restartReceipt, err := restarted.Complete(proofEnvelope)
	if err != nil || !bytes.Equal(restartReceipt, receiptBytes) {
		t.Fatalf("restart complete retry got %x, %v", restartReceipt, err)
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, &fixture.enrollmentKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := VerifyReceipt(
		receiptBytes, verifier, fixture.enrollmentKID, fixture.requestID,
		fixture.hostNonce, challenge.ServerNonce,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Assurance != model.AssuranceSoftware || receipt.Fingerprint != fixture.fingerprint ||
		receipt.BaselineDigest != fixture.baselineDigest {
		t.Fatalf("invalid receipt: %#v", receipt)
	}
	host, err := fixture.database.GetHost(fixture.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if host.Assurance != model.AssuranceSoftware || !bytes.Equal(host.IdentityCOSEKey, fixture.identityCOSE) {
		t.Fatalf("invalid host: %#v", host)
	}
	baseline, err := fixture.database.GetBaseline(fixture.baselineDigest)
	if err != nil || !bytes.Equal(baseline, fixture.baseline) {
		t.Fatalf("stored baseline %x, %v", baseline, err)
	}
}

func legacyEnrollmentBaseline(t *testing.T) []byte {
	t.Helper()
	digest := func(value byte) []byte { return bytes.Repeat([]byte{value}, 32) }
	pcrs := []map[uint64]any{
		{1: uint64(0), 2: digest(0x50)},
		{1: uint64(2), 2: digest(0x51)},
		{1: uint64(4), 2: digest(0x52)},
		{1: uint64(7), 2: digest(0x53)},
	}
	encoded, err := encodeCanonical(map[uint64]any{
		1: "PBNS-ENROLLMENT-BASELINE-v1", 2: digest(0x11), 3: digest(0x22),
		4: true, 5: false, 6: digest(0x33), 7: digest(0x44), 8: pcrs,
		9: []byte("canonical legacy event log"), 10: digest(0x66),
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestEnrollmentRejectsLegacyCanonicalBaseline(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.baseline = legacyEnrollmentBaseline(t)
	fixture.baselineDigest = sha256.Sum256(fixture.baseline)
	envelope, _ := fixture.sealInit(t, fixture.init())
	signedChallenge, err := fixture.service.Begin(envelope)
	if err != nil {
		t.Fatal(err)
	}
	proof := fixture.proof(t, fixture.verifyChallenge(t, signedChallenge))
	_, err = fixture.service.Complete(
		fixture.seal(t, fixture.signedProof(t, proof, fixture.hostKey)),
	)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("legacy baseline got %v, want ErrAuthentication", err)
	}
}

func TestEnrollmentRejectsAADReplayAndSubstitution(t *testing.T) {
	fixture := newServiceFixture(t)
	envelope, _ := fixture.sealInit(t, fixture.init())
	changed := append([]byte(nil), envelope...)
	changed[len(changed)-1] ^= 1
	if _, err := fixture.service.Begin(changed); err == nil {
		t.Fatal("corrupted encrypted init accepted")
	}
	if _, err := fixture.service.Begin(envelope); err != nil {
		t.Fatal(err)
	}
	substituted := fixture.init()
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	substituted.IdentityCOSEKey = encodeIdentityCOSEKey(t, &otherKey.PublicKey)
	substituted.Context.HostFingerprint = sha256.Sum256(substituted.IdentityCOSEKey)
	subEnvelope, _ := fixture.sealInit(t, substituted)
	if _, err := fixture.service.Begin(subEnvelope); !errors.Is(err, ErrTranscript) {
		t.Fatalf("substituted init got %v, want ErrTranscript", err)
	}
}

func TestEnrollmentRejectsChallengeAndProofTampering(t *testing.T) {
	fixture := newServiceFixture(t)
	envelope, _ := fixture.sealInit(t, fixture.init())
	signedChallenge, err := fixture.service.Begin(envelope)
	if err != nil {
		t.Fatal(err)
	}
	corruptedChallenge := append([]byte(nil), signedChallenge...)
	corruptedChallenge[len(corruptedChallenge)-1] ^= 1
	verifier, _ := cose.NewVerifier(cose.AlgorithmES256, &fixture.enrollmentKey.PublicKey)
	if _, err := VerifyChallenge(
		corruptedChallenge, verifier, fixture.enrollmentKID, fixture.requestID,
		fixture.hostNonce,
	); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("corrupted challenge got %v", err)
	}
	challenge := fixture.verifyChallenge(t, signedChallenge)
	proof := fixture.proof(t, challenge)
	proof.ServerNonce[0] ^= 1
	if _, err := fixture.service.Complete(
		fixture.seal(t, fixture.signedProof(t, proof, fixture.hostKey)),
	); !errors.Is(err, ErrTranscript) {
		t.Fatalf("wrong server nonce got %v, want ErrTranscript", err)
	}
}

func TestEnrollmentRejectsWrongIdentityBaselineAndFakeActivation(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(*Proof)
		key  func(*serviceFixture) *ecdsa.PrivateKey
	}{
		{name: "wrong-identity", key: func(*serviceFixture) *ecdsa.PrivateKey {
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return key
		}},
		{name: "wrong-baseline", fn: func(proof *Proof) { proof.BaselineEvidence[0] ^= 1 }},
		{name: "fake-activation", fn: func(proof *Proof) { proof.ActivatedCredential = []byte("fake") }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			envelope, _ := fixture.sealInit(t, fixture.init())
			signedChallenge, err := fixture.service.Begin(envelope)
			if err != nil {
				t.Fatal(err)
			}
			proof := fixture.proof(t, fixture.verifyChallenge(t, signedChallenge))
			if mutate.fn != nil {
				mutate.fn(&proof)
			}
			key := fixture.hostKey
			if mutate.key != nil {
				key = mutate.key(fixture)
			}
			_, err = fixture.service.Complete(fixture.seal(t, fixture.signedProof(t, proof, key)))
			if !errors.Is(err, ErrAuthentication) && !errors.Is(err, ErrTranscript) {
				t.Fatalf("tampered proof got %v", err)
			}
		})
	}
}

func TestConcurrentProofConsumesTokenExactlyOnce(t *testing.T) {
	fixture := newServiceFixture(t)
	envelope, _ := fixture.sealInit(t, fixture.init())
	signedChallenge, err := fixture.service.Begin(envelope)
	if err != nil {
		t.Fatal(err)
	}
	proof := fixture.proof(t, fixture.verifyChallenge(t, signedChallenge))
	proofEnvelope := fixture.seal(t, fixture.signedProof(t, proof, fixture.hostKey))
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := fixture.service.Complete(proofEnvelope)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err != nil {
			t.Fatalf("idempotent concurrent completion failed: %v", err)
		}
		successes++
	}
	if successes != 2 {
		t.Fatalf("successes=%d", successes)
	}
	tokenDigest := sha256.Sum256(fixture.token[:])
	enrollment, err := fixture.database.GetEnrollment(tokenDigest)
	if err != nil || enrollment.State != store.EnrollmentConsumed {
		t.Fatalf("token state=%q err=%v", enrollment.State, err)
	}
}
