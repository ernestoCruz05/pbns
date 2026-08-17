package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/cosebridge"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/store"
)

type countVerifier struct {
	mutex sync.Mutex
	count int
}

func (verifier *countVerifier) Verify(VerifiedEvidence) error {
	verifier.mutex.Lock()
	defer verifier.mutex.Unlock()
	verifier.count++
	return nil
}

func testStore(t *testing.T, now time.Time) *store.Store {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	value, err := store.Open(filepath.Join(directory, "gateway.db"), store.Options{Clock: func() time.Time { return now }, Random: rand.Reader, OpenTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = value.Close() })
	return value
}
func coseKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	value, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := value.Marshal(map[int64]any{1: int64(2), -1: int64(1), -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func enrolledHost(t *testing.T, value *store.Store, now time.Time) (model.HostRecord, *ecdsa.PrivateKey) {
	t.Helper()
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := coseKey(t, identity)
	host := model.HostRecord{Fingerprint: sha256.Sum256(encoded), IdentityCOSEKey: encoded, AKPublic: []byte{1}, AKName: []byte("ak-name"), EKPublic: []byte{2}, Assurance: model.AssuranceTPMUnverified, BaselineID: [32]byte{1}, EnrolledAtUnix: now.Unix()}
	issued, err := value.CreateEnrollment(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := value.BeginEnrollment(issued.Plaintext, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if err := value.CompleteEnrollment(pending.ID, host); err != nil {
		t.Fatal(err)
	}
	return host, identity
}
func testService(t *testing.T, value *store.Store, now time.Time, verifier EvidenceConsumer) (*Service, *ecdsa.PrivateKey) {
	t.Helper()
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := keys.NewPinnedOnlineSigner(keys.RoleAttestation, []byte("attestation-key"), signingKey)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(Config{Store: value, RecipientKey: recipient, RecipientKID: []byte("recipient"), Signer: signer, Clock: func() time.Time { return now }, Random: rand.Reader, Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}
	return service, recipient
}
func validTestInventory(host [32]byte) InventoryReport {
	return InventoryReport{HostFingerprint: host, FirmwareVendor: "vendor", FirmwareVersion: "version", CPUClass: "x86_64", Outcomes: map[uint64]uint64{1: 0, 2: 0, 3: 0, 4: 0, 5: 0}, Timings: map[uint64]uint64{}}
}

func signedCiphertext(t *testing.T, challenge Challenge, host model.HostRecord, identity *ecdsa.PrivateKey, recipient *ecdsa.PrivateKey) []byte {
	t.Helper()
	inventory := validTestInventory(host.Fingerprint)
	inventoryBytes, err := canonicalMode.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	events := []byte{1}
	selectionDigest, valid := canonicalSelectionDigest(challenge.Selection)
	if !valid {
		t.Fatal("invalid selection")
	}
	evidence := Evidence{Context: challenge.Context, Inventory: inventory, Quote: []byte{1}, QuoteSignature: []byte{2}, PCRValues: []PCRValue{{Algorithm: 11, Index: 0, Value: make([]byte, 32)}, {Algorithm: 11, Index: 2, Value: make([]byte, 32)}, {Algorithm: 11, Index: 4, Value: make([]byte, 32)}, {Algorithm: 11, Index: 7, Value: make([]byte, 32)}}, EventLog: events, AKName: append([]byte(nil), host.AKName...), AKReference: []byte{1}, ReportDigest: sha256.Sum256(inventoryBytes), SelectionDigest: selectionDigest, EventLogDigest: sha256.Sum256(events)}
	payload, err := canonicalMode.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, identity)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Payload = payload
	if err := message.Sign(rand.Reader, signAAD(challenge, evidence.AKName), signer); err != nil {
		t.Fatal(err)
	}
	signed, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cosebridge.Encrypt(&recipient.PublicKey, challenge.RecipientKID, signed, encryptAAD(challenge))
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func TestSubmitValidEvidenceConsumesAndHandsOffOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	counter := &countVerifier{}
	service, recipient := testService(t, value, now, counter)
	issued, err := service.Issue(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := value.GetAttestationChallenge(issued.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := signedCiphertext(t, challengeFromStore(record), host, identity, recipient)
	got, err := service.Submit(context.Background(), issued.RequestID, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest == ([32]byte{}) {
		t.Fatal("missing digest")
	}
	if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); !errors.Is(err, ErrChallenge) {
		t.Fatalf("reuse got %v", err)
	}
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	if counter.count != 1 {
		t.Fatalf("handoffs %d", counter.count)
	}
	state, err := value.GetAttestationChallenge(issued.RequestID)
	if err != nil || state.State != store.AttestationChallengeConsumed || state.FailureReason != store.AttestationAccepted {
		t.Fatalf("state %#v err %v", state, err)
	}
}

func TestFailedEvidenceConsumesChallenge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	service, recipient := testService(t, value, now, &countVerifier{})
	issued, err := service.Issue(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := value.GetAttestationChallenge(issued.RequestID)
	ciphertext := signedCiphertext(t, challengeFromStore(record), host, identity, recipient)
	ciphertext[len(ciphertext)/2] ^= 1
	if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); !errors.Is(err, ErrDecryption) {
		t.Fatalf("mutation: %v", err)
	}
	state, err := value.GetAttestationChallenge(issued.RequestID)
	if err != nil || state.State != store.AttestationChallengeConsumed || state.FailureReason != store.AttestationFailureDecrypt {
		t.Fatalf("failure state %#v err %v", state, err)
	}
}

func TestConcurrentSubmissionOnlyOneCrossesGate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	counter := &countVerifier{}
	service, recipient := testService(t, value, now, counter)
	issued, err := service.Issue(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	record, _ := value.GetAttestationChallenge(issued.RequestID)
	ciphertext := signedCiphertext(t, challengeFromStore(record), host, identity, recipient)
	var group sync.WaitGroup
	successes := 0
	var lock sync.Mutex
	for range 12 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); err == nil {
				lock.Lock()
				successes++
				lock.Unlock()
			}
		}()
	}
	group.Wait()
	if successes != 1 {
		t.Fatalf("successes %d", successes)
	}
	counter.mutex.Lock()
	defer counter.mutex.Unlock()
	if counter.count != 1 {
		t.Fatalf("verifications %d", counter.count)
	}
}

func TestNewServiceRequiresVerifierAndAllowedSelection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	recipient, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signing, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := keys.NewPinnedOnlineSigner(keys.RoleAttestation, []byte("kid"), signing)
	config := Config{Store: value, RecipientKey: recipient, RecipientKID: []byte("recipient"), Signer: signer, Clock: func() time.Time { return now }, Random: rand.Reader}
	if _, err := NewService(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil verifier: %v", err)
	}
	config.Verifier = &countVerifier{}
	config.Selection = model.PCRSelection{{Algorithm: 11, Indices: []uint64{0, 7}}}
	if _, err := NewService(config); !errors.Is(err, ErrInvalid) {
		t.Fatalf("selection: %v", err)
	}
}

func TestSubmitEmptyAndOversizedCiphertextConsume(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, _ := enrolledHost(t, value, now)
	service, _ := testService(t, value, now, &countVerifier{})
	for name, ciphertext := range map[string][]byte{"empty": nil, "oversized": make([]byte, maxEncryptedEvidenceSize+1)} {
		t.Run(name, func(t *testing.T) {
			issued, err := service.Issue(host.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); !errors.Is(err, ErrInvalid) {
				t.Fatalf("submit: %v", err)
			}
			state, err := value.GetAttestationChallenge(issued.RequestID)
			if err != nil || state.State != store.AttestationChallengeConsumed || state.FailureReason != store.AttestationFailureInvalid {
				t.Fatalf("state %#v: %v", state, err)
			}
		})
	}
}

func TestSubmitIdentityAndContextFailuresConsume(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	service, recipient := testService(t, value, now, &countVerifier{})
	for name, mutate := range map[string]func(*Evidence, **ecdsa.PrivateKey){
		"identity": func(_ *Evidence, key **ecdsa.PrivateKey) {
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			*key = other
		},
		"outer-inner": func(evidence *Evidence, _ **ecdsa.PrivateKey) { evidence.Context.Nonce[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			issued, err := service.Issue(host.Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			record, _ := value.GetAttestationChallenge(issued.RequestID)
			challenge := challengeFromStore(record)
			evidence := testEvidence(t, challenge, host)
			key := identity
			mutate(&evidence, &key)
			ciphertext := encryptEvidence(t, challenge, evidence, key, recipient, false)
			if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); err == nil {
				t.Fatal("accepted invalid evidence")
			}
			state, _ := value.GetAttestationChallenge(issued.RequestID)
			if state.State != store.AttestationChallengeConsumed {
				t.Fatalf("state %q", state.State)
			}
		})
	}
}

func TestFullPipelineRejectsNonCanonicalEvidenceAndForbiddenInventory(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	service, recipient := testService(t, value, now, &countVerifier{})
	for name, noncanonical := range map[string]bool{"noncanonical": true, "canonical": false} {
		t.Run(name, func(t *testing.T) {
			issued, _ := service.Issue(host.Fingerprint)
			record, _ := value.GetAttestationChallenge(issued.RequestID)
			challenge := challengeFromStore(record)
			evidence := testEvidence(t, challenge, host)
			if !noncanonical {
				evidence.Inventory.FirmwareVendor = string(bytes.Repeat([]byte("sentinel-raw-identifier"), 6))
			}
			ciphertext := encryptEvidence(t, challenge, evidence, identity, recipient, noncanonical)
			if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); err == nil {
				t.Fatal("accepted boundary violation")
			}
		})
	}
}

func TestFinishFailureIsJoinedWithValidationFailure(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, _ := enrolledHost(t, value, now)
	service, _ := testService(t, value, now, &countVerifier{})
	issued, _ := service.Issue(host.Fingerprint)
	finish := errors.New("finish write failed")
	value.SetAttestationFinishHookForTest(func() error { return finish })
	_, err := service.Submit(context.Background(), issued.RequestID, nil)
	if !errors.Is(err, ErrInvalid) || !errors.Is(err, finish) {
		t.Fatalf("joined error %v", err)
	}
	state, _ := value.GetAttestationChallenge(issued.RequestID)
	if state.State != store.AttestationChallengeProcessing {
		t.Fatalf("unexpected state %q", state.State)
	}
}

func testEvidence(t *testing.T, challenge Challenge, host model.HostRecord) Evidence {
	t.Helper()
	inventory := validTestInventory(host.Fingerprint)
	inventoryBytes, err := canonicalMode.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	selectionDigest, valid := canonicalSelectionDigest(challenge.Selection)
	if !valid {
		t.Fatal("invalid selection")
	}
	events := []byte{1}
	return Evidence{Context: challenge.Context, Inventory: inventory, Quote: []byte{1}, QuoteSignature: []byte{2}, PCRValues: []PCRValue{{Algorithm: 11, Index: 0, Value: make([]byte, 32)}, {Algorithm: 11, Index: 2, Value: make([]byte, 32)}, {Algorithm: 11, Index: 4, Value: make([]byte, 32)}, {Algorithm: 11, Index: 7, Value: make([]byte, 32)}}, EventLog: events, AKName: append([]byte(nil), host.AKName...), AKReference: []byte{1}, ReportDigest: sha256.Sum256(inventoryBytes), SelectionDigest: selectionDigest, EventLogDigest: sha256.Sum256(events)}
}
func encryptEvidence(t *testing.T, challenge Challenge, evidence Evidence, identity *ecdsa.PrivateKey, recipient *ecdsa.PrivateKey, noncanonical bool) []byte {
	return encryptEvidenceWithRecipient(t, challenge, evidence, identity, recipient, challenge.RecipientKID, noncanonical)
}
func encryptEvidenceWithRecipient(t *testing.T, challenge Challenge, evidence Evidence, identity *ecdsa.PrivateKey, recipient *ecdsa.PrivateKey, recipientKID []byte, options ...bool) []byte {
	t.Helper()
	noncanonical := len(options) != 0 && options[0]
	payload, err := canonicalMode.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if noncanonical {
		if payload[0] != 0xab {
			t.Fatal("unexpected evidence map")
		}
		payload = append([]byte{0xb8, 0x0b}, payload[1:]...)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, identity)
	if err != nil {
		t.Fatal(err)
	}
	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	message.Payload = payload
	if err := message.Sign(rand.Reader, signAAD(challenge, evidence.AKName), signer); err != nil {
		t.Fatal(err)
	}
	signed, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cosebridge.Encrypt(&recipient.PublicKey, recipientKID, signed, encryptAAD(challenge))
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func TestChallengeExpiryAndDuplicateID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	current := now
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	value, err := store.Open(filepath.Join(directory, "gateway.db"), store.Options{Clock: func() time.Time { return current }, Random: rand.Reader, OpenTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	challenge := store.AttestationChallenge{RequestID: [16]byte{1}, HostFingerprint: [32]byte{2}, VerifierNonce: [32]byte{3}, Selection: defaultSelection.Clone(), RecipientKID: []byte("recipient"), IssuedAtUnixNS: now.UnixNano(), ExpiresAtUnixNS: now.Add(time.Second).UnixNano()}
	if err := value.CreateAttestationChallenge(challenge); err != nil {
		t.Fatal(err)
	}
	if err := value.CreateAttestationChallenge(challenge); !errors.Is(err, store.ErrChallengeExists) {
		t.Fatalf("duplicate: %v", err)
	}
	current = now.Add(time.Second)
	if _, err := value.BeginAttestationChallenge(challenge.RequestID); !errors.Is(err, store.ErrChallengeExpired) {
		t.Fatalf("expiry: %v", err)
	}
	state, err := value.GetAttestationChallenge(challenge.RequestID)
	if err != nil || state.State != store.AttestationChallengeExpired {
		t.Fatalf("state %#v %v", state, err)
	}
}

func TestSubmitWrongRecipientConsumes(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	service, recipient := testService(t, value, now, &countVerifier{})
	issued, _ := service.Issue(host.Fingerprint)
	record, _ := value.GetAttestationChallenge(issued.RequestID)
	challenge := challengeFromStore(record)
	evidence := testEvidence(t, challenge, host)
	wrong := encryptEvidenceWithRecipient(t, challenge, evidence, identity, recipient, []byte("wrong"))
	if _, err := service.Submit(context.Background(), issued.RequestID, wrong); !errors.Is(err, ErrDecryption) {
		t.Fatalf("recipient: %v", err)
	}
	state, _ := value.GetAttestationChallenge(issued.RequestID)
	if state.State != store.AttestationChallengeConsumed {
		t.Fatalf("state %q", state.State)
	}
}

func TestDecryptedEvidenceSentinelIsNeverLogged(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	value := testStore(t, now)
	host, identity := enrolledHost(t, value, now)
	verifier := &countVerifier{}
	service, recipient := testService(t, value, now, verifier)
	issued, err := service.Issue(host.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := value.GetAttestationChallenge(issued.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	challenge := challengeFromStore(record)
	evidence := testEvidence(t, challenge, host)
	sentinel := []byte("TASK4-PLAINTEXT-SENTINEL")
	evidence.AKReference = append([]byte(nil), sentinel...)
	ciphertext := encryptEvidence(t, challenge, evidence, identity, recipient, false)
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	if _, err := service.Submit(context.Background(), issued.RequestID, ciphertext); err != nil {
		t.Fatal(err)
	}
	verifier.mutex.Lock()
	reached := verifier.count
	verifier.mutex.Unlock()
	if reached != 1 {
		t.Fatalf("verifier handoffs %d", reached)
	}
	if bytes.Contains(logs.Bytes(), sentinel) {
		t.Fatal("decrypted plaintext sentinel reached gateway logs")
	}
}
