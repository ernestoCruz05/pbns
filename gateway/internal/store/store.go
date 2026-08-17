package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"go.etcd.io/bbolt"

	"pbns.local/gateway/internal/baselineupdate"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/token"
)

const (
	SchemaVersion           uint64 = 1
	MaxTranscriptMismatches uint32 = 4
	maxEnrollmentTTL               = 24 * time.Hour
	maxPolicyBytes                 = 65536
	maxBaselineBytes               = 4*1024*1024 + 4096
	maxReceiptBytes                = 65536
	pendingIDBytes                 = 16
)

var (
	ErrArgument           = errors.New("invalid store argument")
	ErrPermissions        = errors.New("unsafe store permissions")
	ErrSchema             = errors.New("invalid store schema")
	ErrNewerSchema        = errors.New("store schema is newer than supported")
	ErrCorrupt            = errors.New("corrupt store record")
	ErrNotFound           = errors.New("store record not found")
	ErrTokenCollision     = errors.New("enrollment token collision")
	ErrTokenInvalid       = errors.New("invalid enrollment token")
	ErrTokenExpired       = errors.New("enrollment token expired")
	ErrTokenRevoked       = errors.New("enrollment token revoked")
	ErrTokenConsumed      = errors.New("enrollment token consumed")
	ErrTranscriptMismatch = errors.New("enrollment transcript mismatch")
	ErrRateLimited        = errors.New("enrollment rate limit exceeded")
	ErrEnrollmentComplete = errors.New("enrollment already complete")
	ErrHostExists         = errors.New("host already enrolled")
	ErrBaselineStale      = errors.New("baseline parent is not active")
	ErrBaselineRollback   = errors.New("baseline rollback is forbidden")
)

var (
	bucketMeta                = []byte("meta")
	bucketTokens              = []byte("tokens")
	bucketPending             = []byte("pending_enrollments")
	bucketHosts               = []byte("hosts")
	bucketBaselines           = []byte("baselines")
	bucketAntiRollback        = []byte("anti_rollback")
	bucketReceipts            = []byte("receipts")
	bucketBaselineHistory     = []byte("baseline_history")
	bucketCompletedEnrollment = []byte("completed_enrollment_transcripts")
	keySchemaVersion          = []byte("schema-version")
	requiredBuckets           = [][]byte{bucketMeta, bucketTokens, bucketPending, bucketHosts, bucketBaselines, bucketAntiRollback, bucketReceipts, bucketBaselineHistory, bucketCompletedEnrollment, bucketAttestationChallenges}
)

type EnrollmentState string

const (
	EnrollmentLive     EnrollmentState = "live"
	EnrollmentPending  EnrollmentState = "pending"
	EnrollmentConsumed EnrollmentState = "consumed"
	EnrollmentRevoked  EnrollmentState = "revoked"
)

type Enrollment struct {
	Digest            [32]byte
	ExpiresAtUnixNano int64
	State             EnrollmentState
	PendingID         [pendingIDBytes]byte
	MismatchAttempts  uint32
}

type Pending struct {
	ID                  [pendingIDBytes]byte `cbor:"1,keyasint"`
	TokenDigest         [32]byte             `cbor:"2,keyasint"`
	TranscriptDigest    [32]byte             `cbor:"3,keyasint"`
	CreatedAtUnixNano   int64                `cbor:"4,keyasint"`
	Completed           bool                 `cbor:"5,keyasint"`
	CompletedAtUnixNano int64                `cbor:"6,keyasint"`
}

type tokenRecord struct {
	ExpiresAtUnixNano int64                `cbor:"1,keyasint"`
	State             EnrollmentState      `cbor:"2,keyasint"`
	PendingID         [pendingIDBytes]byte `cbor:"3,keyasint"`
	MismatchAttempts  uint32               `cbor:"4,keyasint"`
}

type completedEnrollmentRecord struct {
	RequestID      [16]byte `cbor:"1,keyasint"`
	EnvelopeDigest [32]byte `cbor:"2,keyasint"`
	Receipt        []byte   `cbor:"3,keyasint"`
}

type Options struct {
	Clock       func() time.Time
	Random      io.Reader
	OpenTimeout time.Duration
}

func DefaultOptions() Options {
	return Options{
		Clock:       time.Now,
		Random:      rand.Reader,
		OpenTimeout: time.Second,
	}
}

type Store struct {
	database              *bbolt.DB
	clock                 func() time.Time
	random                io.Reader
	encodeMode            cbor.EncMode
	decodeMode            cbor.DecMode
	completeHook          func() error
	attestationFinishHook func() error
	baselineUpdateHook    func() error
}

func Open(path string, options Options) (*Store, error) {
	if path == "" {
		return nil, ErrArgument
	}
	options = normalizeOptions(options)
	if options.Clock == nil || options.Random == nil || options.OpenTimeout <= 0 {
		return nil, ErrArgument
	}
	if err := validateStorePath(path); err != nil {
		return nil, err
	}
	encodeMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("create canonical encoder: %w", err)
	}
	decodeMode, err := (cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   8,
		MaxArrayElements:  16,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}).DecMode()
	if err != nil {
		return nil, fmt.Errorf("create strict decoder: %w", err)
	}
	database, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: options.OpenTimeout})
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	store := &Store{
		database:   database,
		clock:      options.Clock,
		random:     options.Random,
		encodeMode: encodeMode,
		decodeMode: decodeMode,
	}
	if err := validateDatabaseMode(path); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := store.initialize(); err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

func normalizeOptions(options Options) Options {
	defaults := DefaultOptions()
	if options.Clock == nil {
		options.Clock = defaults.Clock
	}
	if options.Random == nil {
		options.Random = defaults.Random
	}
	if options.OpenTimeout == 0 {
		options.OpenTimeout = defaults.OpenTimeout
	}
	return options
}

func validateStorePath(path string) error {
	parent := filepath.Dir(filepath.Clean(path))
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("%w: parent directory", ErrPermissions)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: parent mode %04o", ErrPermissions, info.Mode().Perm())
	}
	if info, err = os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return ErrPermissions
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect store path: %w", err)
	}
	return nil
}

func validateDatabaseMode(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect store mode: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%w: database mode %04o", ErrPermissions, info.Mode().Perm())
	}
	return nil
}

func (store *Store) initialize() error {
	return store.update(func(transaction *bbolt.Tx) error {
		meta, err := transaction.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		version := meta.Get(keySchemaVersion)
		switch {
		case version == nil:
			encoded := make([]byte, 8)
			binary.BigEndian.PutUint64(encoded, SchemaVersion)
			if err := meta.Put(keySchemaVersion, encoded); err != nil {
				return err
			}
		case len(version) != 8:
			return ErrSchema
		case binary.BigEndian.Uint64(version) > SchemaVersion:
			return ErrNewerSchema
		case binary.BigEndian.Uint64(version) != SchemaVersion:
			return ErrSchema
		}
		for _, name := range requiredBuckets[1:] {
			if _, err := transaction.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
}

func (store *Store) Close() error {
	if store == nil || store.database == nil {
		return ErrArgument
	}
	return store.database.Close()
}

func (store *Store) update(callback func(*bbolt.Tx) error) error {
	if store == nil || store.database == nil || callback == nil {
		return ErrArgument
	}
	return store.database.Update(callback)
}

func (store *Store) view(callback func(*bbolt.Tx) error) error {
	if store == nil || store.database == nil || callback == nil {
		return ErrArgument
	}
	return store.database.View(callback)
}

func (store *Store) encode(value any) ([]byte, error) {
	encoded, err := store.encodeMode.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode store record: %w", err)
	}
	return encoded, nil
}

func (store *Store) decodeCanonical(encoded []byte, destination any) error {
	if len(encoded) == 0 || destination == nil {
		return ErrCorrupt
	}
	if err := store.decodeMode.Unmarshal(encoded, destination); err != nil {
		return fmt.Errorf("%w: decode", ErrCorrupt)
	}
	reencoded, err := store.encode(destination)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return ErrCorrupt
	}
	return nil
}

func (store *Store) CreateEnrollment(ttl time.Duration) (token.Issued, error) {
	if ttl <= 0 || ttl > maxEnrollmentTTL {
		return token.Issued{}, ErrArgument
	}
	now := store.clock().UTC()
	if now.IsZero() || now.Unix() <= 0 {
		return token.Issued{}, ErrArgument
	}
	issued, err := token.Generate(store.random, now.Add(ttl))
	if err != nil {
		return token.Issued{}, err
	}
	record := tokenRecord{
		ExpiresAtUnixNano: issued.ExpiresAt.UnixNano(),
		State:             EnrollmentLive,
	}
	encoded, err := store.encode(record)
	if err != nil {
		return token.Issued{}, err
	}
	if err := store.update(func(transaction *bbolt.Tx) error {
		bucket := transaction.Bucket(bucketTokens)
		if bucket.Get(issued.Digest[:]) != nil {
			return ErrTokenCollision
		}
		return bucket.Put(issued.Digest[:], encoded)
	}); err != nil {
		return token.Issued{}, err
	}
	return issued, nil
}

func (store *Store) BeginEnrollment(plaintext string, transcriptDigest [32]byte) (Pending, error) {
	digest, err := token.Digest(plaintext)
	if err != nil {
		return Pending{}, ErrTokenInvalid
	}
	return store.beginEnrollmentDigest(digest, transcriptDigest)
}

func (store *Store) BeginEnrollmentSecret(secret []byte, transcriptDigest [32]byte) (Pending, error) {
	digest, err := token.DigestSecret(secret)
	if err != nil {
		return Pending{}, ErrTokenInvalid
	}
	return store.beginEnrollmentDigest(digest, transcriptDigest)
}

func (store *Store) beginEnrollmentDigest(digest [32]byte, transcriptDigest [32]byte) (Pending, error) {
	if isZero32(transcriptDigest) {
		return Pending{}, ErrArgument
	}
	var pending Pending
	var logicalError error
	err := store.update(func(transaction *bbolt.Tx) error {
		tokens := transaction.Bucket(bucketTokens)
		encoded := tokens.Get(digest[:])
		if encoded == nil {
			logicalError = ErrTokenInvalid
			return nil
		}
		var record tokenRecord
		if err := store.decodeCanonical(encoded, &record); err != nil {
			return err
		}
		switch record.State {
		case EnrollmentConsumed:
			logicalError = ErrTokenConsumed
			return nil
		case EnrollmentRevoked:
			logicalError = ErrTokenRevoked
			return nil
		case EnrollmentLive, EnrollmentPending:
		default:
			return ErrCorrupt
		}
		if store.clock().UTC().UnixNano() >= record.ExpiresAtUnixNano {
			logicalError = ErrTokenExpired
			return nil
		}
		pendingBucket := transaction.Bucket(bucketPending)
		if !isZero16(record.PendingID) {
			pendingEncoded := pendingBucket.Get(record.PendingID[:])
			if pendingEncoded == nil || store.decodeCanonical(pendingEncoded, &pending) != nil {
				return ErrCorrupt
			}
			if pending.TokenDigest != digest {
				return ErrCorrupt
			}
			if pending.TranscriptDigest == transcriptDigest {
				return nil
			}
			if record.MismatchAttempts >= MaxTranscriptMismatches {
				logicalError = ErrRateLimited
				return nil
			}
			record.MismatchAttempts++
			updated, err := store.encode(record)
			if err != nil {
				return err
			}
			if err := tokens.Put(digest[:], updated); err != nil {
				return err
			}
			logicalError = ErrTranscriptMismatch
			return nil
		}
		pendingID, err := store.newPendingID(pendingBucket)
		if err != nil {
			return err
		}
		pending = Pending{
			ID:                pendingID,
			TokenDigest:       digest,
			TranscriptDigest:  transcriptDigest,
			CreatedAtUnixNano: store.clock().UTC().UnixNano(),
		}
		pendingEncoded, err := store.encode(pending)
		if err != nil {
			return err
		}
		if err := pendingBucket.Put(pending.ID[:], pendingEncoded); err != nil {
			return err
		}
		record.State = EnrollmentPending
		record.PendingID = pending.ID
		updated, err := store.encode(record)
		if err != nil {
			return err
		}
		return tokens.Put(digest[:], updated)
	})
	if err != nil {
		return Pending{}, err
	}
	if logicalError != nil {
		return Pending{}, logicalError
	}
	return pending, nil
}

func (store *Store) newPendingID(bucket *bbolt.Bucket) ([pendingIDBytes]byte, error) {
	for range 4 {
		var identifier [pendingIDBytes]byte
		if _, err := io.ReadFull(store.random, identifier[:]); err != nil {
			return [pendingIDBytes]byte{}, fmt.Errorf("pending identifier: %w", token.ErrEntropy)
		}
		if !isZero16(identifier) && bucket.Get(identifier[:]) == nil {
			return identifier, nil
		}
	}
	return [pendingIDBytes]byte{}, ErrTokenCollision
}

func (store *Store) CompleteEnrollment(pendingID [pendingIDBytes]byte, host model.HostRecord) error {
	return store.completeEnrollment(pendingID, host, nil, nil, false, nil)
}

func (store *Store) CompleteEnrollmentEvidence(
	pendingID [pendingIDBytes]byte,
	host model.HostRecord,
	baseline []byte,
	receipt []byte,
) error {
	if len(baseline) == 0 || len(baseline) > maxBaselineBytes ||
		len(receipt) == 0 || len(receipt) > maxReceiptBytes ||
		sha256.Sum256(baseline) != host.BaselineID {
		return ErrArgument
	}
	return store.completeEnrollment(
		pendingID,
		host,
		append([]byte(nil), baseline...),
		append([]byte(nil), receipt...),
		true,
		nil,
	)
}

func (store *Store) CompleteEnrollmentTranscript(
	pendingID [pendingIDBytes]byte,
	host model.HostRecord,
	baseline []byte,
	receipt []byte,
	requestID [16]byte,
	envelopeDigest [32]byte,
) error {
	if len(baseline) == 0 || len(baseline) > maxBaselineBytes ||
		len(receipt) == 0 || len(receipt) > maxReceiptBytes ||
		sha256.Sum256(baseline) != host.BaselineID || isZero16(requestID) ||
		isZero32(envelopeDigest) {
		return ErrArgument
	}
	completed := &completedEnrollmentRecord{
		RequestID: requestID, EnvelopeDigest: envelopeDigest,
		Receipt: append([]byte(nil), receipt...),
	}
	return store.completeEnrollment(
		pendingID, host, append([]byte(nil), baseline...),
		append([]byte(nil), receipt...), true, completed,
	)
}

func (store *Store) completeEnrollment(
	pendingID [pendingIDBytes]byte,
	host model.HostRecord,
	baseline []byte,
	receipt []byte,
	withEvidence bool,
	completed *completedEnrollmentRecord,
) error {
	if isZero16(pendingID) || host.Validate() != nil {
		return ErrArgument
	}
	return store.update(func(transaction *bbolt.Tx) error {
		pendingBucket := transaction.Bucket(bucketPending)
		encoded := pendingBucket.Get(pendingID[:])
		if encoded == nil {
			return ErrNotFound
		}
		var pending Pending
		if err := store.decodeCanonical(encoded, &pending); err != nil {
			return err
		}
		if pending.ID != pendingID || pending.Completed {
			return ErrEnrollmentComplete
		}
		tokens := transaction.Bucket(bucketTokens)
		tokenEncoded := tokens.Get(pending.TokenDigest[:])
		if tokenEncoded == nil {
			return ErrCorrupt
		}
		var record tokenRecord
		if err := store.decodeCanonical(tokenEncoded, &record); err != nil {
			return err
		}
		switch record.State {
		case EnrollmentConsumed:
			return ErrTokenConsumed
		case EnrollmentRevoked:
			return ErrTokenRevoked
		case EnrollmentPending:
		default:
			return ErrCorrupt
		}
		if record.PendingID != pendingID {
			return ErrCorrupt
		}
		now := store.clock().UTC().UnixNano()
		if now >= record.ExpiresAtUnixNano {
			return ErrTokenExpired
		}
		hosts := transaction.Bucket(bucketHosts)
		if hosts.Get(host.Fingerprint[:]) != nil {
			return ErrHostExists
		}
		hostEncoded, err := store.encode(host)
		if err != nil {
			return err
		}
		if err := hosts.Put(host.Fingerprint[:], hostEncoded); err != nil {
			return err
		}
		if withEvidence {
			baselines := transaction.Bucket(bucketBaselines)
			if baselines.Get(host.BaselineID[:]) != nil {
				return ErrHostExists
			}
			if err := baselines.Put(host.BaselineID[:], baseline); err != nil {
				return err
			}
			receipts := transaction.Bucket(bucketReceipts)
			if receipts.Get(host.Fingerprint[:]) != nil {
				return ErrHostExists
			}
			if err := receipts.Put(host.Fingerprint[:], receipt); err != nil {
				return err
			}
		}
		if completed != nil {
			completedBucket := transaction.Bucket(bucketCompletedEnrollment)
			if completedBucket.Get(completed.RequestID[:]) != nil {
				return ErrHostExists
			}
			completedEncoded, err := store.encode(*completed)
			if err != nil {
				return err
			}
			if err := completedBucket.Put(completed.RequestID[:], completedEncoded); err != nil {
				return err
			}
		}
		pending.Completed = true
		pending.CompletedAtUnixNano = now
		pendingEncoded, err := store.encode(pending)
		if err != nil {
			return err
		}
		if err := pendingBucket.Put(pending.ID[:], pendingEncoded); err != nil {
			return err
		}
		record.State = EnrollmentConsumed
		tokenEncoded, err = store.encode(record)
		if err != nil {
			return err
		}
		if err := tokens.Put(pending.TokenDigest[:], tokenEncoded); err != nil {
			return err
		}
		if store.completeHook != nil {
			return store.completeHook()
		}
		return nil
	})
}

func (store *Store) GetCompletedEnrollment(
	requestID [16]byte,
	envelopeDigest [32]byte,
) ([]byte, error) {
	if isZero16(requestID) || isZero32(envelopeDigest) {
		return nil, ErrArgument
	}
	var receipt []byte
	err := store.view(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(bucketCompletedEnrollment).Get(requestID[:])
		if encoded == nil {
			return ErrNotFound
		}
		var record completedEnrollmentRecord
		if err := store.decodeCanonical(encoded, &record); err != nil {
			return err
		}
		if record.RequestID != requestID || len(record.Receipt) == 0 ||
			len(record.Receipt) > maxReceiptBytes {
			return ErrCorrupt
		}
		if record.EnvelopeDigest != envelopeDigest {
			return ErrTranscriptMismatch
		}
		receipt = append([]byte(nil), record.Receipt...)
		return nil
	})
	return receipt, err
}

func (store *Store) GetHost(fingerprint [32]byte) (model.HostRecord, error) {
	if isZero32(fingerprint) {
		return model.HostRecord{}, ErrArgument
	}
	var host model.HostRecord
	err := store.view(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(bucketHosts).Get(fingerprint[:])
		if encoded == nil {
			return ErrNotFound
		}
		if err := store.decodeCanonical(encoded, &host); err != nil {
			return err
		}
		return host.Validate()
	})
	if err != nil {
		return model.HostRecord{}, err
	}
	return host.Clone(), nil
}

func (store *Store) GetBaseline(identifier [32]byte) ([]byte, error) {
	return store.getEvidence(bucketBaselines, identifier)
}

func (store *Store) GetReceipt(fingerprint [32]byte) ([]byte, error) {
	return store.getEvidence(bucketReceipts, fingerprint)
}

type BaselineHistory struct {
	HostFingerprint  [32]byte `cbor:"1,keyasint"`
	ParentBaselineID [32]byte `cbor:"2,keyasint"`
	NewBaselineID    [32]byte `cbor:"3,keyasint"`
	ProposalDigest   [32]byte `cbor:"4,keyasint"`
	ApprovedAtUnixNS int64    `cbor:"5,keyasint"`
}

func validBaselineHistory(history BaselineHistory) bool {
	return !isZero32(history.HostFingerprint) && !isZero32(history.ParentBaselineID) &&
		!isZero32(history.NewBaselineID) && !isZero32(history.ProposalDigest) &&
		history.ParentBaselineID != history.NewBaselineID && history.ApprovedAtUnixNS > 0
}

// ApplyBaselineApproval accepts only an authenticated, immutable approval value.
func (store *Store) ApplyBaselineApproval(approval baselineupdate.Approval) error {
	if store == nil || !approval.Valid() {
		return ErrArgument
	}
	hostFingerprint, parentID, newID := approval.HostFingerprint(), approval.ParentBaselineID(), approval.NewBaselineID()
	owned := approval.NewBaseline()
	if len(owned) == 0 || len(owned) > maxBaselineBytes || sha256.Sum256(owned) != newID {
		return ErrArgument
	}
	return store.update(func(transaction *bbolt.Tx) error {
		hosts := transaction.Bucket(bucketHosts)
		encodedHost := hosts.Get(hostFingerprint[:])
		if encodedHost == nil {
			return ErrNotFound
		}
		var host model.HostRecord
		if err := store.decodeCanonical(encodedHost, &host); err != nil || host.Validate() != nil || host.Fingerprint != hostFingerprint {
			return ErrCorrupt
		}
		if host.BaselineID != parentID {
			return ErrBaselineStale
		}
		baselines := transaction.Bucket(bucketBaselines)
		if baselines.Get(newID[:]) != nil {
			return ErrBaselineRollback
		}
		parent := baselines.Get(parentID[:])
		if parent == nil || sha256.Sum256(parent) != parentID {
			return ErrCorrupt
		}
		approvedAtUnixNS, err := approval.AuthorizeParentAt(append([]byte(nil), parent...), store.clock().UTC())
		if err != nil {
			return err
		}
		history := BaselineHistory{HostFingerprint: hostFingerprint, ParentBaselineID: parentID, NewBaselineID: newID,
			ProposalDigest: approval.ProposalDigest(), ApprovedAtUnixNS: approvedAtUnixNS}
		if !validBaselineHistory(history) {
			return ErrArgument
		}
		if err := baselines.Put(newID[:], owned); err != nil {
			return err
		}
		host.BaselineID = newID
		updatedHost, err := store.encode(host)
		if err != nil {
			return err
		}
		if err := hosts.Put(hostFingerprint[:], updatedHost); err != nil {
			return err
		}
		historyKey := make([]byte, 0, 64)
		historyKey = append(historyKey, hostFingerprint[:]...)
		historyKey = append(historyKey, newID[:]...)
		historyBucket := transaction.Bucket(bucketBaselineHistory)
		if historyBucket.Get(historyKey) != nil {
			return ErrBaselineRollback
		}
		encodedHistory, err := store.encode(history)
		if err != nil {
			return err
		}
		if err := historyBucket.Put(historyKey, encodedHistory); err != nil {
			return err
		}
		if store.baselineUpdateHook != nil {
			return store.baselineUpdateHook()
		}
		return nil
	})
}

func (store *Store) ListBaselineHistory(hostFingerprint [32]byte) ([]BaselineHistory, error) {
	if isZero32(hostFingerprint) {
		return nil, ErrArgument
	}
	result := make([]BaselineHistory, 0)
	err := store.view(func(transaction *bbolt.Tx) error {
		cursor := transaction.Bucket(bucketBaselineHistory).Cursor()
		for key, value := cursor.Seek(hostFingerprint[:]); key != nil && bytes.HasPrefix(key, hostFingerprint[:]); key, value = cursor.Next() {
			if len(key) != 64 {
				return ErrCorrupt
			}
			var history BaselineHistory
			if err := store.decodeCanonical(value, &history); err != nil || !validBaselineHistory(history) || history.HostFingerprint != hostFingerprint {
				return ErrCorrupt
			}
			result = append(result, history)
		}
		return nil
	})
	return result, err
}

func (store *Store) getEvidence(bucketName []byte, identifier [32]byte) ([]byte, error) {
	if isZero32(identifier) {
		return nil, ErrArgument
	}
	var result []byte
	err := store.view(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(bucketName).Get(identifier[:])
		if encoded == nil {
			return ErrNotFound
		}
		result = append([]byte(nil), encoded...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (store *Store) GetEnrollment(digest [32]byte) (Enrollment, error) {
	if isZero32(digest) {
		return Enrollment{}, ErrArgument
	}
	var enrollment Enrollment
	err := store.view(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(bucketTokens).Get(digest[:])
		if encoded == nil {
			return ErrNotFound
		}
		var record tokenRecord
		if err := store.decodeCanonical(encoded, &record); err != nil {
			return err
		}
		enrollment = Enrollment{
			Digest:            digest,
			ExpiresAtUnixNano: record.ExpiresAtUnixNano,
			State:             record.State,
			PendingID:         record.PendingID,
			MismatchAttempts:  record.MismatchAttempts,
		}
		return nil
	})
	return enrollment, err
}

func (store *Store) RevokeEnrollment(digest [32]byte) error {
	if isZero32(digest) {
		return ErrArgument
	}
	return store.update(func(transaction *bbolt.Tx) error {
		bucket := transaction.Bucket(bucketTokens)
		encoded := bucket.Get(digest[:])
		if encoded == nil {
			return ErrNotFound
		}
		var record tokenRecord
		if err := store.decodeCanonical(encoded, &record); err != nil {
			return err
		}
		if record.State == EnrollmentConsumed {
			return ErrTokenConsumed
		}
		if record.State == EnrollmentRevoked {
			return nil
		}
		record.State = EnrollmentRevoked
		updated, err := store.encode(record)
		if err != nil {
			return err
		}
		return bucket.Put(digest[:], updated)
	})
}

func (store *Store) ListHosts() ([]model.HostRecord, error) {
	hosts := make([]model.HostRecord, 0)
	err := store.view(func(transaction *bbolt.Tx) error {
		return transaction.Bucket(bucketHosts).ForEach(func(_, encoded []byte) error {
			var host model.HostRecord
			if err := store.decodeCanonical(encoded, &host); err != nil {
				return err
			}
			if err := host.Validate(); err != nil {
				return ErrCorrupt
			}
			hosts = append(hosts, host.Clone())
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return hosts, nil
}

func (store *Store) PutAntiRollbackPolicy(identifier [32]byte, policy []byte) error {
	if isZero32(identifier) || len(policy) == 0 || len(policy) > maxPolicyBytes {
		return ErrArgument
	}
	owned := append([]byte(nil), policy...)
	return store.update(func(transaction *bbolt.Tx) error {
		return transaction.Bucket(bucketAntiRollback).Put(identifier[:], owned)
	})
}

func isZero16(value [pendingIDBytes]byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}

func isZero32(value [32]byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}

// AttestationChallengeState is the durable one-use state of a verifier challenge.
type AttestationChallengeState string

const (
	AttestationChallengeIssued     AttestationChallengeState = "issued"
	AttestationChallengeProcessing AttestationChallengeState = "processing"
	AttestationChallengeConsumed   AttestationChallengeState = "consumed"
	AttestationChallengeExpired    AttestationChallengeState = "expired"
)

type AttestationFailureReason string

const (
	AttestationAccepted              AttestationFailureReason = "accepted"
	AttestationFailureHost           AttestationFailureReason = "host"
	AttestationFailureDecrypt        AttestationFailureReason = "decrypt"
	AttestationFailureAuthentication AttestationFailureReason = "authentication"
	AttestationFailureContext        AttestationFailureReason = "context"
	AttestationFailureInvalid        AttestationFailureReason = "invalid"
	AttestationFailureVerification   AttestationFailureReason = "verification"
	AttestationFailureCancelled      AttestationFailureReason = "cancelled"
	AttestationFailureIssue          AttestationFailureReason = "issue_failure"
)

func (reason AttestationFailureReason) valid() bool {
	switch reason {
	case AttestationAccepted, AttestationFailureHost, AttestationFailureDecrypt, AttestationFailureAuthentication, AttestationFailureContext, AttestationFailureInvalid, AttestationFailureVerification, AttestationFailureCancelled, AttestationFailureIssue:
		return true
	default:
		return false
	}
}

type AttestationChallenge struct {
	RequestID       [16]byte
	HostFingerprint [32]byte
	VerifierNonce   [32]byte
	Selection       model.PCRSelection
	RecipientKID    []byte
	IssuedAtUnixNS  int64
	ExpiresAtUnixNS int64
	State           AttestationChallengeState
	FailureReason   AttestationFailureReason
}

var (
	ErrChallengeExists   = errors.New("attestation challenge already exists")
	ErrChallengeConsumed = errors.New("attestation challenge unavailable")
	ErrChallengeExpired  = errors.New("attestation challenge expired")
)

var bucketAttestationChallenges = []byte("attestation_challenges")

type attestationChallengeRecord struct {
	HostFingerprint [32]byte                  `cbor:"1,keyasint"`
	VerifierNonce   [32]byte                  `cbor:"2,keyasint"`
	Selection       model.PCRSelection        `cbor:"3,keyasint"`
	RecipientKID    []byte                    `cbor:"4,keyasint"`
	IssuedAtUnixNS  int64                     `cbor:"5,keyasint"`
	ExpiresAtUnixNS int64                     `cbor:"6,keyasint"`
	State           AttestationChallengeState `cbor:"7,keyasint"`
	FailureReason   AttestationFailureReason  `cbor:"8,keyasint"`
}

func validAttestationChallenge(challenge AttestationChallenge) bool {
	return !isZero16(challenge.RequestID) && !isZero32(challenge.HostFingerprint) &&
		!isZero32(challenge.VerifierNonce) && challenge.Selection.Valid() &&
		len(challenge.RecipientKID) > 0 && len(challenge.RecipientKID) <= 64 &&
		challenge.IssuedAtUnixNS > 0 && challenge.ExpiresAtUnixNS > challenge.IssuedAtUnixNS &&
		(challenge.State == "" || challenge.State == AttestationChallengeIssued) && challenge.FailureReason == ""
}

func (store *Store) CreateAttestationChallenge(challenge AttestationChallenge) error {
	if !validAttestationChallenge(challenge) {
		return ErrArgument
	}
	record := attestationChallengeRecord{HostFingerprint: challenge.HostFingerprint, VerifierNonce: challenge.VerifierNonce,
		Selection: challenge.Selection.Clone(), RecipientKID: append([]byte(nil), challenge.RecipientKID...),
		IssuedAtUnixNS: challenge.IssuedAtUnixNS, ExpiresAtUnixNS: challenge.ExpiresAtUnixNS, State: AttestationChallengeIssued}
	encoded, err := store.encode(record)
	if err != nil {
		return err
	}
	return store.update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAttestationChallenges)
		if bucket.Get(challenge.RequestID[:]) != nil {
			return ErrChallengeExists
		}
		return bucket.Put(challenge.RequestID[:], encoded)
	})
}

func (store *Store) BeginAttestationChallenge(requestID [16]byte) (AttestationChallenge, error) {
	if isZero16(requestID) {
		return AttestationChallenge{}, ErrArgument
	}
	var result AttestationChallenge
	var logical error
	err := store.update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAttestationChallenges)
		encoded := bucket.Get(requestID[:])
		if encoded == nil {
			logical = ErrNotFound
			return nil
		}
		var record attestationChallengeRecord
		if store.decodeCanonical(encoded, &record) != nil || !record.Selection.Valid() || len(record.RecipientKID) == 0 || len(record.RecipientKID) > 64 || record.ExpiresAtUnixNS <= record.IssuedAtUnixNS || (record.State != AttestationChallengeIssued && record.State != AttestationChallengeProcessing && record.State != AttestationChallengeConsumed && record.State != AttestationChallengeExpired) {
			return ErrCorrupt
		}
		if store.clock().UTC().UnixNano() >= record.ExpiresAtUnixNS {
			if record.State == AttestationChallengeIssued {
				record.State = AttestationChallengeExpired
				updated, err := store.encode(record)
				if err != nil {
					return err
				}
				if err := bucket.Put(requestID[:], updated); err != nil {
					return err
				}
			}
			logical = ErrChallengeExpired
			return nil
		}
		if record.State != AttestationChallengeIssued {
			logical = ErrChallengeConsumed
			return nil
		}
		record.State = AttestationChallengeProcessing
		updated, err := store.encode(record)
		if err != nil {
			return err
		}
		if err := bucket.Put(requestID[:], updated); err != nil {
			return err
		}
		result = challengeFromRecord(requestID, record)
		return nil
	})
	if err != nil {
		return AttestationChallenge{}, err
	}
	if logical != nil {
		return AttestationChallenge{}, logical
	}
	return result, nil
}

// SetAttestationFinishHookForTest installs a failure seam used only to prove callers surface an unsuccessful consume write.
func (store *Store) SetAttestationFinishHookForTest(hook func() error) {
	store.attestationFinishHook = hook
}

func (store *Store) FinishAttestationChallenge(requestID [16]byte, reason AttestationFailureReason) error {
	if isZero16(requestID) || !reason.valid() {
		return ErrArgument
	}
	return store.update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketAttestationChallenges)
		encoded := bucket.Get(requestID[:])
		if encoded == nil {
			return ErrNotFound
		}
		var record attestationChallengeRecord
		if store.decodeCanonical(encoded, &record) != nil {
			return ErrCorrupt
		}
		if record.State != AttestationChallengeProcessing {
			return ErrChallengeConsumed
		}
		if store.attestationFinishHook != nil {
			if err := store.attestationFinishHook(); err != nil {
				return err
			}
		}
		record.State, record.FailureReason = AttestationChallengeConsumed, reason
		updated, err := store.encode(record)
		if err != nil {
			return err
		}
		return bucket.Put(requestID[:], updated)
	})
}

func (store *Store) GetAttestationChallenge(requestID [16]byte) (AttestationChallenge, error) {
	if isZero16(requestID) {
		return AttestationChallenge{}, ErrArgument
	}
	var result AttestationChallenge
	err := store.view(func(tx *bbolt.Tx) error {
		encoded := tx.Bucket(bucketAttestationChallenges).Get(requestID[:])
		if encoded == nil {
			return ErrNotFound
		}
		var record attestationChallengeRecord
		if store.decodeCanonical(encoded, &record) != nil {
			return ErrCorrupt
		}
		result = challengeFromRecord(requestID, record)
		return nil
	})
	return result, err
}

func challengeFromRecord(requestID [16]byte, record attestationChallengeRecord) AttestationChallenge {
	return AttestationChallenge{RequestID: requestID, HostFingerprint: record.HostFingerprint, VerifierNonce: record.VerifierNonce, Selection: record.Selection.Clone(), RecipientKID: append([]byte(nil), record.RecipientKID...), IssuedAtUnixNS: record.IssuedAtUnixNS, ExpiresAtUnixNS: record.ExpiresAtUnixNS, State: record.State, FailureReason: record.FailureReason}
}
