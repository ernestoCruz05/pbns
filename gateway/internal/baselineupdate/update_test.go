package baselineupdate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/veraison/go-cose"

	controlled "pbns.local/gateway/internal/baseline"
)

func testBaseline(t *testing.T, marker byte) []byte {
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
func testAdmin(t *testing.T) (*ecdsa.PrivateKey, [32]byte) {
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
func signApproval(t *testing.T, proposal []byte, key *ecdsa.PrivateKey, kid [32]byte) []byte {
	t.Helper()
	decoded, err := DecodeProposal(proposal)
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
	message.Payload = proposal
	if err := message.Sign(rand.Reader, ApprovalAAD(decoded), signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := message.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestVerifiedApprovalIsOpaqueAndAuthorizesItsExactParent(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	admin, kid := testAdmin(t)
	parent := testBaseline(t, 1)
	parentID := sha256.Sum256(parent)
	host := [32]byte{1}
	proposal, err := CreateProposal(host, parentID, parent, testBaseline(t, 9), ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := VerifyApproval(proposal, signApproval(t, proposal, admin, kid), &admin.PublicKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approval.AuthorizeParentAt(parent, now); err != nil {
		t.Fatal(err)
	}
	if _, err := approval.AuthorizeParentAt(testBaseline(t, 2), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong parent accepted: %v", err)
	}
	if _, err := approval.AuthorizeParentAt(parent, now.Add(time.Hour)); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("expiry boundary accepted: %v", err)
	}
	if (Approval{}).Valid() {
		t.Fatal("zero approval is valid")
	}
	if approval.HostFingerprint() != host || approval.ParentBaselineID() != parentID || bytes.Equal(approval.NewBaseline(), parent) {
		t.Fatal("approval accessors differ")
	}
	returned := approval.NewBaseline()
	returned[0] ^= 0xff
	if bytes.Equal(returned, approval.NewBaseline()) {
		t.Fatal("NewBaseline aliases approval")
	}
	if _, err := approval.AuthorizeParentAt(parent, now); err != nil {
		t.Fatalf("mutated accessor changed approval: %v", err)
	}
}

func TestCheckedUnixNanosecondsRejectsUnrepresentableTimes(t *testing.T) {
	for _, valid := range []time.Time{
		time.Unix(1_900_000_000, 123).UTC(),
		time.Unix(0, -1<<63).UTC(),
		time.Unix(0, 1<<63-1).UTC(),
	} {
		if got, err := checkedUnixNanoseconds(valid); err != nil || got != valid.UnixNano() {
			t.Fatalf("valid timestamp %s got=%d err=%v", valid, got, err)
		}
	}
	for _, at := range []time.Time{
		time.Time{},
		time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		if _, err := checkedUnixNanoseconds(at); !errors.Is(err, ErrAuthorization) {
			t.Fatalf("unrepresentable %s accepted: %v", at, err)
		}
	}
}

func TestApprovalRejectsUnsignedWrongAdminKidTimeAndTrailing(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	admin, kid := testAdmin(t)
	wrong, _ := testAdmin(t)
	parent := testBaseline(t, 1)
	proposal, err := CreateProposal([32]byte{1}, sha256.Sum256(parent), parent, testBaseline(t, 9), ChangeSecurity, now.Add(-time.Minute), now.Add(time.Hour), kid)
	if err != nil {
		t.Fatal(err)
	}
	signed := signApproval(t, proposal, admin, kid)
	wrongKid := kid
	wrongKid[0] ^= 0x80
	cases := []struct {
		name      string
		signature []byte
		public    *ecdsa.PublicKey
		at        time.Time
	}{
		{"unsigned", nil, &admin.PublicKey, now}, {"wrong-admin", signed, &wrong.PublicKey, now},
		{"wrong-kid", signApproval(t, proposal, admin, wrongKid), &admin.PublicKey, now},
		{"future", signed, &admin.PublicKey, now.Add(-time.Hour)}, {"expired", signed, &admin.PublicKey, now.Add(2 * time.Hour)},
		{"zero-clock", signed, &admin.PublicKey, time.Time{}},
		{"pre-range-clock", signed, &admin.PublicKey, time.Date(1600, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"post-range-clock", signed, &admin.PublicKey, time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC)},
		{"trailing", append(append([]byte(nil), signed...), 0), &admin.PublicKey, now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if approval, err := VerifyApproval(proposal, tc.signature, tc.public, tc.at); err == nil || approval.Valid() {
				t.Fatal("invalid approval accepted")
			}
		})
	}
}
