package attestation

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"pbns.local/gateway/internal/model"
)

func TestSelectionDigestMatchesCanonicalTupleVector(t *testing.T) {
	selection := model.PCRSelection{{Algorithm: 0x000b, Indices: []uint64{0, 2, 4, 7}}}
	got, ok := canonicalSelectionDigest(selection)
	want := sha256.Sum256([]byte{0x00, 0x0b, 0x00, 0x00, 0x0b, 0x02, 0x00, 0x0b, 0x04, 0x00, 0x0b, 0x07})
	if !ok || got != want {
		t.Fatalf("selection digest=%x valid=%v, want %x", got, ok, want)
	}
}

func TestDecodeCanonicalRejectsNonCanonicalEvidence(t *testing.T) {
	var destination map[uint64]any
	// Map key 1 encoded with an unnecessarily wide uint representation.
	if err := decodeCanonical([]byte{0xa1, 0x18, 0x01, 0x01}, &destination); err == nil {
		t.Fatal("accepted non-canonical CBOR")
	}
}

func TestExactAADsAreCanonicalAndContextBound(t *testing.T) {
	challenge := Challenge{Context: Context{RequestID: [16]byte{1}, HostFingerprint: [32]byte{2}}, VerifierNonce: [32]byte{3}, RecipientKID: []byte("recipient")}
	first := encryptAAD(challenge)
	challenge.RecipientKID = []byte("other")
	if bytes.Equal(first, encryptAAD(challenge)) {
		t.Fatal("recipient not bound")
	}
}

func TestInventoryBoundaryRejectsArbitraryAndExtraFields(t *testing.T) {
	// Neither arbitrary canonical maps nor an otherwise valid report with an extra raw-identifier field can decode into the authoritative schema.
	var inventory InventoryReport
	if err := decodeCanonical([]byte{0xa1, 0x01, 0x68, 's', 'e', 'n', 't', 'i', 'n', 'e', 'l'}, &inventory); err == nil {
		t.Fatal("accepted arbitrary inventory map")
	}
	valid := validTestInventory([32]byte{1})
	encoded, err := canonicalMode.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	// Add map key 18 (a hypothetical detached identifier) while retaining canonical ordering.
	if encoded[0] != 0xb1 {
		t.Fatalf("inventory map header %x", encoded[0])
	}
	extra := append([]byte{0xb2}, encoded[1:]...)
	extra = append(extra, 0x12, 0x68, 's', 'e', 'n', 't', 'i', 'n', 'e', 'l')
	if err := decodeCanonical(extra, &inventory); err == nil {
		t.Fatal("accepted extra inventory field")
	}
}

func TestInventoryHandoffIsDefensivelyCopied(t *testing.T) {
	value := InventoryReport{Outcomes: map[uint64]uint64{1: 0, 2: 0, 3: 0, 4: 0, 5: 0}, Timings: map[uint64]uint64{1: 2}, TPM: TPMInventory{ActiveBanks: []uint64{11}}}
	clone := cloneInventory(value)
	value.Outcomes[1] = 5
	value.Timings[1] = 9
	value.TPM.ActiveBanks[0] = 12
	if clone.Outcomes[1] != 0 || clone.Timings[1] != 2 || clone.TPM.ActiveBanks[0] != 11 {
		t.Fatal("mutable inventory crossed handoff")
	}
}

func TestInventoryTask1TextAndBlockDeviceBounds(t *testing.T) {
	host := [32]byte{1}
	base := func() InventoryReport {
		return InventoryReport{HostFingerprint: host, FirmwareVendor: "Vendor 1", FirmwareVersion: "Version 2", CPUClass: "x86_64", Outcomes: map[uint64]uint64{1: 0, 2: 0, 3: 0, 4: 0, 5: 0}, Timings: map[uint64]uint64{}}
	}
	for _, test := range []struct {
		name   string
		mutate func(*InventoryReport)
		want   bool
	}{
		{"count-64", func(v *InventoryReport) { v.Storage.BlockDeviceCount = 64 }, true},
		{"count-65", func(v *InventoryReport) { v.Storage.BlockDeviceCount = 65 }, false},
		{"non-ascii-utf8", func(v *InventoryReport) { v.FirmwareVendor = "Vend\u00f8r" }, false},
		{"control", func(v *InventoryReport) { v.FirmwareVersion = "version\n2" }, false},
		{"leading-space", func(v *InventoryReport) { v.CPUClass = " x86" }, false},
		{"trailing-space", func(v *InventoryReport) { v.CPUClass = "x86 " }, false},
		{"double-space", func(v *InventoryReport) { v.FirmwareVendor = "Vendor  1" }, false},
		{"normalized-printable-ascii", func(v *InventoryReport) {
			v.FirmwareVendor = "Vendor-1.0"
			v.FirmwareVersion = "Build 42"
			v.CPUClass = "x86_64-v3"
		}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventory := base()
			test.mutate(&inventory)
			if got := validInventory(inventory, host); got != test.want {
				t.Fatalf("validInventory=%v, want %v", got, test.want)
			}
		})
	}
}
