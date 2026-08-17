package baseline

import (
	"crypto/sha256"
	"testing"
)

func controlledFixture() Controlled {
	measurement := sha256.Sum256([]byte("measured"))
	return Controlled{Record: Record{Version: 1, MeasurementDigest: measurement, SecureBoot: true, SetupMode: false, DBDigest: sha256.Sum256([]byte("db")), DBXDigest: sha256.Sum256([]byte("dbx")), FirmwareDigest: FirmwareIdentity("vendor", "1"), Inventory: InventoryRule{MemoryMiBDelta: 128, StorageGiBDelta: 4, BlockDeviceDelta: 1}}, MemoryMiB: 4096, StorageGiB: 64, BlockDevices: 1}
}
func observed(c Controlled) Observed {
	return Observed{MeasurementDigest: c.Record.MeasurementDigest, SecureBoot: c.Record.SecureBoot, SetupMode: c.Record.SetupMode, DBDigest: c.Record.DBDigest, DBXDigest: c.Record.DBXDigest, FirmwareDigest: c.Record.FirmwareDigest, MemoryMiB: c.MemoryMiB, StorageGiB: c.StorageGiB, BlockDevices: c.BlockDevices}
}
func TestDecodeRejectsEmptyControlledBaseline(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Fatal("Decode accepted empty baseline")
	}
}
func TestControlledBaselineCanonicalAndSecurityState(t *testing.T) {
	controlled := controlledFixture()
	encoded, err := Encode(controlled)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := Verify(decoded, observed(decoded)); !got.MeasurementMatch || !got.InventoryMatch {
		t.Fatalf("exact baseline=%#v", got)
	}
	cases := []func(*Observed){func(v *Observed) { v.MeasurementDigest[0] ^= 1 }, func(v *Observed) { v.SecureBoot = false }, func(v *Observed) { v.DBDigest[0] ^= 1 }, func(v *Observed) { v.DBXDigest[0] ^= 1 }, func(v *Observed) { v.FirmwareDigest[0] ^= 1 }}
	for _, mutate := range cases {
		value := observed(decoded)
		mutate(&value)
		if Verify(decoded, value).MeasurementMatch {
			t.Fatal("security state unexpectedly matched")
		}
	}
}
func TestPermittedInventoryDriftIsSeparate(t *testing.T) {
	c := controlledFixture()
	v := observed(c)
	v.MemoryMiB += 128
	v.StorageGiB -= 4
	v.BlockDevices += 1
	got := Verify(c, v)
	if !got.MeasurementMatch || !got.InventoryMatch {
		t.Fatalf("permitted drift=%#v", got)
	}
	v.MemoryMiB++
	if Verify(c, v).InventoryMatch {
		t.Fatal("excess memory drift accepted")
	}
}

func TestInsecureBaselineOrObservationNeverMatches(t *testing.T) {
	for _, mutate := range []func(*Controlled){
		func(c *Controlled) { c.Record.SecureBoot = false },
		func(c *Controlled) { c.Record.SetupMode = true },
		func(c *Controlled) { c.Record.DBDigest = [32]byte{} },
		func(c *Controlled) { c.Record.DBXDigest = [32]byte{} },
	} {
		c := controlledFixture()
		mutate(&c)
		if _, err := Encode(c); err == nil {
			t.Fatal("Encode accepted insecure controlled baseline")
		}
		v := observed(c)
		if got := Verify(c, v); got.MeasurementMatch || got.InventoryMatch {
			t.Fatalf("insecure matching values trusted: %#v", got)
		}
	}
	for _, mutate := range []func(*Observed){
		func(v *Observed) { v.SecureBoot = false },
		func(v *Observed) { v.SetupMode = true },
		func(v *Observed) { v.DBDigest = [32]byte{} },
		func(v *Observed) { v.DBXDigest = [32]byte{} },
	} {
		c := controlledFixture()
		v := observed(c)
		mutate(&v)
		if got := Verify(c, v); got.MeasurementMatch || got.InventoryMatch {
			t.Fatalf("insecure observation trusted: %#v", got)
		}
	}
}
