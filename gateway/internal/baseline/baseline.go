// Package baseline validates the controlled, encrypted enrollment baseline.
package baseline

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var ErrInvalid = errors.New("invalid controlled baseline")

type InventoryRule struct {
	MemoryMiBDelta   uint64 `cbor:"1,keyasint"`
	StorageGiBDelta  uint64 `cbor:"2,keyasint"`
	BlockDeviceDelta uint64 `cbor:"3,keyasint"`
}

// Record is persisted only as enrollment BaselineEvidence. It contains no raw host identifiers.
type Record struct {
	Version           uint64        `cbor:"1,keyasint"`
	MeasurementDigest [32]byte      `cbor:"2,keyasint"`
	SecureBoot        bool          `cbor:"3,keyasint"`
	SetupMode         bool          `cbor:"4,keyasint"`
	DBDigest          [32]byte      `cbor:"5,keyasint"`
	DBXDigest         [32]byte      `cbor:"6,keyasint"`
	FirmwareDigest    [32]byte      `cbor:"7,keyasint"`
	Inventory         InventoryRule `cbor:"8,keyasint"`
}

type Observed struct {
	MeasurementDigest [32]byte
	SecureBoot        bool
	SetupMode         bool
	DBDigest          [32]byte
	DBXDigest         [32]byte
	FirmwareDigest    [32]byte
	MemoryMiB         uint64
	StorageGiB        uint64
	BlockDevices      uint64
}

type Controlled struct {
	Record       Record `cbor:"1,keyasint"`
	MemoryMiB    uint64 `cbor:"2,keyasint"`
	StorageGiB   uint64 `cbor:"3,keyasint"`
	BlockDevices uint64 `cbor:"4,keyasint"`
}

type Result struct {
	MeasurementMatch bool
	InventoryMatch   bool
}

var canonical cbor.EncMode
var strict cbor.DecMode

func init() {
	var err error
	canonical, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	strict, err = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, MaxNestedLevels: 4, MaxMapPairs: 16, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}).DecMode()
	if err != nil {
		panic(err)
	}
}

// Decode accepts only a canonical controlled enrollment record; verification never writes it.
func Decode(encoded []byte) (Controlled, error) {
	var controlled Controlled
	if len(encoded) == 0 || strict.Unmarshal(encoded, &controlled) != nil || !valid(controlled) {
		return Controlled{}, ErrInvalid
	}
	canonicalized, err := canonical.Marshal(controlled)
	if err != nil || !bytes.Equal(canonicalized, encoded) {
		return Controlled{}, ErrInvalid
	}
	return controlled, nil
}

func Encode(controlled Controlled) ([]byte, error) {
	if !valid(controlled) {
		return nil, ErrInvalid
	}
	return canonical.Marshal(controlled)
}

func Verify(controlled Controlled, observed Observed) Result {
	if !valid(controlled) || !secureObserved(observed) {
		return Result{}
	}
	measurement := controlled.Record.MeasurementDigest == observed.MeasurementDigest &&
		controlled.Record.SecureBoot == observed.SecureBoot && controlled.Record.SetupMode == observed.SetupMode &&
		controlled.Record.DBDigest == observed.DBDigest && controlled.Record.DBXDigest == observed.DBXDigest &&
		controlled.Record.FirmwareDigest == observed.FirmwareDigest
	rules := controlled.Record.Inventory
	inventory := within(controlled.MemoryMiB, observed.MemoryMiB, rules.MemoryMiBDelta) &&
		within(controlled.StorageGiB, observed.StorageGiB, rules.StorageGiBDelta) &&
		within(controlled.BlockDevices, observed.BlockDevices, rules.BlockDeviceDelta)
	return Result{MeasurementMatch: measurement, InventoryMatch: inventory}
}

func FirmwareIdentity(vendor, version string) [32]byte {
	h := sha256.New()
	h.Write([]byte("PBNS-FIRMWARE-IDENTITY-v1"))
	h.Write([]byte(vendor))
	h.Write([]byte{0})
	h.Write([]byte(version))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func valid(controlled Controlled) bool {
	return controlled.Record.Version == 1 && !zero(controlled.Record.MeasurementDigest) && !zero(controlled.Record.FirmwareDigest) &&
		controlled.Record.SecureBoot && !controlled.Record.SetupMode && !zero(controlled.Record.DBDigest) && !zero(controlled.Record.DBXDigest)
}
func secureObserved(observed Observed) bool {
	return observed.SecureBoot && !observed.SetupMode && !zero(observed.DBDigest) && !zero(observed.DBXDigest)
}
func zero(value [32]byte) bool {
	var v byte
	for _, b := range value {
		v |= b
	}
	return v == 0
}
func within(expected, actual, delta uint64) bool {
	if actual >= expected {
		return actual-expected <= delta
	}
	return expected-actual <= delta
}
