package model

import (
	"errors"
	"fmt"
)

const maxPublicFieldBytes = 65536

var ErrInvalid = errors.New("invalid enrollment model")

type Assurance string

const (
	AssuranceTPMVerified   Assurance = "tpm-verified"
	AssuranceTPMUnverified Assurance = "tpm-unverified-ek"
	AssuranceSoftware      Assurance = "software"
)

func (assurance Assurance) Valid() bool {
	switch assurance {
	case AssuranceTPMVerified, AssuranceTPMUnverified, AssuranceSoftware:
		return true
	default:
		return false
	}
}

type HostRecord struct {
	Fingerprint     [32]byte  `cbor:"1,keyasint"`
	IdentityCOSEKey []byte    `cbor:"2,keyasint"`
	AKPublic        []byte    `cbor:"3,keyasint"`
	AKName          []byte    `cbor:"4,keyasint"`
	EKPublic        []byte    `cbor:"5,keyasint"`
	EKChainDigest   [32]byte  `cbor:"6,keyasint"`
	Assurance       Assurance `cbor:"7,keyasint"`
	BaselineID      [32]byte  `cbor:"8,keyasint"`
	EnrolledAtUnix  int64     `cbor:"9,keyasint"`
}

func (record HostRecord) Validate() error {
	if isZero(record.Fingerprint) || len(record.IdentityCOSEKey) == 0 ||
		len(record.IdentityCOSEKey) > maxPublicFieldBytes || !record.Assurance.Valid() ||
		isZero(record.BaselineID) || record.EnrolledAtUnix <= 0 ||
		len(record.AKPublic) > maxPublicFieldBytes || len(record.AKName) > maxPublicFieldBytes ||
		len(record.EKPublic) > maxPublicFieldBytes {
		return ErrInvalid
	}
	switch record.Assurance {
	case AssuranceSoftware:
		if len(record.AKPublic) != 0 || len(record.AKName) != 0 || len(record.EKPublic) != 0 ||
			!isZero(record.EKChainDigest) {
			return ErrInvalid
		}
	case AssuranceTPMUnverified:
		if len(record.AKPublic) == 0 || len(record.AKName) == 0 || len(record.EKPublic) == 0 {
			return ErrInvalid
		}
	case AssuranceTPMVerified:
		if len(record.AKPublic) == 0 || len(record.AKName) == 0 || len(record.EKPublic) == 0 ||
			isZero(record.EKChainDigest) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func (record HostRecord) Clone() HostRecord {
	clone := record
	clone.IdentityCOSEKey = append([]byte(nil), record.IdentityCOSEKey...)
	clone.AKPublic = append([]byte(nil), record.AKPublic...)
	clone.AKName = append([]byte(nil), record.AKName...)
	clone.EKPublic = append([]byte(nil), record.EKPublic...)
	return clone
}

func (record HostRecord) String() string {
	return fmt.Sprintf("host fingerprint=%x assurance=%s", record.Fingerprint, record.Assurance)
}

func (record HostRecord) GoString() string {
	return record.String()
}

func isZero(value [32]byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}

// PCRBank is a canonical TPM PCR-bank selection used by attestation challenges.
type PCRBank struct {
	Algorithm uint64   `cbor:"1,keyasint"`
	Indices   []uint64 `cbor:"2,keyasint"`
}

// PCRSelection is an ordered, duplicate-free PCR selection.
type PCRSelection []PCRBank

func (selection PCRSelection) Valid() bool {
	if len(selection) == 0 || len(selection) > 8 {
		return false
	}
	var previousAlgorithm uint64
	for bankIndex, bank := range selection {
		if bank.Algorithm == 0 || len(bank.Indices) == 0 || len(bank.Indices) > 24 ||
			(bankIndex > 0 && bank.Algorithm <= previousAlgorithm) {
			return false
		}
		var previousIndex uint64
		for index, value := range bank.Indices {
			if value >= 24 || (index > 0 && value <= previousIndex) {
				return false
			}
			previousIndex = value
		}
		previousAlgorithm = bank.Algorithm
	}
	return true
}

func (selection PCRSelection) Clone() PCRSelection {
	clone := make(PCRSelection, len(selection))
	for index := range selection {
		clone[index].Algorithm = selection[index].Algorithm
		clone[index].Indices = append([]uint64(nil), selection[index].Indices...)
	}
	return clone
}
