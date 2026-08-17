package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
)

const maximum = 4_268_800

func main() {
	path := flag.String("file", "", "COSE_Encrypt file")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		die(errors.New("-file is required"))
	}
	encoded, err := os.ReadFile(*path)
	if err != nil || len(encoded) == 0 || len(encoded) > maximum {
		die(errors.New("invalid COSE input"))
	}
	if err := inspect(encoded); err != nil {
		die(err)
	}
	fmt.Println("COSE -29/A128GCM PASS")
}

func die(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "cose inspect:", err)
	os.Exit(1)
}

func inspect(encoded []byte) error {
	dec, err := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, MaxNestedLevels: 8, MaxArrayElements: 16, MaxMapPairs: 16}).DecMode()
	if err != nil {
		return err
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return err
	}
	var tag cbor.RawTag
	if err := dec.Unmarshal(encoded, &tag); err != nil || tag.Number != 96 {
		return errors.New("not tagged COSE_Encrypt")
	}
	var outer []cbor.RawMessage
	if dec.Unmarshal(tag.Content, &outer) != nil || len(outer) != 4 {
		return errors.New("invalid COSE_Encrypt array")
	}
	if err := protectedAlgorithm(dec, outer[0], 1); err != nil {
		return err
	}
	var bodyUnprotected map[int64]cbor.RawMessage
	if dec.Unmarshal(outer[1], &bodyUnprotected) != nil || len(bodyUnprotected) != 1 {
		return errors.New("invalid body unprotected headers")
	}
	var iv []byte
	if dec.Unmarshal(bodyUnprotected[5], &iv) != nil || len(iv) != 12 {
		return errors.New("invalid A128GCM IV")
	}
	var ciphertext []byte
	if dec.Unmarshal(outer[2], &ciphertext) != nil || len(ciphertext) < 16 {
		return errors.New("missing authenticated ciphertext")
	}
	var recipients []cbor.RawMessage
	if dec.Unmarshal(outer[3], &recipients) != nil || len(recipients) != 1 {
		return errors.New("invalid recipient count")
	}
	var recipient []cbor.RawMessage
	if dec.Unmarshal(recipients[0], &recipient) != nil || len(recipient) != 3 {
		return errors.New("invalid recipient")
	}
	if err := protectedAlgorithm(dec, recipient[0], -29); err != nil {
		return err
	}
	var headers map[int64]cbor.RawMessage
	if dec.Unmarshal(recipient[1], &headers) != nil || len(headers) != 2 {
		return errors.New("invalid recipient headers")
	}
	var kid []byte
	if dec.Unmarshal(headers[4], &kid) != nil || len(kid) == 0 || len(kid) > 64 {
		return errors.New("invalid recipient KID")
	}
	if err := ephemeralKey(dec, headers[-1]); err != nil {
		return err
	}
	var wrappedKey []byte
	if dec.Unmarshal(recipient[2], &wrappedKey) != nil || len(wrappedKey) != 24 {
		return errors.New("invalid A128KW recipient ciphertext")
	}
	canonical, err := enc.Marshal(tag)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return errors.New("noncanonical COSE_Encrypt")
	}
	return nil
}

func protectedAlgorithm(dec cbor.DecMode, raw cbor.RawMessage, expected int64) error {
	var encoded []byte
	if dec.Unmarshal(raw, &encoded) != nil || len(encoded) == 0 {
		return errors.New("missing protected headers")
	}
	var headers map[int64]cbor.RawMessage
	if dec.Unmarshal(encoded, &headers) != nil || len(headers) != 1 {
		return errors.New("invalid protected headers")
	}
	var algorithm int64
	if dec.Unmarshal(headers[1], &algorithm) != nil || algorithm != expected {
		return errors.New("unexpected COSE algorithm")
	}
	return nil
}

func ephemeralKey(dec cbor.DecMode, raw cbor.RawMessage) error {
	var key map[int64]cbor.RawMessage
	if dec.Unmarshal(raw, &key) != nil || len(key) != 4 {
		return errors.New("invalid ephemeral key")
	}
	var keyType, curve int64
	var x, y []byte
	if dec.Unmarshal(key[1], &keyType) != nil || keyType != 2 || dec.Unmarshal(key[-1], &curve) != nil || curve != 1 || dec.Unmarshal(key[-2], &x) != nil || len(x) != 32 || dec.Unmarshal(key[-3], &y) != nil || len(y) != 32 {
		return errors.New("invalid P-256 ephemeral key")
	}
	return nil
}
