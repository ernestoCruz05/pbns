package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
)

type vectorFile struct {
	Cases []vectorCase `json:"cases"`
}

type vectorCase struct {
	Name         string `json:"name"`
	Service      uint8  `json:"service"`
	MessageType  uint8  `json:"message_type"`
	Flags        uint8  `json:"flags"`
	RequestIDHex string `json:"request_id_hex"`
	Sequence     uint32 `json:"sequence"`
	PayloadHex   string `json:"payload_hex"`
	RawHex       string `json:"raw_hex"`
	COBSHex      string `json:"cobs_hex"`
	WireHex      string `json:"wire_hex"`
}

func mustHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func loadVectors(t *testing.T) []vectorCase {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "vectors", "frame-v1.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("frame vector file is empty")
	}
	return vectors.Cases
}

func frameFromVector(t *testing.T, vector vectorCase) Frame {
	t.Helper()
	var requestID RequestID
	requestBytes := mustHex(t, vector.RequestIDHex)
	if len(requestBytes) != len(requestID) {
		t.Fatalf("request ID length %d", len(requestBytes))
	}
	copy(requestID[:], requestBytes)
	return Frame{
		Service:   ServiceID(vector.Service),
		Type:      MessageType(vector.MessageType),
		Flags:     vector.Flags,
		RequestID: requestID,
		Sequence:  vector.Sequence,
		Payload:   mustHex(t, vector.PayloadHex),
	}
}

func TestFrameVectorsMatchExactlyInBothDirections(t *testing.T) {
	decoder, err := NewDecoder(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range loadVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			expectedFrame := frameFromVector(t, vector)
			expectedWire := mustHex(t, vector.WireHex)
			encoded, err := Encode(expectedFrame)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expectedWire, encoded) {
				t.Fatalf("wire mismatch\n got: %x\nwant: %x", encoded, expectedWire)
			}

			input := bytes.Clone(expectedWire)
			decoded, err := decoder.Decode(input)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Service != expectedFrame.Service || decoded.Type != expectedFrame.Type ||
				decoded.Flags != expectedFrame.Flags || decoded.RequestID != expectedFrame.RequestID ||
				decoded.Sequence != expectedFrame.Sequence ||
				!bytes.Equal(decoded.Payload, expectedFrame.Payload) {
				t.Fatalf("decoded frame mismatch: %#v", decoded)
			}
			if len(decoded.Payload) > 0 {
				input[len(input)/2] ^= 0xff
				if !bytes.Equal(decoded.Payload, expectedFrame.Payload) {
					t.Fatal("decoded payload aliases input storage")
				}
			}
		})
	}
}

func testCOBSEncode(input []byte) []byte {
	output := make([]byte, 1, len(input)+len(input)/254+2)
	codeIndex := 0
	code := byte(1)
	for _, value := range input {
		if value == 0 {
			output[codeIndex] = code
			codeIndex = len(output)
			output = append(output, 0)
			code = 1
			continue
		}
		output = append(output, value)
		code++
		if code == 0xff {
			output[codeIndex] = code
			codeIndex = len(output)
			output = append(output, 0)
			code = 1
		}
	}
	output[codeIndex] = code
	return append(output, 0)
}

func refreshCRCs(raw []byte) {
	table := crc32.MakeTable(crc32.Castagnoli)
	binary.BigEndian.PutUint32(raw[32:36], crc32.Checksum(raw[:32], table))
	binary.BigEndian.PutUint32(raw[len(raw)-4:], crc32.Checksum(raw[:len(raw)-4], table))
}

func TestDecoderRejectsMalformedFramesWithTypedErrors(t *testing.T) {
	vector := loadVectors(t)[0]
	baseRaw := mustHex(t, vector.RawHex)
	decoder, err := NewDecoder(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(change func([]byte), refresh bool) []byte {
		raw := bytes.Clone(baseRaw)
		change(raw)
		if refresh {
			refreshCRCs(raw)
		}
		return testCOBSEncode(raw)
	}

	invalidTerminalPayload := func(messageType MessageType) []byte {
		raw := make([]byte, len(baseRaw)+1)
		copy(raw[:HeaderSize], baseRaw[:HeaderSize])
		raw[6] = byte(messageType)
		binary.BigEndian.PutUint32(raw[28:32], 1)
		raw[HeaderSize] = 0x42
		binary.BigEndian.PutUint32(raw[32:36], crc32.Checksum(raw[:32], crc32.MakeTable(crc32.Castagnoli)))
		return testCOBSEncode(raw)
	}

	tests := map[string]struct {
		wire []byte
		want error
	}{
		"magic": {
			wire: mutate(func(raw []byte) { raw[0] = 'X' }, true),
			want: ErrFormat,
		},
		"version": {
			wire: mutate(func(raw []byte) { raw[4] = 2 }, true),
			want: ErrVersion,
		},
		"service": {
			wire: mutate(func(raw []byte) { raw[5] = 99 }, true),
			want: ErrService,
		},
		"message-type": {
			wire: mutate(func(raw []byte) { raw[6] = 99 }, true),
			want: ErrMessageType,
		},
		"flags": {
			wire: mutate(func(raw []byte) { raw[7] = 1 }, true),
			want: ErrFormat,
		},
		"header-crc": {
			wire: mutate(func(raw []byte) { raw[32] ^= 1 }, false),
			want: ErrCRC,
		},
		"payload-limit": {
			wire: mutate(func(raw []byte) { binary.BigEndian.PutUint32(raw[28:32], ControlPayloadMax+1) }, true),
			want: ErrLimit,
		},
		"payload-size": {
			wire: mutate(func(raw []byte) { binary.BigEndian.PutUint32(raw[28:32], 1) }, true),
			want: ErrFormat,
		},
		"record-crc": {
			wire: mutate(func(raw []byte) { raw[len(raw)-1] ^= 1 }, false),
			want: ErrCRC,
		},
		"short-record": {
			wire: testCOBSEncode(baseRaw[:HeaderSize+TrailerSize-1]),
			want: ErrFormat,
		},
		"missing-delimiter": {
			wire: mustHex(t, vector.COBSHex),
			want: ErrFormat,
		},
		"extra-delimiter": {
			wire: append(bytes.Clone(mustHex(t, vector.WireHex)), 0),
			want: ErrFormat,
		},
		"invalid-cobs-zero": {
			wire: []byte{1, 0, 1, 0},
			want: ErrFormat,
		},
		"invalid-cobs-run": {
			wire: []byte{5, 1, 0},
			want: ErrFormat,
		},
		"ack-length-precedes-record-crc": {
			wire: invalidTerminalPayload(MessageACK),
			want: ErrFormat,
		},
		"cancel-length-precedes-record-crc": {
			wire: invalidTerminalPayload(MessageCancel),
			want: ErrFormat,
		},
		"complete-length-precedes-record-crc": {
			wire: invalidTerminalPayload(MessageComplete),
			want: ErrFormat,
		},
	}

	extraRaw := append(bytes.Clone(baseRaw), 0xaa)
	tests["extra-raw-byte"] = struct {
		wire []byte
		want error
	}{wire: testCOBSEncode(extraRaw), want: ErrFormat}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decoder.Decode(test.wire); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestHeaderCRCPrecedesPayloadLengthUse(t *testing.T) {
	vector := loadVectors(t)[0]
	raw := mustHex(t, vector.RawHex)
	binary.BigEndian.PutUint32(raw[28:32], ControlPayloadMax+1)
	decoder, err := NewDecoder(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(testCOBSEncode(raw)); !errors.Is(err, ErrCRC) {
		t.Fatalf("got %v, want ErrCRC", err)
	}
}

func TestEncoderRejectsInvalidSemantics(t *testing.T) {
	valid := frameFromVector(t, loadVectors(t)[0])
	validACK := make([]byte, ACKPayloadSize)
	binary.BigEndian.PutUint32(validACK[:4], 1)
	binary.BigEndian.PutUint32(validACK[4:], 1)

	tests := map[string]struct {
		frame Frame
		want  error
	}{
		"service":      {frame: func() Frame { f := valid; f.Service = 0; return f }(), want: ErrService},
		"message-type": {frame: func() Frame { f := valid; f.Type = 0; return f }(), want: ErrMessageType},
		"flags":        {frame: func() Frame { f := valid; f.Flags = 1; return f }(), want: ErrFormat},
		"data-limit":   {frame: func() Frame { f := valid; f.Type = MessageData; f.Payload = make([]byte, DataPayloadMax+1); return f }(), want: ErrLimit},
		"ack-size":     {frame: func() Frame { f := valid; f.Type = MessageACK; f.Payload = []byte{1}; return f }(), want: ErrFormat},
		"ack-next-zero": {frame: func() Frame {
			f := valid
			f.Type = MessageACK
			f.Payload = bytes.Clone(validACK)
			binary.BigEndian.PutUint32(f.Payload[:4], 0)
			return f
		}(), want: ErrFormat},
		"ack-window-zero": {frame: func() Frame {
			f := valid
			f.Type = MessageACK
			f.Payload = bytes.Clone(validACK)
			binary.BigEndian.PutUint32(f.Payload[4:], 0)
			return f
		}(), want: ErrFormat},
		"cancel-payload":   {frame: func() Frame { f := valid; f.Type = MessageCancel; f.Payload = []byte{1}; return f }(), want: ErrFormat},
		"complete-payload": {frame: func() Frame { f := valid; f.Type = MessageComplete; f.Payload = []byte{1}; return f }(), want: ErrFormat},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Encode(test.frame); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestDecoderEnforcesConfiguredLimitsBeforeDecoding(t *testing.T) {
	wire := mustHex(t, loadVectors(t)[0].WireHex)
	limits := DefaultLimits()
	limits.EncodedRecordMax = len(wire) - 1
	decoder, err := NewDecoder(limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decoder.Decode(wire); !errors.Is(err, ErrLimit) {
		t.Fatalf("got %v, want ErrLimit", err)
	}

	limits = DefaultLimits()
	limits.EncodedRecordMax = WireMax + 1
	if _, err := NewDecoder(limits); !errors.Is(err, ErrArgument) {
		t.Fatalf("got %v, want ErrArgument", err)
	}
}
