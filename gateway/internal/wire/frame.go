package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	ProtocolVersion   = 1
	HeaderSize        = 36
	TrailerSize       = 4
	ControlPayloadMax = 65536
	DataPayloadMax    = 16384
	RawMax            = 65576
	COBSMax           = 65835
	WireMax           = 65836
	RequestIDSize     = 16
	ACKPayloadSize    = 8
)

var (
	ErrArgument    = errors.New("invalid frame argument")
	ErrLimit       = errors.New("frame limit exceeded")
	ErrFormat      = errors.New("invalid frame format")
	ErrCRC         = errors.New("frame CRC mismatch")
	ErrVersion     = errors.New("unsupported frame version")
	ErrService     = errors.New("invalid service identifier")
	ErrMessageType = errors.New("invalid message type")
)

type ServiceID uint8

const (
	ServiceTrustedTime         ServiceID = 1
	ServiceRecoveryArtifact    ServiceID = 2
	ServicePlatformAttestation ServiceID = 3
	ServiceEnrollment          ServiceID = 4
)

func (service ServiceID) Valid() bool {
	return service >= ServiceTrustedTime && service <= ServiceEnrollment
}

type MessageType uint8

const (
	MessageRequest  MessageType = 1
	MessageResponse MessageType = 2
	MessageData     MessageType = 3
	MessageACK      MessageType = 4
	MessageError    MessageType = 5
	MessageCancel   MessageType = 6
	MessageComplete MessageType = 7
)

func (messageType MessageType) Valid() bool {
	return messageType >= MessageRequest && messageType <= MessageComplete
}

type RequestID [RequestIDSize]byte

type Frame struct {
	Service   ServiceID
	Type      MessageType
	Flags     uint8
	RequestID RequestID
	Sequence  uint32
	Payload   []byte
}

type Limits struct {
	ControlPayloadMax int
	DataPayloadMax    int
	EncodedRecordMax  int
}

func DefaultLimits() Limits {
	return Limits{
		ControlPayloadMax: ControlPayloadMax,
		DataPayloadMax:    DataPayloadMax,
		EncodedRecordMax:  WireMax,
	}
}

type Decoder struct {
	limits Limits
}

func NewDecoder(limits Limits) (*Decoder, error) {
	if limits.ControlPayloadMax < 0 || limits.ControlPayloadMax > ControlPayloadMax ||
		limits.DataPayloadMax < 0 || limits.DataPayloadMax > DataPayloadMax ||
		limits.EncodedRecordMax < 0 || limits.EncodedRecordMax > WireMax {
		return nil, ErrArgument
	}
	return &Decoder{limits: limits}, nil
}

func payloadLengthError(messageType MessageType, payloadLength, controlLimit, dataLimit uint64) error {
	switch messageType {
	case MessageData:
		if payloadLength > dataLimit {
			return ErrLimit
		}
	case MessageACK:
		if payloadLength != ACKPayloadSize {
			return ErrFormat
		}
	case MessageCancel, MessageComplete:
		if payloadLength != 0 {
			return ErrFormat
		}
	case MessageRequest, MessageResponse, MessageError:
		if payloadLength > controlLimit {
			return ErrLimit
		}
	default:
		return ErrMessageType
	}
	return nil
}

func payloadError(messageType MessageType, payload []byte, controlLimit, dataLimit int) error {
	if err := payloadLengthError(
		messageType,
		uint64(len(payload)),
		uint64(controlLimit),
		uint64(dataLimit),
	); err != nil {
		return err
	}
	if messageType == MessageACK &&
		(binary.BigEndian.Uint32(payload[:4]) == 0 || binary.BigEndian.Uint32(payload[4:]) == 0) {
		return ErrFormat
	}
	return nil
}

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)
var frameMagic = []byte{'P', 'B', 'N', 'S'}

func Encode(frame Frame) ([]byte, error) {
	if !frame.Service.Valid() {
		return nil, ErrService
	}
	if !frame.Type.Valid() {
		return nil, ErrMessageType
	}
	if frame.Flags != 0 {
		return nil, ErrFormat
	}
	if err := payloadError(frame.Type, frame.Payload, ControlPayloadMax, DataPayloadMax); err != nil {
		return nil, err
	}

	rawSize := HeaderSize + len(frame.Payload) + TrailerSize
	if rawSize > RawMax {
		return nil, ErrLimit
	}
	raw := make([]byte, rawSize)
	copy(raw[:4], frameMagic)
	raw[4] = ProtocolVersion
	raw[5] = byte(frame.Service)
	raw[6] = byte(frame.Type)
	raw[7] = frame.Flags
	copy(raw[8:24], frame.RequestID[:])
	binary.BigEndian.PutUint32(raw[24:28], frame.Sequence)
	binary.BigEndian.PutUint32(raw[28:32], uint32(len(frame.Payload)))
	binary.BigEndian.PutUint32(raw[32:36], crc32.Checksum(raw[:32], castagnoliTable))
	copy(raw[HeaderSize:rawSize-TrailerSize], frame.Payload)
	binary.BigEndian.PutUint32(
		raw[rawSize-TrailerSize:],
		crc32.Checksum(raw[:rawSize-TrailerSize], castagnoliTable),
	)

	encoded := cobsEncode(raw)
	if len(encoded)+1 > WireMax {
		return nil, ErrLimit
	}
	return append(encoded, 0), nil
}

func (decoder *Decoder) Decode(wireRecord []byte) (Frame, error) {
	if decoder == nil {
		return Frame{}, ErrArgument
	}
	if len(wireRecord) > decoder.limits.EncodedRecordMax {
		return Frame{}, ErrLimit
	}
	if len(wireRecord) < 2 || wireRecord[len(wireRecord)-1] != 0 ||
		bytes.IndexByte(wireRecord[:len(wireRecord)-1], 0) >= 0 {
		return Frame{}, ErrFormat
	}

	raw, err := cobsDecode(wireRecord[:len(wireRecord)-1])
	if err != nil {
		return Frame{}, err
	}
	if len(raw) < HeaderSize+TrailerSize {
		return Frame{}, ErrFormat
	}
	if len(raw) > RawMax {
		return Frame{}, ErrLimit
	}
	if !bytes.Equal(raw[:4], frameMagic) {
		return Frame{}, ErrFormat
	}
	if raw[4] != ProtocolVersion {
		return Frame{}, ErrVersion
	}
	if binary.BigEndian.Uint32(raw[32:36]) != crc32.Checksum(raw[:32], castagnoliTable) {
		return Frame{}, ErrCRC
	}

	service := ServiceID(raw[5])
	if !service.Valid() {
		return Frame{}, ErrService
	}
	messageType := MessageType(raw[6])
	if !messageType.Valid() {
		return Frame{}, ErrMessageType
	}
	if raw[7] != 0 {
		return Frame{}, ErrFormat
	}

	payloadLength := uint64(binary.BigEndian.Uint32(raw[28:32]))
	if err := payloadLengthError(
		messageType,
		payloadLength,
		uint64(decoder.limits.ControlPayloadMax),
		uint64(decoder.limits.DataPayloadMax),
	); err != nil {
		return Frame{}, err
	}
	expectedRawLength := uint64(HeaderSize+TrailerSize) + payloadLength
	if uint64(len(raw)) != expectedRawLength {
		return Frame{}, ErrFormat
	}
	if binary.BigEndian.Uint32(raw[len(raw)-TrailerSize:]) !=
		crc32.Checksum(raw[:len(raw)-TrailerSize], castagnoliTable) {
		return Frame{}, ErrCRC
	}

	payload := append([]byte(nil), raw[HeaderSize:len(raw)-TrailerSize]...)
	if err := payloadError(messageType, payload, decoder.limits.ControlPayloadMax, decoder.limits.DataPayloadMax); err != nil {
		return Frame{}, err
	}
	var requestID RequestID
	copy(requestID[:], raw[8:24])
	return Frame{
		Service:   service,
		Type:      messageType,
		Flags:     raw[7],
		RequestID: requestID,
		Sequence:  binary.BigEndian.Uint32(raw[24:28]),
		Payload:   payload,
	}, nil
}

func cobsEncode(input []byte) []byte {
	output := make([]byte, 1, len(input)+len(input)/254+1)
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
	return output
}

func cobsDecode(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, ErrFormat
	}
	output := make([]byte, 0, len(input))
	for readIndex := 0; readIndex < len(input); {
		code := int(input[readIndex])
		readIndex++
		if code == 0 {
			return nil, ErrFormat
		}
		runLength := code - 1
		if runLength > len(input)-readIndex {
			return nil, fmt.Errorf("%w: COBS run exceeds record", ErrFormat)
		}
		for _, value := range input[readIndex : readIndex+runLength] {
			if value == 0 {
				return nil, ErrFormat
			}
			output = append(output, value)
		}
		readIndex += runLength
		if code != 0xff && readIndex < len(input) {
			output = append(output, 0)
		}
	}
	return output, nil
}
