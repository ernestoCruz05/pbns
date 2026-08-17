package recovery

import (
	"encoding/binary"
	"errors"

	"pbns.local/gateway/internal/wire"
)

const ACKWindow = uint32(8)

var (
	ErrStream          = errors.New("invalid recovery stream")
	ErrBackpressure    = errors.New("recovery stream awaits acknowledgement")
	ErrStreamIO        = errors.New("recovery stream artifact read failed")
	ErrAcknowledgement = errors.New("invalid recovery stream acknowledgement")
)

type ReaderAt interface {
	ReadAt(data []byte, offset int64) (int, error)
}

type StreamSender struct {
	reader       ReaderAt
	requestID    wire.RequestID
	size         uint64
	offset       uint64
	nextSequence uint32
	nextACK      uint32
	sinceACK     uint32
	buffer       [wire.DataPayloadMax]byte
	awaitingACK  bool
	complete     bool
	failed       bool
}

func NewStreamSender(reader ReaderAt, size uint64, requestID wire.RequestID) (*StreamSender, error) {
	if reader == nil || size == 0 || size > MaximumImageSize || allZero(requestID[:]) {
		return nil, ErrStream
	}
	return &StreamSender{reader: reader, requestID: requestID, size: size}, nil
}

// Next returns a DATA payload backed by the sender's fixed buffer; the caller
// must encode or write it before calling Next again.
func (sender *StreamSender) Next() (wire.Frame, error) {
	if sender == nil || sender.reader == nil || sender.failed || sender.complete {
		return wire.Frame{}, ErrStream
	}
	if sender.awaitingACK {
		return wire.Frame{}, ErrBackpressure
	}
	if sender.offset == sender.size {
		sender.complete = true
		return wire.Frame{
			Service: wire.ServiceRecoveryArtifact, Type: wire.MessageComplete,
			RequestID: sender.requestID, Sequence: sender.nextSequence,
		}, nil
	}
	remaining := sender.size - sender.offset
	length := uint64(len(sender.buffer))
	if remaining < length {
		length = remaining
	}
	chunk := sender.buffer[:int(length)]
	read, err := sender.reader.ReadAt(chunk, int64(sender.offset))
	if err != nil || read != len(chunk) {
		sender.failed = true
		clear(chunk)
		return wire.Frame{}, ErrStreamIO
	}
	frame := wire.Frame{
		Service: wire.ServiceRecoveryArtifact, Type: wire.MessageData,
		RequestID: sender.requestID, Sequence: sender.nextSequence, Payload: chunk,
	}
	sender.offset += length
	sender.nextSequence++
	sender.sinceACK++
	if sender.sinceACK == ACKWindow {
		sender.awaitingACK = true
	}
	return frame, nil
}

func (sender *StreamSender) AcceptACK(frame wire.Frame) error {
	if sender == nil || sender.failed || sender.complete || !sender.awaitingACK ||
		frame.Service != wire.ServiceRecoveryArtifact || frame.Type != wire.MessageACK ||
		frame.Flags != 0 || frame.RequestID != sender.requestID || frame.Sequence != sender.nextACK ||
		len(frame.Payload) != wire.ACKPayloadSize ||
		binary.BigEndian.Uint32(frame.Payload[:4]) != sender.nextSequence ||
		binary.BigEndian.Uint32(frame.Payload[4:]) != ACKWindow {
		if sender != nil {
			sender.failed = true
		}
		return ErrAcknowledgement
	}
	sender.nextACK++
	sender.sinceACK = 0
	sender.awaitingACK = false
	return nil
}

func (sender *StreamSender) Cancel() {
	if sender == nil {
		return
	}
	clear(sender.buffer[:])
	sender.failed = true
}

func (sender *StreamSender) Reset() error {
	if sender == nil || sender.reader == nil {
		return ErrStream
	}
	clear(sender.buffer[:])
	sender.offset = 0
	sender.nextSequence = 0
	sender.nextACK = 0
	sender.sinceACK = 0
	sender.awaitingACK = false
	sender.complete = false
	sender.failed = false
	return nil
}

func ACKFrame(requestID wire.RequestID, sequence, nextSequence uint32) wire.Frame {
	payload := make([]byte, wire.ACKPayloadSize)
	binary.BigEndian.PutUint32(payload[:4], nextSequence)
	binary.BigEndian.PutUint32(payload[4:], ACKWindow)
	return wire.Frame{
		Service: wire.ServiceRecoveryArtifact, Type: wire.MessageACK,
		RequestID: requestID, Sequence: sequence, Payload: payload,
	}
}
