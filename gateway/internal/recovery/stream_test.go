package recovery

import (
	"errors"
	"io"
	"testing"

	"pbns.local/gateway/internal/wire"
)

type patternReader struct {
	size      uint64
	maximum   int
	calls     int
	failCall  int
	shortCall int
}

func (reader *patternReader) ReadAt(data []byte, offset int64) (int, error) {
	reader.calls++
	if len(data) > reader.maximum {
		reader.maximum = len(data)
	}
	if reader.calls == reader.failCall {
		return 0, errors.New("injected read failure")
	}
	length := len(data)
	if reader.calls == reader.shortCall {
		length--
	}
	for index := 0; index < length; index++ {
		data[index] = byte((uint64(offset)+uint64(index))*37 + 11)
	}
	if length != len(data) {
		return length, io.EOF
	}
	return length, nil
}

func streamRequestID() wire.RequestID {
	var request wire.RequestID
	for index := range request {
		request[index] = byte(0x10 + index)
	}
	return request
}

func TestStreamSizesBackpressureAndComplete(t *testing.T) {
	sizes := []uint64{1, 16_383, 16_384, 16_385, 1024 * 1024, MaximumImageSize}
	for _, size := range sizes {
		t.Run(streamSizeName(size), func(t *testing.T) {
			reader := &patternReader{size: size}
			request := streamRequestID()
			sender, err := NewStreamSender(reader, size, request)
			if err != nil {
				t.Fatal(err)
			}
			var offset uint64
			var sequence uint32
			var ackSequence uint32
			for offset < size {
				frame, err := sender.Next()
				if err != nil {
					t.Fatal(err)
				}
				if frame.Type != wire.MessageData || frame.Sequence != sequence || frame.RequestID != request {
					t.Fatalf("wrong frame: %#v", frame)
				}
				remaining := size - offset
				expected := uint64(wire.DataPayloadMax)
				if remaining < expected {
					expected = remaining
				}
				if uint64(len(frame.Payload)) != expected {
					t.Fatalf("chunk %d, expected %d", len(frame.Payload), expected)
				}
				offset += expected
				sequence++
				if sequence%ACKWindow == 0 {
					if _, err := sender.Next(); !errors.Is(err, ErrBackpressure) {
						t.Fatalf("backpressure: %v", err)
					}
					if err := sender.AcceptACK(ACKFrame(request, ackSequence, sequence)); err != nil {
						t.Fatal(err)
					}
					ackSequence++
				}
			}
			complete, err := sender.Next()
			if err != nil {
				t.Fatal(err)
			}
			if complete.Type != wire.MessageComplete || complete.Sequence != sequence || len(complete.Payload) != 0 {
				t.Fatalf("wrong complete frame: %#v", complete)
			}
			if reader.maximum > wire.DataPayloadMax || reader.calls != int(sequence) {
				t.Fatalf("read bound: max=%d calls=%d sequence=%d", reader.maximum, reader.calls, sequence)
			}
		})
	}
}

func TestStreamRejectsIOAndAcknowledgementSubstitution(t *testing.T) {
	request := streamRequestID()
	for _, reader := range []*patternReader{
		{size: 16_385, failCall: 1},
		{size: 16_385, shortCall: 1},
	} {
		sender, err := NewStreamSender(reader, reader.size, request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sender.Next(); !errors.Is(err, ErrStreamIO) {
			t.Fatalf("I/O failure: %v", err)
		}
		if _, err := sender.Next(); !errors.Is(err, ErrStream) {
			t.Fatalf("failed sender reused: %v", err)
		}
	}

	reader := &patternReader{size: uint64(wire.DataPayloadMax) * uint64(ACKWindow)}
	sender, err := NewStreamSender(reader, reader.size, request)
	if err != nil {
		t.Fatal(err)
	}
	for index := uint32(0); index < ACKWindow; index++ {
		if _, err := sender.Next(); err != nil {
			t.Fatal(err)
		}
	}
	wrong := ACKFrame(request, 0, ACKWindow)
	wrong.Payload[7] = 7
	if err := sender.AcceptACK(wrong); !errors.Is(err, ErrAcknowledgement) {
		t.Fatalf("changed ACK accepted: %v", err)
	}
}

func TestStreamCancelResetAndArguments(t *testing.T) {
	request := streamRequestID()
	reader := &patternReader{size: 1}
	sender, err := NewStreamSender(reader, 1, request)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := sender.Next()
	if err != nil || len(frame.Payload) != 1 {
		t.Fatalf("first frame: %#v %v", frame, err)
	}
	sender.Cancel()
	if _, err := sender.Next(); !errors.Is(err, ErrStream) {
		t.Fatalf("cancelled sender reused: %v", err)
	}
	if err := sender.Reset(); err != nil {
		t.Fatal(err)
	}
	frame, err = sender.Next()
	if err != nil || frame.Sequence != 0 || len(frame.Payload) != 1 {
		t.Fatalf("reset frame: %#v %v", frame, err)
	}
	if _, err := NewStreamSender(nil, 1, request); !errors.Is(err, ErrStream) {
		t.Fatalf("nil reader: %v", err)
	}
	if _, err := NewStreamSender(reader, 0, request); !errors.Is(err, ErrStream) {
		t.Fatalf("zero size: %v", err)
	}
	if _, err := NewStreamSender(reader, MaximumImageSize+1, request); !errors.Is(err, ErrStream) {
		t.Fatalf("oversize: %v", err)
	}
}

func streamSizeName(size uint64) string {
	const digits = "0123456789"
	if size == 0 {
		return "0"
	}
	var reversed [20]byte
	position := len(reversed)
	for size > 0 {
		position--
		reversed[position] = digits[size%10]
		size /= 10
	}
	return string(reversed[position:])
}
