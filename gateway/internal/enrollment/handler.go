package enrollment

import (
	"context"
	"errors"
	"log/slog"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

const (
	OperationBegin    = uint64(1)
	OperationComplete = uint64(2)
)

type WireRequest struct {
	Operation uint64 `cbor:"1,keyasint"`
	Envelope  []byte `cbor:"2,keyasint"`
}

type WireResponse struct {
	Operation uint64 `cbor:"1,keyasint"`
	Object    []byte `cbor:"2,keyasint"`
}

func (service *Service) Handle(
	ctx context.Context,
	request wire.Frame,
	stream *server.Stream,
) error {
	if service == nil || ctx == nil || stream == nil ||
		request.Service != wire.ServiceEnrollment || request.Type != wire.MessageRequest ||
		request.Sequence != 0 || len(request.Payload) == 0 {
		return &server.ProtocolError{Code: 3, Detail: "invalid enrollment request"}
	}
	var wireRequest WireRequest
	if err := decodeCanonical(request.Payload, &wireRequest); err != nil ||
		len(wireRequest.Envelope) == 0 {
		return &server.ProtocolError{Code: 3, Detail: "invalid enrollment object"}
	}
	var object []byte
	var err error
	switch wireRequest.Operation {
	case OperationBegin:
		object, err = service.Begin(wireRequest.Envelope)
	case OperationComplete:
		object, err = service.Complete(wireRequest.Envelope)
	default:
		return &server.ProtocolError{Code: 3, Detail: "invalid enrollment operation"}
	}
	if err != nil {
		if errors.Is(err, ErrTPMEvidence) {
			slog.Warn("TPM enrollment evidence rejected", "reason", err)
		}
		return enrollmentProtocolError(err)
	}
	payload, err := encodeCanonical(WireResponse{
		Operation: wireRequest.Operation,
		Object:    object,
	})
	if err != nil {
		return &server.ProtocolError{Code: 13, Detail: "enrollment response failure"}
	}
	return stream.Send(wire.Frame{
		Service: request.Service, Type: wire.MessageResponse,
		RequestID: request.RequestID, Sequence: request.Sequence,
		Payload: payload,
	})
}

func enrollmentProtocolError(err error) error {
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrDecryption):
		return &server.ProtocolError{Code: 3, Detail: "invalid enrollment object"}
	case errors.Is(err, ErrAuthentication), errors.Is(err, ErrTranscript):
		return &server.ProtocolError{Code: 14, Detail: "enrollment authentication failed"}
	case errors.Is(err, ErrState):
		return &server.ProtocolError{Code: 9, Detail: "enrollment state unavailable"}
	default:
		return &server.ProtocolError{Code: 13, Detail: "enrollment service failure"}
	}
}
