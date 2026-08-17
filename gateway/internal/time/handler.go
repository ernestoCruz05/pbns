package time

import (
	"context"
	"errors"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

func (service *Service) HandleFrame(
	ctx context.Context,
	request wire.Frame,
	stream *server.Stream,
) error {
	if service == nil || ctx == nil || stream == nil ||
		request.Service != wire.ServiceTrustedTime || request.Type != wire.MessageRequest ||
		request.Sequence != 0 || len(request.Payload) == 0 {
		return &server.ProtocolError{Code: 3, Detail: "invalid trusted-time request"}
	}
	response, err := service.Handle(request.Payload)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidRequest):
			return &server.ProtocolError{Code: 3, Detail: "invalid trusted-time object"}
		case errors.Is(err, ErrHostAuthentication), errors.Is(err, ErrTimeAuthentication):
			return &server.ProtocolError{Code: 14, Detail: "trusted-time authentication failed"}
		case errors.Is(err, ErrExpiredRequest):
			return &server.ProtocolError{Code: 8, Detail: "trusted-time request expired"}
		default:
			return &server.ProtocolError{Code: 13, Detail: "trusted-time service failure"}
		}
	}
	return stream.Send(wire.Frame{
		Service: request.Service, Type: wire.MessageResponse,
		RequestID: request.RequestID, Sequence: request.Sequence, Payload: response,
	})
}

type ServerHandler struct {
	Service *Service
}

func (handler ServerHandler) Handle(
	ctx context.Context,
	request wire.Frame,
	stream *server.Stream,
) error {
	if handler.Service == nil {
		return &server.ProtocolError{Code: 13, Detail: "trusted-time service unavailable"}
	}
	return handler.Service.HandleFrame(ctx, request, stream)
}
