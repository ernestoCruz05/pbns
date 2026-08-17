package service

import (
	"context"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

const statusUnimplemented = 17

func UnimplementedHandler() server.Handler {
	return server.HandlerFunc(func(context.Context, wire.Frame, *server.Stream) error {
		return &server.ProtocolError{
			Code:   statusUnimplemented,
			Detail: "service not implemented",
		}
	})
}
