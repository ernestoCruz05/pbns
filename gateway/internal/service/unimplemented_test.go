package service

import (
	"context"
	"errors"
	"testing"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

func TestUnimplementedHandlerReturnsTypedBoundedError(t *testing.T) {
	handler := UnimplementedHandler()
	if handler == nil {
		t.Fatal("handler is nil")
	}
	for _, service := range []wire.ServiceID{
		wire.ServiceTrustedTime,
		wire.ServiceRecoveryArtifact,
		wire.ServicePlatformAttestation,
		wire.ServiceEnrollment,
	} {
		err := handler.Handle(context.Background(), wire.Frame{Service: service}, nil)
		var protocolError *server.ProtocolError
		if !errors.As(err, &protocolError) {
			t.Fatalf("service %d returned %v", service, err)
		}
		if protocolError.Code != 17 || protocolError.Detail != "service not implemented" {
			t.Fatalf("service %d returned %#v", service, protocolError)
		}
	}
}
