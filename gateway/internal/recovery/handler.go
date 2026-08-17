package recovery

import (
	"context"
	"encoding/binary"
	"errors"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

type recoverySender interface {
	Next() (wire.Frame, error)
	AcceptACK(wire.Frame) error
	Cancel()
}

type recoverySenderFactory func(ReaderAt, uint64, wire.RequestID) (recoverySender, error)

func newRecoverySender(plan *evaluationPlan, reader ReaderAt, size uint64,
	requestID wire.RequestID) (recoverySender, error) {
	if plan != nil && plan.newStreamSender != nil {
		return plan.newStreamSender(reader, size, requestID)
	}
	return NewStreamSender(reader, size, requestID)
}

const (
	statusFormat         = uint64(3)
	statusTransport      = uint64(12)
	statusCrypto         = uint64(13)
	statusAuthentication = uint64(14)
	statusReplay         = uint64(15)
	statusIO             = uint64(21)
)

func (service *Service) Handle(ctx context.Context, frame wire.Frame,
	stream *server.Stream) error {
	return service.handle(ctx, frame, stream, nil)
}

func (service *Service) handle(ctx context.Context, frame wire.Frame,
	stream *server.Stream, plan *evaluationPlan) error {
	if service == nil || ctx == nil || stream == nil ||
		frame.Service != wire.ServiceRecoveryArtifact ||
		frame.Type != wire.MessageRequest || frame.Flags != 0 ||
		frame.Sequence != 0 || len(frame.Payload) == 0 {
		return recoveryProtocolError(statusFormat, "invalid recovery request")
	}
	request, err := VerifyRequest(frame.Payload, service.hosts)
	if err != nil {
		if errors.Is(err, ErrRequest) {
			return recoveryProtocolError(statusFormat, "invalid recovery request")
		}
		return recoveryProtocolError(statusAuthentication, "recovery request authentication failed")
	}
	if wire.RequestID(request.RequestID) != frame.RequestID {
		return recoveryProtocolError(statusAuthentication, "recovery request correlation failed")
	}
	switch request.Operation {
	case OperationManifest:
		return service.handleManifest(ctx, frame, request, stream, plan)
	case OperationArtifact:
		return service.handleArtifact(ctx, frame, request, stream, plan)
	default:
		return recoveryProtocolError(statusFormat, "invalid recovery operation")
	}
}

func (service *Service) handleManifest(ctx context.Context, frame wire.Frame,
	request Request, stream *server.Stream, plan *evaluationPlan) error {
	signed, err := service.Manifest(ctx, request)
	if err != nil {
		return mapRecoveryServiceError(err)
	}
	outgoing := wire.Frame{
		Service: frame.Service, Type: wire.MessageResponse,
		RequestID: frame.RequestID, Sequence: 0, Payload: signed,
	}
	if err := stream.Send(outgoing); err != nil {
		return err
	}
	if err := plan.record(stream, "manifest", outgoing, "sent", 0, 0); err != nil {
		return recoveryProtocolError(statusIO, "recovery evaluation observation failed")
	}
	return nil
}

func (service *Service) handleArtifact(ctx context.Context, frame wire.Frame,
	request Request, stream *server.Stream, plan *evaluationPlan) error {
	if request.ArtifactDigest != service.artifact.Digest {
		return recoveryProtocolError(statusReplay, "recovery artifact is not active")
	}
	transferContext, cancel := context.WithTimeout(ctx, service.transferTimeout)
	defer cancel()
	file, artifact, err := service.repository.OpenArtifact(service.artifact.Digest)
	if err != nil {
		return recoveryProtocolError(statusIO, "recovery artifact unavailable")
	}
	closed := false
	closeFile := func() error {
		if closed {
			return nil
		}
		closed = true
		return file.Close()
	}
	defer func() {
		_ = closeFile()
	}()
	if artifact != service.artifact {
		return recoveryProtocolError(statusIO, "recovery artifact changed")
	}
	sender, err := newRecoverySender(plan, file, artifact.Size, frame.RequestID)
	if err != nil {
		return recoveryProtocolError(statusIO, "recovery stream unavailable")
	}
	for {
		if err := transferContext.Err(); err != nil {
			sender.Cancel()
			return recoveryProtocolError(statusTransport, "recovery transfer expired")
		}
		outgoing, err := sender.Next()
		if errors.Is(err, ErrBackpressure) {
			ack, receiveErr := stream.Receive(transferContext)
			if receiveErr != nil {
				sender.Cancel()
				if errors.Is(receiveErr, server.ErrStreamCorrelation) {
					return recoveryProtocolError(statusFormat, "invalid recovery acknowledgement")
				}
				return recoveryProtocolError(statusTransport, "recovery acknowledgement unavailable")
			}
			if ack.Type == wire.MessageCancel {
				sender.Cancel()
				return recoveryProtocolError(statusTransport, "recovery transfer cancelled")
			}
			if err := sender.AcceptACK(ack); err != nil {
				return recoveryProtocolError(statusFormat, "invalid recovery acknowledgement")
			}
			if err := plan.record(stream, "artifact", ack, "accepted",
				binary.BigEndian.Uint32(ack.Payload[:4]), binary.BigEndian.Uint32(ack.Payload[4:])); err != nil {
				sender.Cancel()
				return recoveryProtocolError(statusIO, "recovery evaluation observation failed")
			}
			continue
		}
		if err != nil {
			sender.Cancel()
			return recoveryProtocolError(statusIO, "recovery artifact read failed")
		}
		if outgoing.Type == wire.MessageComplete {
			if err := closeFile(); err != nil {
				return recoveryProtocolError(statusIO, "recovery artifact close failed")
			}
		}

		injected := false
		if plan != nil && plan.fault == EvaluationFaultArtifactDigestMismatch &&
			outgoing.Type == wire.MessageData && outgoing.Sequence == 0 {
			outgoing.Payload = append([]byte(nil), outgoing.Payload...)
			outgoing.Payload[0] ^= 1
			injected = true
		}
		if plan != nil && plan.fault == EvaluationFaultChunkSequence &&
			outgoing.Type == wire.MessageData && outgoing.Sequence == 1 {
			outgoing.Sequence = 2
			injected = true
		}
		if err := stream.Send(outgoing); err != nil {
			sender.Cancel()
			return err
		}
		outcome := "sent"
		if injected {
			outcome = "injected"
		}
		interrupt := plan != nil && plan.fault == EvaluationFaultInterruptAfterData7 &&
			outgoing.Type == wire.MessageData && outgoing.Sequence == 7
		if interrupt {
			outcome = "interrupt-ready"
		}
		if err := plan.record(stream, "artifact", outgoing, outcome, 0, 0); err != nil {
			sender.Cancel()
			return recoveryProtocolError(statusIO, "recovery evaluation observation failed")
		}
		if interrupt {
			<-ctx.Done()
			sender.Cancel()
			return ctx.Err()
		}
		if outgoing.Type == wire.MessageComplete {
			return nil
		}
	}
}

func (plan *evaluationPlan) record(stream *server.Stream, operation string,
	frame wire.Frame, outcome string, next, window uint32) error {
	if plan == nil {
		return nil
	}
	return plan.observer.Record(EvaluationEvent{
		Connection: stream.ConnectionOrdinal(), Operation: operation,
		Frame: evaluationFrameName(frame.Type), Sequence: frame.Sequence,
		Next: next, Window: window, Fault: plan.fault, Outcome: outcome,
	})
}

func evaluationFrameName(messageType wire.MessageType) string {
	switch messageType {
	case wire.MessageResponse:
		return "RESPONSE"
	case wire.MessageData:
		return "DATA"
	case wire.MessageACK:
		return "ACK"
	case wire.MessageComplete:
		return "COMPLETE"
	default:
		return ""
	}
}

func mapRecoveryServiceError(err error) error {
	switch {
	case errors.Is(err, ErrRequest):
		return recoveryProtocolError(statusFormat, "invalid recovery request")
	case errors.Is(err, ErrRequestAuthentication):
		return recoveryProtocolError(statusAuthentication, "recovery authentication failed")
	case errors.Is(err, ErrManifestPolicy), errors.Is(err, ErrPolicyVersion):
		return recoveryProtocolError(statusReplay, "recovery policy rejected")
	case errors.Is(err, ErrArtifactChanged), errors.Is(err, ErrUnregistered),
		errors.Is(err, ErrRepository), errors.Is(err, ErrStreamIO):
		return recoveryProtocolError(statusIO, "recovery artifact unavailable")
	default:
		return recoveryProtocolError(statusCrypto, "recovery service failure")
	}
}

func recoveryProtocolError(code uint64, detail string) error {
	return &server.ProtocolError{Code: code, Detail: detail}
}
