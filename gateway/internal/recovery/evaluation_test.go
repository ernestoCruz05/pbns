package recovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

type evaluationMemoryObserver struct {
	mutex  sync.Mutex
	events []EvaluationEvent
	err    error
}

func (observer *evaluationMemoryObserver) Record(event EvaluationEvent) error {
	observer.mutex.Lock()
	defer observer.mutex.Unlock()
	if observer.err != nil {
		return observer.err
	}
	observer.events = append(observer.events, event)
	return nil
}

func (observer *evaluationMemoryObserver) snapshot() []EvaluationEvent {
	observer.mutex.Lock()
	defer observer.mutex.Unlock()
	return append([]EvaluationEvent(nil), observer.events...)
}

type instrumentedEvaluationSender struct {
	sender      *StreamSender
	nextCalls   atomic.Uint32
	cancelCalls atomic.Uint32
}

func (sender *instrumentedEvaluationSender) Next() (wire.Frame, error) {
	sender.nextCalls.Add(1)
	return sender.sender.Next()
}

func (sender *instrumentedEvaluationSender) AcceptACK(frame wire.Frame) error {
	return sender.sender.AcceptACK(frame)
}

func (sender *instrumentedEvaluationSender) Cancel() {
	sender.cancelCalls.Add(1)
	sender.sender.Cancel()
}

func installEvaluationSenderInstrumentation(t *testing.T, handler server.Handler) *instrumentedEvaluationSender {
	t.Helper()
	evaluation, ok := handler.(*evaluationHandler)
	if !ok {
		t.Fatalf("evaluation handler type = %T", handler)
	}
	instrumented := &instrumentedEvaluationSender{}
	evaluation.plan.newStreamSender = func(reader ReaderAt, size uint64, requestID wire.RequestID) (recoverySender, error) {
		streamSender, err := NewStreamSender(reader, size, requestID)
		if err != nil {
			return nil, err
		}
		instrumented.sender = streamSender
		return instrumented, nil
	}
	return instrumented
}

func waitForEvaluationCounter(t *testing.T, counter *atomic.Uint32, want uint32) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if counter.Load() == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("counter = %d, want %d", counter.Load(), want)
}

func startEvaluationHandlerServer(t *testing.T, handler server.Handler) (string, *tls.Config, context.CancelFunc) {
	t.Helper()
	serverTLS, clientTLS := recoveryTLSConfig(t)
	instance, err := server.New(server.Config{
		TLS: serverTLS,
		Handlers: map[wire.ServiceID]server.Handler{
			wire.ServiceRecoveryArtifact: handler,
		},
		Limits: wire.DefaultLimits(), HandshakeTimeout: time.Second,
		ReadTimeout: time.Second, WriteTimeout: time.Second, MaxConnections: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("evaluation server did not stop")
		}
	})
	return listener.Addr().String(), clientTLS, cancel
}

func TestEvaluationHandlerRejectsInvalidConfiguration(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	var typedNil *evaluationMemoryObserver
	for name, testCase := range map[string]struct {
		service  *Service
		fault    EvaluationFault
		observer EvaluationObserver
	}{
		"nil-service":        {nil, EvaluationFaultChunkSequence, observer},
		"nil-observer":       {service, EvaluationFaultChunkSequence, nil},
		"typed-nil-observer": {service, EvaluationFaultChunkSequence, typedNil},
		"empty-fault":        {service, "", observer},
		"unknown-fault":      {service, EvaluationFault("unknown"), observer},
		"combined-fault":     {service, EvaluationFaultChunkSequence + "," + EvaluationFaultArtifactDigestMismatch, observer},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := NewEvaluationHandler(testCase.service, testCase.fault, testCase.observer)
			if handler != nil || !errors.Is(err, ErrEvaluationConfig) {
				t.Fatalf("NewEvaluationHandler() = %v, %v; want nil, ErrEvaluationConfig", handler, err)
			}
		})
	}
	for _, fault := range []EvaluationFault{
		EvaluationFaultInterruptAfterData7,
		EvaluationFaultArtifactDigestMismatch,
		EvaluationFaultChunkSequence,
	} {
		t.Run(string(fault), func(t *testing.T) {
			handler, err := NewEvaluationHandler(service, fault, observer)
			if err != nil || handler == nil {
				t.Fatalf("NewEvaluationHandler() = %v, %v", handler, err)
			}
		})
	}
}

func evaluationArtifactFrames(t *testing.T, address string, config *tls.Config,
	fixture recoveryServiceFixture, request Request) []wire.Frame {
	t.Helper()
	connection, reader := dialRecoveryHandler(t, address, config)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
	frames := make([]wire.Frame, 0)
	var data uint32
	var acknowledgements uint32
	for {
		frame := reader.next(t, connection)
		frame.Payload = append([]byte(nil), frame.Payload...)
		frames = append(frames, frame)
		if frame.Type == wire.MessageComplete || frame.Type == wire.MessageError {
			return frames
		}
		if frame.Type != wire.MessageData {
			t.Fatalf("unexpected frame: %#v", frame)
		}
		data++
		if data%ACKWindow == 0 {
			writeRecoveryFrame(t, connection, ACKFrame(wire.RequestID(request.RequestID), acknowledgements, data))
			acknowledgements++
		}
	}
}

func TestEvaluationArtifactDigestMismatchInjectsCopiedFirstChunk(t *testing.T) {
	content := bytes.Repeat([]byte{0x3c}, 2*wire.DataPayloadMax)
	fixture := newRecoveryServiceFixtureWithContent(t, content)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	handler, err := NewEvaluationHandler(service, EvaluationFaultArtifactDigestMismatch, observer)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS, _ := startEvaluationHandlerServer(t, handler)
	request := artifactRequest(fixture, 1)
	frames := evaluationArtifactFrames(t, address, clientTLS, fixture, request)
	if len(frames) != 3 || frames[0].Type != wire.MessageData || frames[0].Sequence != 0 ||
		frames[0].Payload[0] != content[0]^1 || !bytes.Equal(frames[0].Payload[1:], content[1:wire.DataPayloadMax]) {
		t.Fatalf("first frame was not the required injected copy: %#v", frames[0])
	}
	if fixture.artifact.Digest != service.artifact.Digest {
		t.Fatal("evaluation fault changed active manifest artifact digest")
	}
	events := observer.snapshot()
	if len(events) == 0 || events[0].Outcome != "injected" || events[0].Frame != "DATA" || events[0].Sequence != 0 {
		t.Fatalf("missing injected event: %#v", events)
	}
}

func TestEvaluationManifestEmitsUnchangedSignedArtifactDigest(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	handler, err := NewEvaluationHandler(service, EvaluationFaultArtifactDigestMismatch, observer)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS, _ := startEvaluationHandlerServer(t, handler)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, fixture.request))
	response := reader.next(t, connection)
	expectation := Expectation{
		RequestID: fixture.request.RequestID, HostBinding: fixture.request.HostFingerprint,
		Nonce: fixture.request.Nonce, RecoverySigningKeyID: fixture.manifestKeyID,
		ExpectedPolicyKeyID: fixture.policyKeyID,
		TrustedEarliestNS:   90_000_000_500, TrustedLatestNS: 120_000_000_500,
	}
	manifest, err := VerifyManifest(response.Payload, fixture.manifestVerifier, expectation)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ArtifactDigest != fixture.artifact.Digest {
		t.Fatalf("emitted manifest digest = %x, want %x", manifest.ArtifactDigest, fixture.artifact.Digest)
	}
	if events := observer.snapshot(); len(events) != 1 || events[0].Operation != "manifest" ||
		events[0].Frame != "RESPONSE" || events[0].Outcome != "sent" {
		t.Fatalf("manifest event = %#v", events)
	}
}

func TestEvaluationChunkSequenceInjectsOnlyDataOne(t *testing.T) {
	fixture := newRecoveryServiceFixtureWithContent(t, bytes.Repeat([]byte{0x61}, 3*wire.DataPayloadMax))
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	handler, err := NewEvaluationHandler(service, EvaluationFaultChunkSequence, observer)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS, _ := startEvaluationHandlerServer(t, handler)
	frames := evaluationArtifactFrames(t, address, clientTLS, fixture, artifactRequest(fixture, 2))
	if len(frames) != 4 || frames[0].Sequence != 0 || frames[1].Sequence != 2 || frames[2].Sequence != 2 || frames[3].Sequence != 3 {
		t.Fatalf("unexpected sequence injection: %#v", frames)
	}
	events := observer.snapshot()
	if len(events) < 2 || events[1].Outcome != "injected" || events[1].Sequence != 2 {
		t.Fatalf("missing chunk injection event: %#v", events)
	}
}

func TestEvaluationRecordsAcceptedACKOnlyAfterValidation(t *testing.T) {
	fixture := newRecoveryServiceFixtureWithContent(t, bytes.Repeat([]byte{0x39}, 9*wire.DataPayloadMax))
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	handler, err := NewEvaluationHandler(service, EvaluationFaultArtifactDigestMismatch, observer)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS, _ := startEvaluationHandlerServer(t, handler)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	request := artifactRequest(fixture, 6)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
	for sequence := uint32(0); sequence < ACKWindow; sequence++ {
		if frame := reader.next(t, connection); frame.Type != wire.MessageData || frame.Sequence != sequence {
			t.Fatalf("DATA %d = %#v", sequence, frame)
		}
	}
	if events := observer.snapshot(); len(events) != int(ACKWindow) {
		t.Fatalf("events before valid ACK = %#v", events)
	}
	writeRecoveryFrame(t, connection, ACKFrame(wire.RequestID(request.RequestID), 0, ACKWindow))
	if frame := reader.next(t, connection); frame.Type != wire.MessageData || frame.Sequence != ACKWindow {
		t.Fatalf("frame after valid ACK = %#v", frame)
	}
	events := observer.snapshot()
	if len(events) < int(ACKWindow)+2 {
		t.Fatalf("events after valid ACK = %#v", events)
	}
	ack := events[ACKWindow]
	if ack.Connection == 0 || ack.Operation != "artifact" || ack.Frame != "ACK" ||
		ack.Sequence != 0 || ack.Next != ACKWindow || ack.Window != ACKWindow ||
		ack.Fault != EvaluationFaultArtifactDigestMismatch || ack.Outcome != "accepted" {
		t.Fatalf("accepted ACK event = %#v", ack)
	}
	if events[ACKWindow+1].Frame != "DATA" || events[ACKWindow+1].Sequence != ACKWindow {
		t.Fatalf("ACK was not recorded before next DATA: %#v", events)
	}
}

func TestEvaluationRejectedACKRecordsNoEvent(t *testing.T) {
	fixture := newRecoveryServiceFixtureWithContent(t, bytes.Repeat([]byte{0x2a}, 9*wire.DataPayloadMax))
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	handler, err := NewEvaluationHandler(service, EvaluationFaultArtifactDigestMismatch, observer)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS, _ := startEvaluationHandlerServer(t, handler)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	request := artifactRequest(fixture, 7)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
	for sequence := uint32(0); sequence < ACKWindow; sequence++ {
		_ = reader.next(t, connection)
	}
	ack := ACKFrame(wire.RequestID(request.RequestID), 0, ACKWindow)
	ack.Payload[3] ^= 1
	writeRecoveryFrame(t, connection, ack)
	if response := reader.next(t, connection); response.Type != wire.MessageError {
		t.Fatalf("invalid ACK response = %#v", response)
	}
	if events := observer.snapshot(); len(events) != int(ACKWindow) {
		t.Fatalf("rejected ACK was observed: %#v", events)
	} else {
		for _, event := range events {
			if event.Frame == "ACK" {
				t.Fatalf("rejected ACK event = %#v", event)
			}
		}
	}
}

func TestEvaluationInterruptionWaitsForCancellationAfterDataSeven(t *testing.T) {
	fixture := newRecoveryServiceFixtureWithContent(t, bytes.Repeat([]byte{0x51}, 9*wire.DataPayloadMax))
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{}
	handler, err := NewEvaluationHandler(service, EvaluationFaultInterruptAfterData7, observer)
	if err != nil {
		t.Fatal(err)
	}
	instrumented := installEvaluationSenderInstrumentation(t, handler)
	address, clientTLS, cancel := startEvaluationHandlerServer(t, handler)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	request := artifactRequest(fixture, 3)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
	for sequence := uint32(0); sequence <= 7; sequence++ {
		frame := reader.next(t, connection)
		if frame.Type != wire.MessageData || frame.Sequence != sequence {
			t.Fatalf("data %d: %#v", sequence, frame)
		}
	}
	if events := observer.snapshot(); len(events) != 8 || events[7].Outcome != "interrupt-ready" || events[7].Sequence != 7 {
		t.Fatalf("interruption event = %#v", events)
	}
	if calls := instrumented.nextCalls.Load(); calls != 8 {
		t.Fatalf("sender.Next calls after DATA 7 = %d, want 8", calls)
	}
	if err := connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.reader.ReadBytes(0); err == nil {
		t.Fatal("handler sent a frame after interruption boundary")
	} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("read after interruption = %v, want timeout", err)
	}
	cancel()
	waitForEvaluationCounter(t, &instrumented.cancelCalls, 1)
	if calls := instrumented.nextCalls.Load(); calls != 8 {
		t.Fatalf("sender.Next calls after cancellation = %d, want 8", calls)
	}
}

func goldenProductionArtifactFrames(content []byte, requestID wire.RequestID) []wire.Frame {
	frames := make([]wire.Frame, 0, len(content)/wire.DataPayloadMax+2)
	var sequence uint32
	for len(content) > 0 {
		length := len(content)
		if length > wire.DataPayloadMax {
			length = wire.DataPayloadMax
		}
		frames = append(frames, wire.Frame{
			Service: wire.ServiceRecoveryArtifact, Type: wire.MessageData,
			RequestID: requestID, Sequence: sequence,
			Payload: append([]byte(nil), content[:length]...),
		})
		content = content[length:]
		sequence++
	}
	return append(frames, wire.Frame{
		Service: wire.ServiceRecoveryArtifact, Type: wire.MessageComplete,
		RequestID: requestID, Sequence: sequence,
	})
}

func encodedEvaluationFrames(t *testing.T, frames []wire.Frame) []byte {
	t.Helper()
	var encoded []byte
	for _, frame := range frames {
		record, err := wire.Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, record...)
	}
	return encoded
}

func TestEvaluationNilPlanMatchesIndependentGoldenProductionFrames(t *testing.T) {
	content := bytes.Repeat([]byte{0x7d}, 9*wire.DataPayloadMax+1)
	fixture := newRecoveryServiceFixtureWithContent(t, content)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
	request := artifactRequest(fixture, 4)
	actual := evaluationArtifactFrames(t, address, clientTLS, fixture, request)
	golden := goldenProductionArtifactFrames(content, wire.RequestID(request.RequestID))
	if !bytes.Equal(encodedEvaluationFrames(t, actual), encodedEvaluationFrames(t, golden)) {
		t.Fatalf("production frames differ from independent golden\n got: %#v\nwant: %#v", actual, golden)
	}
}

func TestEvaluationObserverFailureCancelsAndFailsClosed(t *testing.T) {
	fixture := newRecoveryServiceFixtureWithContent(t, bytes.Repeat([]byte{0x4a}, 2*wire.DataPayloadMax))
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationMemoryObserver{err: errors.New("observer failed")}
	handler, err := NewEvaluationHandler(service, EvaluationFaultArtifactDigestMismatch, observer)
	if err != nil {
		t.Fatal(err)
	}
	instrumented := installEvaluationSenderInstrumentation(t, handler)
	address, clientTLS, _ := startEvaluationHandlerServer(t, handler)
	frames := evaluationArtifactFrames(t, address, clientTLS, fixture, artifactRequest(fixture, 5))
	if len(frames) != 2 || frames[0].Type != wire.MessageData || frames[1].Type != wire.MessageError {
		t.Fatalf("observer failure did not fail closed: %#v", frames)
	}
	waitForEvaluationCounter(t, &instrumented.cancelCalls, 1)
}
