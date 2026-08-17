package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"pbns.local/gateway/internal/wire"
)

func serverFixturePath(name string) string {
	return filepath.Join("..", "..", "..", "tests", "fixtures", "keys", name)
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(
		serverFixturePath("tls-gateway-test-cert.pem"),
		serverFixturePath("tls-gateway-test-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		NextProtos:   []string{"pbns/1"},
	}
}

func testClientTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	contents, err := os.ReadFile(serverFixturePath("tls-gateway-test-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(contents) {
		t.Fatal("failed to add test root")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: "pbns-gateway.test",
		NextProtos: []string{"pbns/1"},
	}
}

func validServerConfig(t *testing.T, handler Handler) Config {
	t.Helper()
	return Config{
		TLS: testTLSConfig(t),
		Handlers: map[wire.ServiceID]Handler{
			wire.ServiceTrustedTime: handler,
		},
		Limits:           wire.DefaultLimits(),
		HandshakeTimeout: time.Second,
		ReadTimeout:      time.Second,
		WriteTimeout:     time.Second,
		MaxConnections:   4,
	}
}

func noOpHandler(context.Context, wire.Frame, *Stream) error {
	return nil
}

func TestServerRejectsInvalidTLSAndRegistry(t *testing.T) {
	valid := validServerConfig(t, HandlerFunc(noOpHandler))
	tests := map[string]struct {
		config Config
		want   error
	}{
		"nil-tls": {
			config: func() Config { cfg := valid; cfg.TLS = nil; return cfg }(),
			want:   ErrTLSProfile,
		},
		"tls-default-minimum": {
			config: func() Config { cfg := valid; cfg.TLS = cfg.TLS.Clone(); cfg.TLS.MinVersion = 0; return cfg }(),
			want:   ErrTLSProfile,
		},
		"tls-below-1.2": {
			config: func() Config {
				cfg := valid
				cfg.TLS = cfg.TLS.Clone()
				cfg.TLS.MinVersion = tls.VersionTLS11
				return cfg
			}(),
			want: ErrTLSProfile,
		},
		"tls-max-below-1.2": {
			config: func() Config {
				cfg := valid
				cfg.TLS = cfg.TLS.Clone()
				cfg.TLS.MaxVersion = tls.VersionTLS11
				return cfg
			}(),
			want: ErrTLSProfile,
		},
		"no-certificate": {
			config: func() Config { cfg := valid; cfg.TLS = cfg.TLS.Clone(); cfg.TLS.Certificates = nil; return cfg }(),
			want:   ErrTLSProfile,
		},
		"implicit-cipher-profile": {
			config: func() Config { cfg := valid; cfg.TLS = cfg.TLS.Clone(); cfg.TLS.CipherSuites = nil; return cfg }(),
			want:   ErrTLSProfile,
		},
		"no-alpn": {
			config: func() Config { cfg := valid; cfg.TLS = cfg.TLS.Clone(); cfg.TLS.NextProtos = nil; return cfg }(),
			want:   ErrTLSProfile,
		},
		"wrong-alpn": {
			config: func() Config {
				cfg := valid
				cfg.TLS = cfg.TLS.Clone()
				cfg.TLS.NextProtos = []string{"h2"}
				return cfg
			}(),
			want: ErrTLSProfile,
		},
		"fallback-alpn": {
			config: func() Config {
				cfg := valid
				cfg.TLS = cfg.TLS.Clone()
				cfg.TLS.NextProtos = []string{"pbns/1", "h2"}
				return cfg
			}(),
			want: ErrTLSProfile,
		},
		"rsa-key-exchange": {
			config: func() Config {
				cfg := valid
				cfg.TLS = cfg.TLS.Clone()
				cfg.TLS.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
				return cfg
			}(),
			want: ErrTLSProfile,
		},
		"no-handlers": {
			config: func() Config { cfg := valid; cfg.Handlers = nil; return cfg }(),
			want:   ErrServiceRegistry,
		},
		"nil-handler": {
			config: func() Config {
				cfg := valid
				cfg.Handlers = map[wire.ServiceID]Handler{wire.ServiceTrustedTime: nil}
				return cfg
			}(),
			want: ErrServiceRegistry,
		},
		"invalid-service": {
			config: func() Config {
				cfg := valid
				cfg.Handlers = map[wire.ServiceID]Handler{0: HandlerFunc(noOpHandler)}
				return cfg
			}(),
			want: ErrServiceRegistry,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(test.config); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func startServer(t *testing.T, server *Server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx, listener)
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Serve did not stop")
		}
	})
	return listener.Addr().String(), cancel, done
}

func testRequest() wire.Frame {
	var requestID wire.RequestID
	for index := range requestID {
		requestID[index] = byte(index)
	}
	return wire.Frame{
		Service:   wire.ServiceTrustedTime,
		Type:      wire.MessageRequest,
		RequestID: requestID,
	}
}

func dialTLS(t *testing.T, address string) *tls.Conn {
	t.Helper()
	connection, err := tls.Dial("tcp", address, testClientTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

func readFrame(t *testing.T, connection net.Conn) wire.Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	record, err := bufio.NewReaderSize(connection, wire.WireMax).ReadBytes(0)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	frame, err := decoder.Decode(record)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestStreamConnectionOrdinalUsesSuccessfulTLSOrder(t *testing.T) {
	if (*Stream)(nil).ConnectionOrdinal() != 0 || (&Stream{}).ConnectionOrdinal() != 0 {
		t.Fatal("nil or zero-value stream exposed an ordinal")
	}
	ordinals := make(chan uint64, 2)
	handler := HandlerFunc(func(_ context.Context, request wire.Frame, stream *Stream) error {
		ordinals <- stream.ConnectionOrdinal()
		return stream.Send(wire.Frame{
			Service: request.Service, Type: wire.MessageResponse,
			RequestID: request.RequestID, Sequence: request.Sequence,
		})
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	for want := uint64(1); want <= 2; want++ {
		connection := dialTLS(t, address)
		encoded, encodeErr := wire.Encode(testRequest())
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if _, writeErr := connection.Write(encoded); writeErr != nil {
			t.Fatal(writeErr)
		}
		_ = readFrame(t, connection)
		select {
		case got := <-ordinals:
			if got != want {
				t.Fatalf("ordinal=%d, want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("ordinal was not observed")
		}
		_ = connection.Close()
	}
}

func TestServeDispatchesOnlyAfterTLSHandshake(t *testing.T) {
	handled := make(chan wire.Frame, 1)
	handler := HandlerFunc(func(ctx context.Context, request wire.Frame, stream *Stream) error {
		select {
		case handled <- request:
		case <-ctx.Done():
			return ctx.Err()
		}
		return stream.Send(wire.Frame{
			Service:   request.Service,
			Type:      wire.MessageResponse,
			RequestID: request.RequestID,
			Sequence:  request.Sequence,
			Payload:   []byte("ok"),
		})
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	encoded, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	response := readFrame(t, connection)
	if response.Type != wire.MessageResponse || !bytes.Equal(response.Payload, []byte("ok")) {
		t.Fatalf("unexpected response: %#v", response)
	}
	select {
	case request := <-handled:
		if request.Type != wire.MessageRequest {
			t.Fatalf("unexpected request: %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("handler was not called")
	}
}

func TestServeRejectsClientWithoutPBNSALPN(t *testing.T) {
	called := make(chan struct{}, 1)
	handler := HandlerFunc(func(context.Context, wire.Frame, *Stream) error {
		called <- struct{}{}
		return nil
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	clientConfig := testClientTLSConfig(t)
	clientConfig.NextProtos = nil
	connection, err := tls.Dial("tcp", address, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	encoded, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("connection without PBNS ALPN remained open")
	}
	select {
	case <-called:
		t.Fatal("client without PBNS ALPN reached handler")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPlaintextInputNeverReachesHandler(t *testing.T) {
	called := make(chan struct{}, 1)
	handler := HandlerFunc(func(context.Context, wire.Frame, *Stream) error {
		called <- struct{}{}
		return nil
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	encoded, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, connection)
	select {
	case <-called:
		t.Fatal("plaintext request reached handler")
	default:
	}
}

func TestHandlerErrorsBecomeSanitizedTypedFrames(t *testing.T) {
	handler := HandlerFunc(func(context.Context, wire.Frame, *Stream) error {
		return errors.New("bearer-token-secret")
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	encoded, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	response := readFrame(t, connection)
	if response.Type != wire.MessageError || response.Service != wire.ServiceTrustedTime ||
		response.RequestID != testRequest().RequestID || response.Sequence != 0 {
		t.Fatalf("unexpected error frame: %#v", response)
	}
	if bytes.Contains(response.Payload, []byte("bearer-token-secret")) {
		t.Fatal("error frame exposed handler error detail")
	}
	wantPayload, err := hex.DecodeString("a3010d0201036f73657276696365206661696c757265")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.Payload, wantPayload) {
		t.Fatalf("non-canonical error payload: %x", response.Payload)
	}
	var payload map[uint64]any
	if err := cbor.Unmarshal(response.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload[uint64(1)] != uint64(13) || payload[uint64(2)] != uint64(wire.ServiceTrustedTime) ||
		payload[uint64(3)] != "service failure" {
		t.Fatalf("unexpected error payload: %#v", payload)
	}
}

func TestHandlerProtocolErrorFollowsSuccessfulOutboundData(t *testing.T) {
	handler := HandlerFunc(func(_ context.Context, request wire.Frame, stream *Stream) error {
		for sequence := uint32(0); sequence < 8; sequence++ {
			if err := stream.Send(wire.Frame{
				Service: request.Service, Type: wire.MessageData,
				RequestID: request.RequestID, Sequence: sequence, Payload: []byte{byte(sequence)},
			}); err != nil {
				return err
			}
		}
		return &ProtocolError{Code: 12, Detail: "transfer failed"}
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	request := testRequest()
	encoded, err := wire.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	reader := newPersistentFrameReader(t, connection)
	for sequence := uint32(0); sequence < 8; sequence++ {
		frame := reader.next(t, connection)
		if frame.Type != wire.MessageData || frame.Sequence != sequence {
			t.Fatalf("DATA %d = %#v", sequence, frame)
		}
	}
	errorFrame := reader.next(t, connection)
	if errorFrame.Type != wire.MessageError || errorFrame.Sequence != 8 ||
		errorFrame.RequestID != request.RequestID {
		t.Fatalf("ERROR after DATA 0..7 = %#v", errorFrame)
	}
	var payload errorPayload
	if err := cbor.Unmarshal(errorFrame.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != 12 || payload.Detail != "transfer failed" {
		t.Fatalf("unexpected error payload: %#v", payload)
	}
}

func TestServeCancellationClosesIdleTLSConnections(t *testing.T) {
	handled := make(chan struct{}, 1)
	handler := HandlerFunc(func(context.Context, wire.Frame, *Stream) error {
		handled <- struct{}{}
		return nil
	})
	config := validServerConfig(t, handler)
	config.ReadTimeout = 5 * time.Second
	instance, err := New(config)
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
	connection := dialTLS(t, listener.Addr().String())
	request, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-handled:
	case <-time.After(time.Second):
		t.Fatal("request was not dispatched")
	}
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Serve waited for the idle connection read deadline")
	}
	_ = connection.Close()
}

func TestStreamRejectsCrossRequestResponses(t *testing.T) {
	handler := HandlerFunc(func(_ context.Context, request wire.Frame, stream *Stream) error {
		other := request
		other.Type = wire.MessageResponse
		other.RequestID[0] ^= 1
		return stream.Send(other)
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	encoded, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	response := readFrame(t, connection)
	if response.Type != wire.MessageError {
		t.Fatalf("got type %d, want ERROR", response.Type)
	}
}

type persistentFrameReader struct {
	reader  *bufio.Reader
	decoder *wire.Decoder
}

func newPersistentFrameReader(t *testing.T, connection net.Conn) *persistentFrameReader {
	t.Helper()
	decoder, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return &persistentFrameReader{
		reader: bufio.NewReaderSize(connection, wire.WireMax), decoder: decoder,
	}
}

func (reader *persistentFrameReader) next(t *testing.T, connection net.Conn) wire.Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	record, err := reader.reader.ReadBytes(0)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := reader.decoder.Decode(record)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func ackFrame(request wire.Frame) wire.Frame {
	payload := make([]byte, wire.ACKPayloadSize)
	binary.BigEndian.PutUint32(payload[:4], 8)
	binary.BigEndian.PutUint32(payload[4:], 8)
	return wire.Frame{
		Service: request.Service, Type: wire.MessageACK,
		RequestID: request.RequestID, Sequence: 0, Payload: payload,
	}
}

type recordingConnection struct {
	mutex            sync.Mutex
	writes           [][]byte
	writeError       error
	writeStarted     chan struct{}
	releaseWrite     <-chan struct{}
	activeWrites     int
	concurrentWrites bool
}

func (connection *recordingConnection) Read([]byte) (int, error) { return 0, io.EOF }

func (connection *recordingConnection) Write(data []byte) (int, error) {
	connection.mutex.Lock()
	connection.activeWrites++
	if connection.activeWrites > 1 {
		connection.concurrentWrites = true
	}
	connection.writes = append(connection.writes, append([]byte(nil), data...))
	writeError := connection.writeError
	started := connection.writeStarted
	release := connection.releaseWrite
	connection.mutex.Unlock()

	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}

	connection.mutex.Lock()
	connection.activeWrites--
	connection.mutex.Unlock()
	if writeError != nil {
		return 0, writeError
	}
	return len(data), nil
}

func (*recordingConnection) Close() error                     { return nil }
func (*recordingConnection) LocalAddr() net.Addr              { return nil }
func (*recordingConnection) RemoteAddr() net.Addr             { return nil }
func (*recordingConnection) SetDeadline(time.Time) error      { return nil }
func (*recordingConnection) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConnection) SetWriteDeadline(time.Time) error { return nil }

func (connection *recordingConnection) writeCount() int {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	return len(connection.writes)
}

func (connection *recordingConnection) setWriteError(err error) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.writeError = err
}

func newTestStream(t *testing.T, connection net.Conn) (*Stream, wire.Frame) {
	t.Helper()
	validator, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest()
	return &Stream{
		connection: connection, validator: validator, service: request.Service,
		requestID: request.RequestID, writeTimeout: time.Second,
	}, request
}

func TestStreamRejectsUnusableOutboundSequenceBeforeWrite(t *testing.T) {
	connection := &recordingConnection{}
	stream, request := newTestStream(t, connection)
	if err := stream.Send(wire.Frame{
		Service: request.Service, Type: wire.MessageData,
		RequestID: request.RequestID, Sequence: ^uint32(0), Payload: []byte{1},
	}); !errors.Is(err, ErrStreamSequenceOverflow) {
		t.Fatalf("Send error = %v, want sequence overflow", err)
	}
	if connection.writeCount() != 0 {
		t.Fatal("unusable UINT32_MAX frame was written")
	}
}

func TestStreamOutboundSequenceExhaustionFailsClosed(t *testing.T) {
	connection := &recordingConnection{}
	stream, request := newTestStream(t, connection)
	if err := stream.Send(wire.Frame{
		Service: request.Service, Type: wire.MessageData,
		RequestID: request.RequestID, Sequence: ^uint32(0) - 1, Payload: []byte{1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stream.sendError(request, &ProtocolError{Code: 12, Detail: "transfer failed"}); !errors.Is(err, ErrStreamSequenceOverflow) {
		t.Fatalf("sendError error = %v, want sequence overflow", err)
	}
	if connection.writeCount() != 1 {
		t.Fatal("automatic ERROR was written after outbound sequence exhaustion")
	}
}

func TestStreamFailedWriteDoesNotAdvanceOutboundSequence(t *testing.T) {
	connection := &recordingConnection{writeError: io.ErrClosedPipe}
	stream, request := newTestStream(t, connection)
	if err := stream.Send(wire.Frame{
		Service: request.Service, Type: wire.MessageData,
		RequestID: request.RequestID, Sequence: 7, Payload: []byte{1},
	}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Send error = %v, want closed pipe", err)
	}
	connection.setWriteError(nil)
	if err := stream.sendError(request, &ProtocolError{Code: 12, Detail: "transfer failed"}); err != nil {
		t.Fatal(err)
	}
	if connection.writeCount() != 2 {
		t.Fatal("expected failed DATA attempt and ERROR write")
	}
	decoder, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	connection.mutex.Lock()
	errorRecord := append([]byte(nil), connection.writes[1]...)
	connection.mutex.Unlock()
	errorFrame, err := decoder.Decode(errorRecord)
	if err != nil {
		t.Fatal(err)
	}
	if errorFrame.Type != wire.MessageError || errorFrame.Sequence != 0 {
		t.Fatalf("ERROR after failed DATA = %#v, want sequence zero", errorFrame)
	}
}

func TestStreamConcurrentSendsSerializeOutboundState(t *testing.T) {
	release := make(chan struct{})
	connection := &recordingConnection{
		writeStarted: make(chan struct{}, 2),
		releaseWrite: release,
	}
	stream, request := newTestStream(t, connection)
	frames := []wire.Frame{
		{Service: request.Service, Type: wire.MessageData, RequestID: request.RequestID, Sequence: 0, Payload: []byte{0}},
		{Service: request.Service, Type: wire.MessageData, RequestID: request.RequestID, Sequence: 1, Payload: []byte{1}},
	}
	results := make(chan error, len(frames))
	go func() { results <- stream.Send(frames[0]) }()
	select {
	case <-connection.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("first concurrent Send did not begin writing")
	}
	go func() { results <- stream.Send(frames[1]) }()
	close(release)
	for range frames {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	connection.mutex.Lock()
	concurrentWrites := connection.concurrentWrites
	connection.mutex.Unlock()
	if concurrentWrites || connection.writeCount() != 2 || stream.outboundSequence != 2 {
		t.Fatalf("concurrent Send state: simultaneous=%t writes=%d sequence=%d",
			concurrentWrites, connection.writeCount(), stream.outboundSequence)
	}
}

func TestStreamReceiveAcceptsFragmentedACKAndPreservesNextRequest(t *testing.T) {
	var calls int
	received := make(chan wire.Frame, 1)
	handler := HandlerFunc(func(ctx context.Context, request wire.Frame, stream *Stream) error {
		calls++
		if calls == 2 {
			return stream.Send(wire.Frame{
				Service: request.Service, Type: wire.MessageResponse,
				RequestID: request.RequestID, Sequence: 0, Payload: []byte("second"),
			})
		}
		for sequence := uint32(0); sequence < 8; sequence++ {
			if err := stream.Send(wire.Frame{
				Service: request.Service, Type: wire.MessageData,
				RequestID: request.RequestID, Sequence: sequence, Payload: []byte{byte(sequence)},
			}); err != nil {
				return err
			}
		}
		ack, err := stream.Receive(ctx)
		if err != nil {
			return err
		}
		received <- ack
		return stream.Send(wire.Frame{
			Service: request.Service, Type: wire.MessageComplete,
			RequestID: request.RequestID, Sequence: 8,
		})
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	reader := newPersistentFrameReader(t, connection)
	request := testRequest()
	encodedRequest, err := wire.Encode(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encodedRequest); err != nil {
		t.Fatal(err)
	}
	for sequence := uint32(0); sequence < 8; sequence++ {
		frame := reader.next(t, connection)
		if frame.Type != wire.MessageData || frame.Sequence != sequence {
			t.Fatalf("unexpected data frame: %#v", frame)
		}
	}
	encodedACK, err := wire.Encode(ackFrame(request))
	if err != nil {
		t.Fatal(err)
	}
	middle := len(encodedACK) / 2
	if _, err := connection.Write(encodedACK[:middle]); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encodedACK[middle:]); err != nil {
		t.Fatal(err)
	}
	if complete := reader.next(t, connection); complete.Type != wire.MessageComplete {
		t.Fatalf("unexpected completion: %#v", complete)
	}
	select {
	case ack := <-received:
		if ack.Type != wire.MessageACK || ack.RequestID != request.RequestID {
			t.Fatalf("unexpected received ACK: %#v", ack)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not receive ACK")
	}

	second := request
	second.RequestID[0] ^= 0x80
	encodedSecond, err := wire.Encode(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encodedSecond); err != nil {
		t.Fatal(err)
	}
	response := reader.next(t, connection)
	if response.Type != wire.MessageResponse || string(response.Payload) != "second" ||
		response.RequestID != second.RequestID {
		t.Fatalf("unexpected second response: %#v", response)
	}
}

func TestStreamReceiveAcceptsCorrelatedCancel(t *testing.T) {
	received := make(chan wire.Frame, 1)
	handler := HandlerFunc(func(ctx context.Context, _ wire.Frame, stream *Stream) error {
		frame, err := stream.Receive(ctx)
		if err != nil {
			return err
		}
		received <- frame
		return nil
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	request := testRequest()
	encodedRequest, _ := wire.Encode(request)
	cancel := request
	cancel.Type = wire.MessageCancel
	cancel.Sequence = 1
	encodedCancel, _ := wire.Encode(cancel)
	if _, err := connection.Write(append(encodedRequest, encodedCancel...)); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-received:
		if frame.Type != wire.MessageCancel {
			t.Fatalf("unexpected frame: %#v", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("handler did not receive cancel")
	}
}

func TestStreamReceiveRejectsTypeAndCorrelationSubstitution(t *testing.T) {
	request := testRequest()
	for name, mutate := range map[string]func(*wire.Frame){
		"service":    func(frame *wire.Frame) { frame.Service = wire.ServiceEnrollment },
		"request-id": func(frame *wire.Frame) { frame.RequestID[0] ^= 1 },
		"nested-request": func(frame *wire.Frame) {
			frame.Type = wire.MessageRequest
			frame.Payload = nil
		},
		"data": func(frame *wire.Frame) {
			frame.Type = wire.MessageData
			frame.Payload = []byte{1}
		},
		"response": func(frame *wire.Frame) {
			frame.Type = wire.MessageResponse
			frame.Payload = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			receiveError := make(chan error, 1)
			handler := HandlerFunc(func(ctx context.Context, _ wire.Frame, stream *Stream) error {
				_, err := stream.Receive(ctx)
				receiveError <- err
				return err
			})
			instance, err := New(validServerConfig(t, handler))
			if err != nil {
				t.Fatal(err)
			}
			address, _, _ := startServer(t, instance)
			connection := dialTLS(t, address)
			encodedRequest, _ := wire.Encode(request)
			candidate := ackFrame(request)
			mutate(&candidate)
			encodedCandidate, err := wire.Encode(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Write(append(encodedRequest, encodedCandidate...)); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-receiveError:
				if !errors.Is(err, ErrStreamCorrelation) {
					t.Fatalf("got %v, want ErrStreamCorrelation", err)
				}
			case <-time.After(time.Second):
				t.Fatal("handler receive did not return")
			}
		})
	}
}

func TestStreamReceiveStopsOnContextCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	receiveError := make(chan error, 1)
	handler := HandlerFunc(func(ctx context.Context, _ wire.Frame, stream *Stream) error {
		started <- struct{}{}
		_, err := stream.Receive(ctx)
		receiveError <- err
		return err
	})
	config := validServerConfig(t, handler)
	config.ReadTimeout = 5 * time.Second
	instance, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	address, cancel, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	encodedRequest, _ := wire.Encode(testRequest())
	if _, err := connection.Write(encodedRequest); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start receive")
	}
	cancel()
	select {
	case err := <-receiveError:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context cancellation", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("receive did not stop on context cancellation")
	}
}

func TestStreamReceiveRejectsRecordWithoutBoundedDelimiter(t *testing.T) {
	receiveError := make(chan error, 1)
	handler := HandlerFunc(func(ctx context.Context, _ wire.Frame, stream *Stream) error {
		_, err := stream.Receive(ctx)
		receiveError <- err
		return err
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	encodedRequest, _ := wire.Encode(testRequest())
	if _, err := connection.Write(encodedRequest); err != nil {
		t.Fatal(err)
	}
	withoutDelimiter := bytes.Repeat([]byte{0xff}, wire.WireMax)
	if _, err := connection.Write(withoutDelimiter); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-receiveError:
		if !errors.Is(err, bufio.ErrBufferFull) {
			t.Fatalf("got %v, want bounded buffer rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("undelimited record did not fail")
	}
}

func TestStreamReceiveUsesBoundedReadDeadline(t *testing.T) {
	receiveError := make(chan error, 1)
	handler := HandlerFunc(func(ctx context.Context, _ wire.Frame, stream *Stream) error {
		_, err := stream.Receive(ctx)
		receiveError <- err
		return err
	})
	config := validServerConfig(t, handler)
	config.ReadTimeout = 30 * time.Millisecond
	instance, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	connection := dialTLS(t, address)
	encodedRequest, _ := wire.Encode(testRequest())
	if _, err := connection.Write(encodedRequest); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-receiveError:
		if err == nil {
			t.Fatal("receive timeout returned nil")
		}
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("got %v, want network timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("handler receive exceeded bounded deadline")
	}
}
