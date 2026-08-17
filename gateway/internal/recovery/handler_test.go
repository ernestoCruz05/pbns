package recovery

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

type recoveryFrameReader struct {
	reader  *bufio.Reader
	decoder *wire.Decoder
}

func recoveryTLSConfig(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	base := filepath.Join("..", "..", "..", "tests", "fixtures", "keys")
	certificate, err := tls.LoadX509KeyPair(
		filepath.Join(base, "tls-gateway-test-cert.pem"),
		filepath.Join(base, "tls-gateway-test-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(filepath.Join(base, "tls-gateway-test-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(encoded) {
		t.Fatal("test TLS certificate did not parse")
	}
	return &tls.Config{
			MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"pbns/1"},
		}, &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: roots,
			ServerName: "pbns-gateway.test", NextProtos: []string{"pbns/1"},
		}
}

func startRecoveryHandlerServer(t *testing.T, service *Service,
	readTimeout time.Duration) (string, *tls.Config) {
	t.Helper()
	serverTLS, clientTLS := recoveryTLSConfig(t)
	instance, err := server.New(server.Config{
		TLS: serverTLS,
		Handlers: map[wire.ServiceID]server.Handler{
			wire.ServiceRecoveryArtifact: service,
		},
		Limits: wire.DefaultLimits(), HandshakeTimeout: time.Second,
		ReadTimeout: readTimeout, WriteTimeout: time.Second, MaxConnections: 4,
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
			t.Error("recovery server did not stop")
		}
	})
	return listener.Addr().String(), clientTLS
}

func dialRecoveryHandler(t *testing.T, address string, config *tls.Config) (*tls.Conn, *recoveryFrameReader) {
	t.Helper()
	connection, err := tls.Dial("tcp", address, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	decoder, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return connection, &recoveryFrameReader{
		reader: bufio.NewReaderSize(connection, wire.WireMax), decoder: decoder,
	}
}

func (reader *recoveryFrameReader) next(t *testing.T, connection net.Conn) wire.Frame {
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

func signedRecoveryFrame(t *testing.T, fixture recoveryServiceFixture,
	request Request) wire.Frame {
	t.Helper()
	signed, err := SignRequest(request, fixture.hostSigner)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Frame{
		Service: wire.ServiceRecoveryArtifact, Type: wire.MessageRequest,
		RequestID: wire.RequestID(request.RequestID), Sequence: 0, Payload: signed,
	}
}

func writeRecoveryFrame(t *testing.T, connection net.Conn, frame wire.Frame) {
	t.Helper()
	encoded, err := wire.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatal(err)
	}
}

func artifactRequest(fixture recoveryServiceFixture, salt byte) Request {
	request := Request{
		Domain: RequestDomain, Version: RequestVersion,
		Service: ServiceRecoveryArtifact, Operation: OperationArtifact,
		HostFingerprint: fixture.request.HostFingerprint,
		ArtifactDigest:  fixture.artifact.Digest,
	}
	for index := range request.RequestID {
		request.RequestID[index] = byte(0x10 + index)
	}
	for index := range request.Nonce {
		request.Nonce[index] = byte(0x40 + index)
	}
	request.RequestID[0] ^= salt
	request.Nonce[0] ^= salt
	return request
}

func TestRecoveryHandlerReturnsAuthenticatedManifest(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, fixture.request))
	response := reader.next(t, connection)
	if response.Type != wire.MessageResponse || response.Sequence != 0 ||
		response.RequestID != wire.RequestID(fixture.request.RequestID) {
		t.Fatalf("unexpected manifest response: %#v", response)
	}
	expectation := Expectation{
		RequestID:   fixture.request.RequestID,
		HostBinding: fixture.request.HostFingerprint, Nonce: fixture.request.Nonce,
		RecoverySigningKeyID: fixture.manifestKeyID,
		ExpectedPolicyKeyID:  fixture.policyKeyID,
		TrustedEarliestNS:    90_000_000_500, TrustedLatestNS: 120_000_000_500,
	}
	if _, err := VerifyManifest(response.Payload, fixture.manifestVerifier, expectation); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryHandlerStreamsExactChunksWithACKBackpressure(t *testing.T) {
	sizes := []int{1, 16_384, 16_385, 8 * 16_384, 8*16_384 + 1}
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			content := bytes.Repeat([]byte{byte(size%251 + 1)}, size)
			fixture := newRecoveryServiceFixtureWithContent(t, content)
			service, err := NewService(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
			connection, reader := dialRecoveryHandler(t, address, clientTLS)
			request := artifactRequest(fixture, byte(size%127+1))
			writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))

			var received []byte
			var dataSequence uint32
			var ackSequence uint32
			for {
				frame := reader.next(t, connection)
				if frame.Type == wire.MessageComplete {
					if frame.Sequence != dataSequence || len(frame.Payload) != 0 {
						t.Fatalf("unexpected complete: %#v", frame)
					}
					break
				}
				if frame.Type != wire.MessageData || frame.Sequence != dataSequence ||
					len(frame.Payload) == 0 || len(frame.Payload) > wire.DataPayloadMax {
					t.Fatalf("unexpected data: %#v", frame)
				}
				received = append(received, frame.Payload...)
				dataSequence++
				if dataSequence%ACKWindow == 0 {
					writeRecoveryFrame(t, connection,
						ACKFrame(wire.RequestID(request.RequestID), ackSequence, dataSequence))
					ackSequence++
				}
			}
			if !bytes.Equal(received, content) {
				t.Fatalf("received %d bytes, want %d", len(received), len(content))
			}
		})
	}
}

func TestRecoveryHandlerRejectsRequestAndACKSubstitution(t *testing.T) {
	t.Run("header-request-id", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		service, err := NewService(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
		connection, reader := dialRecoveryHandler(t, address, clientTLS)
		frame := signedRecoveryFrame(t, fixture, fixture.request)
		frame.RequestID[0] ^= 1
		writeRecoveryFrame(t, connection, frame)
		if response := reader.next(t, connection); response.Type != wire.MessageError {
			t.Fatalf("substituted request id got %#v", response)
		}
	})
	t.Run("inactive-digest", func(t *testing.T) {
		fixture := newRecoveryServiceFixture(t)
		service, err := NewService(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
		connection, reader := dialRecoveryHandler(t, address, clientTLS)
		request := artifactRequest(fixture, 1)
		request.ArtifactDigest[0] ^= 1
		writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
		if response := reader.next(t, connection); response.Type != wire.MessageError {
			t.Fatalf("inactive digest got %#v", response)
		}
	})

	for name, mutate := range map[string]func(*wire.Frame){
		"ack-sequence": func(frame *wire.Frame) { frame.Sequence = 1 },
		"next-data":    func(frame *wire.Frame) { frame.Payload[3] ^= 1 },
		"window":       func(frame *wire.Frame) { frame.Payload[7] ^= 1 },
		"request-id":   func(frame *wire.Frame) { frame.RequestID[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRecoveryServiceFixtureWithContent(
				t, bytes.Repeat([]byte{0xa5}, 8*wire.DataPayloadMax),
			)
			service, err := NewService(fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
			connection, reader := dialRecoveryHandler(t, address, clientTLS)
			request := artifactRequest(fixture, 2)
			writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
			for sequence := uint32(0); sequence < ACKWindow; sequence++ {
				if frame := reader.next(t, connection); frame.Type != wire.MessageData {
					t.Fatalf("unexpected pre-ACK frame: %#v", frame)
				}
			}
			ack := ACKFrame(wire.RequestID(request.RequestID), 0, ACKWindow)
			mutate(&ack)
			writeRecoveryFrame(t, connection, ack)
			if response := reader.next(t, connection); response.Type != wire.MessageError {
				t.Fatalf("substituted ACK got %#v", response)
			}
		})
	}
}

func TestRecoveryHandlerCancelTimeoutAndReconnectRestartAtZero(t *testing.T) {
	fixture := newRecoveryServiceFixtureWithContent(
		t, bytes.Repeat([]byte{0x6c}, 8*wire.DataPayloadMax+1),
	)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS := startRecoveryHandlerServer(t, service, 40*time.Millisecond)

	request := artifactRequest(fixture, 3)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	writeRecoveryFrame(t, connection, signedRecoveryFrame(t, fixture, request))
	for sequence := uint32(0); sequence < ACKWindow; sequence++ {
		if frame := reader.next(t, connection); frame.Type != wire.MessageData {
			t.Fatalf("unexpected data before cancel: %#v", frame)
		}
	}
	cancel := wire.Frame{
		Service: wire.ServiceRecoveryArtifact, Type: wire.MessageCancel,
		RequestID: wire.RequestID(request.RequestID), Sequence: 0,
	}
	writeRecoveryFrame(t, connection, cancel)
	if response := reader.next(t, connection); response.Type != wire.MessageError {
		t.Fatalf("cancel got %#v", response)
	}

	restart := artifactRequest(fixture, 4)
	restartedConnection, restartedReader := dialRecoveryHandler(t, address, clientTLS)
	writeRecoveryFrame(t, restartedConnection, signedRecoveryFrame(t, fixture, restart))
	if first := restartedReader.next(t, restartedConnection); first.Type != wire.MessageData || first.Sequence != 0 {
		t.Fatalf("restart did not begin at zero: %#v", first)
	}

	timeoutRequest := artifactRequest(fixture, 5)
	timeoutConnection, timeoutReader := dialRecoveryHandler(t, address, clientTLS)
	writeRecoveryFrame(t, timeoutConnection, signedRecoveryFrame(t, fixture, timeoutRequest))
	for sequence := uint32(0); sequence < ACKWindow; sequence++ {
		_ = timeoutReader.next(t, timeoutConnection)
	}
	if response := timeoutReader.next(t, timeoutConnection); response.Type != wire.MessageError {
		t.Fatalf("missing ACK got %#v", response)
	}
}

func TestRecoveryHandlerRejectsInvalidOuterFrame(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
	for name, mutate := range map[string]func(*wire.Frame){
		"type":     func(frame *wire.Frame) { frame.Type = wire.MessageResponse },
		"sequence": func(frame *wire.Frame) { frame.Sequence = 1 },
		"empty":    func(frame *wire.Frame) { frame.Payload = nil },
	} {
		t.Run(name, func(t *testing.T) {
			connection, reader := dialRecoveryHandler(t, address, clientTLS)
			frame := signedRecoveryFrame(t, fixture, fixture.request)
			mutate(&frame)
			writeRecoveryFrame(t, connection, frame)
			response := reader.next(t, connection)
			if response.Type != wire.MessageError {
				t.Fatalf("invalid outer frame got %#v", response)
			}
		})
	}
}

func TestRecoveryHandlerReturnsTypedAuthenticationError(t *testing.T) {
	fixture := newRecoveryServiceFixture(t)
	service, err := NewService(fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	address, clientTLS := startRecoveryHandlerServer(t, service, time.Second)
	connection, reader := dialRecoveryHandler(t, address, clientTLS)
	frame := signedRecoveryFrame(t, fixture, fixture.request)
	frame.Payload[len(frame.Payload)-1] ^= 1
	writeRecoveryFrame(t, connection, frame)
	response := reader.next(t, connection)
	if response.Type != wire.MessageError {
		t.Fatalf("tampered signature got %#v", response)
	}
	var payload struct {
		Code    uint64 `cbor:"1,keyasint"`
		Service uint64 `cbor:"2,keyasint"`
		Detail  string `cbor:"3,keyasint"`
	}
	if err := cbor.Unmarshal(response.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != statusAuthentication ||
		payload.Service != uint64(wire.ServiceRecoveryArtifact) ||
		payload.Detail != "recovery request authentication failed" {
		t.Fatalf("unexpected authentication error: %#v", payload)
	}
}
