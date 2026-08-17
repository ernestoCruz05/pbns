package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"

	"pbns.local/gateway/internal/tlsprofile"
	"pbns.local/gateway/internal/wire"
)

var (
	ErrArgument               = errors.New("invalid server argument")
	ErrTLSProfile             = errors.New("invalid TLS profile")
	ErrServiceRegistry        = errors.New("invalid service registry")
	ErrStreamCorrelation      = errors.New("stream frame correlation mismatch")
	ErrStreamSequenceOverflow = errors.New("stream outbound sequence overflow")
)

const (
	pbnsALPN            = "pbns/1"
	statusCrypto        = 13
	statusUnimplemented = 17
	maxErrorDetail      = 256
)

type Handler interface {
	Handle(ctx context.Context, request wire.Frame, stream *Stream) error
}

type HandlerFunc func(ctx context.Context, request wire.Frame, stream *Stream) error

func (function HandlerFunc) Handle(ctx context.Context, request wire.Frame, stream *Stream) error {
	return function(ctx, request, stream)
}

type ProtocolError struct {
	Code   uint64
	Detail string
}

func (protocolError *ProtocolError) Error() string {
	return "PBNS protocol error"
}

type Config struct {
	TLS              *tls.Config
	Handlers         map[wire.ServiceID]Handler
	Limits           wire.Limits
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	MaxConnections   int
}

type Server struct {
	tlsConfig         *tls.Config
	handlers          map[wire.ServiceID]Handler
	limits            wire.Limits
	handshakeTimeout  time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	maxConnections    int
	connectionCounter atomic.Uint64
}

func New(config Config) (*Server, error) {
	if !validTLSConfig(config.TLS) {
		return nil, ErrTLSProfile
	}
	if len(config.Handlers) == 0 {
		return nil, ErrServiceRegistry
	}
	handlers := make(map[wire.ServiceID]Handler, len(config.Handlers))
	for service, handler := range config.Handlers {
		if !service.Valid() || handler == nil {
			return nil, ErrServiceRegistry
		}
		handlers[service] = handler
	}
	if _, err := wire.NewDecoder(config.Limits); err != nil ||
		config.Limits.EncodedRecordMax == 0 || config.HandshakeTimeout <= 0 ||
		config.ReadTimeout <= 0 || config.WriteTimeout <= 0 || config.MaxConnections <= 0 {
		return nil, ErrArgument
	}
	return &Server{
		tlsConfig:        config.TLS.Clone(),
		handlers:         handlers,
		limits:           config.Limits,
		handshakeTimeout: config.HandshakeTimeout,
		readTimeout:      config.ReadTimeout,
		writeTimeout:     config.WriteTimeout,
		maxConnections:   config.MaxConnections,
	}, nil
}

func validTLSConfig(config *tls.Config) bool {
	if config == nil || config.MinVersion < tls.VersionTLS12 ||
		(config.MaxVersion != 0 && config.MaxVersion < tls.VersionTLS12) ||
		(config.MaxVersion != 0 && config.MaxVersion < config.MinVersion) ||
		len(config.Certificates) == 0 ||
		!tlsprofile.ValidTLS12CipherSuites(config.CipherSuites) ||
		len(config.NextProtos) != 1 || config.NextProtos[0] != pbnsALPN {
		return false
	}
	for _, certificate := range config.Certificates {
		if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
			return false
		}
	}
	return true
}

func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	if server == nil || ctx == nil || listener == nil {
		return ErrArgument
	}
	stopClosing := make(chan struct{})
	defer close(stopClosing)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-stopClosing:
		}
	}()

	connections := make(chan struct{}, server.maxConnections)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept TLS connection: %w", err)
		}
		select {
		case connections <- struct{}{}:
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { <-connections }()
				server.serveConnection(ctx, connection)
			}()
		default:
			_ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(parent context.Context, connection net.Conn) {
	defer connection.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopClosing := make(chan struct{})
	defer close(stopClosing)
	go func() {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-stopClosing:
		}
	}()

	tlsConnection := tls.Server(connection, server.tlsConfig)
	if err := tlsConnection.SetDeadline(time.Now().Add(server.handshakeTimeout)); err != nil {
		return
	}
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return
	}
	if tlsConnection.ConnectionState().NegotiatedProtocol != pbnsALPN {
		return
	}
	if err := tlsConnection.SetDeadline(time.Time{}); err != nil {
		return
	}
	connectionOrdinal := server.connectionCounter.Add(1)

	decoder, err := wire.NewDecoder(server.limits)
	if err != nil {
		return
	}
	reader := bufio.NewReaderSize(tlsConnection, server.limits.EncodedRecordMax)
	for {
		request, err := readConnectionFrame(
			ctx, tlsConnection, reader, decoder, server.readTimeout,
		)
		if err != nil {
			return
		}
		stream := &Stream{
			connection:        tlsConnection,
			connectionOrdinal: connectionOrdinal,
			reader:            reader,
			validator:         decoder,
			service:           request.Service,
			requestID:         request.RequestID,
			readTimeout:       server.readTimeout,
			writeTimeout:      server.writeTimeout,
		}
		handler, configured := server.handlers[request.Service]
		if !configured {
			if err := stream.sendError(request, &ProtocolError{
				Code:   statusUnimplemented,
				Detail: "service not configured",
			}); err != nil {
				return
			}
			continue
		}
		handlerError := handler.Handle(ctx, request, stream)
		if handlerError != nil {
			if ctx.Err() != nil {
				return
			}
			if sendError := stream.sendError(request, handlerError); sendError != nil {
				return
			}
		}
	}
}

type Stream struct {
	connection        net.Conn
	connectionOrdinal uint64
	reader            *bufio.Reader
	validator         *wire.Decoder
	service           wire.ServiceID
	requestID         wire.RequestID
	readTimeout       time.Duration
	writeTimeout      time.Duration
	mutex             sync.Mutex
	outboundSequence  uint32
	outboundExhausted bool
}

func (stream *Stream) ConnectionOrdinal() uint64 {
	if stream == nil {
		return 0
	}
	return stream.connectionOrdinal
}

func readConnectionFrame(ctx context.Context, connection net.Conn,
	reader *bufio.Reader, decoder *wire.Decoder, readTimeout time.Duration) (wire.Frame, error) {
	if ctx == nil || connection == nil || reader == nil || decoder == nil || readTimeout <= 0 {
		return wire.Frame{}, ErrArgument
	}
	deadline := time.Now().Add(readTimeout)
	if contextDeadline, configured := ctx.Deadline(); configured && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetReadDeadline(deadline); err != nil {
		return wire.Frame{}, err
	}
	stop := context.AfterFunc(ctx, func() {
		_ = connection.SetReadDeadline(time.Now())
	})
	defer stop()
	record, err := reader.ReadSlice(0)
	if err != nil {
		if ctx.Err() != nil {
			return wire.Frame{}, ctx.Err()
		}
		return wire.Frame{}, err
	}
	frame, err := decoder.Decode(record)
	if err != nil {
		return wire.Frame{}, err
	}
	return frame, nil
}

func (stream *Stream) Send(frame wire.Frame) error {
	if err := stream.validateOutboundFrame(frame); err != nil {
		return err
	}
	encoded, err := wire.Encode(frame)
	if err != nil {
		return err
	}
	if _, err := stream.validator.Decode(encoded); err != nil {
		return err
	}
	stream.mutex.Lock()
	defer stream.mutex.Unlock()
	return stream.writeOutboundFrameLocked(frame, encoded)
}

func (stream *Stream) validateOutboundFrame(frame wire.Frame) error {
	if stream == nil || stream.connection == nil || stream.validator == nil {
		return ErrArgument
	}
	if frame.Service != stream.service || frame.RequestID != stream.requestID ||
		frame.Type == wire.MessageRequest {
		return ErrStreamCorrelation
	}
	return nil
}

func (stream *Stream) writeOutboundFrameLocked(frame wire.Frame, encoded []byte) error {
	if stream.outboundExhausted || frame.Sequence == ^uint32(0) {
		return ErrStreamSequenceOverflow
	}
	if err := stream.connection.SetWriteDeadline(time.Now().Add(stream.writeTimeout)); err != nil {
		return err
	}
	if err := writeAll(stream.connection, encoded); err != nil {
		return err
	}
	if frame.Sequence == ^uint32(0)-1 {
		stream.outboundExhausted = true
		return nil
	}
	stream.outboundSequence = frame.Sequence + 1
	return nil
}

func (stream *Stream) sendErrorFrame(frame wire.Frame) error {
	if err := stream.validateOutboundFrame(frame); err != nil {
		return err
	}
	stream.mutex.Lock()
	defer stream.mutex.Unlock()
	if stream.outboundExhausted || stream.outboundSequence == ^uint32(0) {
		return ErrStreamSequenceOverflow
	}
	frame.Sequence = stream.outboundSequence
	encoded, err := wire.Encode(frame)
	if err != nil {
		return err
	}
	if _, err := stream.validator.Decode(encoded); err != nil {
		return err
	}
	return stream.writeOutboundFrameLocked(frame, encoded)
}

// ReceiveUpload reads an inbound DATA/COMPLETE/CANCEL frame correlated with
// the active request. It is separate from Receive so download ACK semantics
// cannot be weakened by an upload handler.
func (stream *Stream) ReceiveUpload(ctx context.Context) (wire.Frame, error) {
	if stream == nil || stream.connection == nil || stream.reader == nil ||
		stream.validator == nil || ctx == nil || stream.readTimeout <= 0 {
		return wire.Frame{}, ErrArgument
	}
	frame, err := readConnectionFrame(ctx, stream.connection, stream.reader, stream.validator, stream.readTimeout)
	if err != nil {
		return wire.Frame{}, err
	}
	if frame.Service != stream.service || frame.RequestID != stream.requestID ||
		(frame.Type != wire.MessageData && frame.Type != wire.MessageComplete && frame.Type != wire.MessageCancel) {
		return wire.Frame{}, ErrStreamCorrelation
	}
	return frame, nil
}

func (stream *Stream) Receive(ctx context.Context) (wire.Frame, error) {
	if stream == nil || stream.connection == nil || stream.reader == nil ||
		stream.validator == nil || ctx == nil || stream.readTimeout <= 0 {
		return wire.Frame{}, ErrArgument
	}
	frame, err := readConnectionFrame(
		ctx, stream.connection, stream.reader, stream.validator, stream.readTimeout,
	)
	if err != nil {
		return wire.Frame{}, err
	}
	if frame.Service != stream.service || frame.RequestID != stream.requestID ||
		(frame.Type != wire.MessageACK && frame.Type != wire.MessageCancel) {
		return wire.Frame{}, ErrStreamCorrelation
	}
	return frame, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(data) {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}

type errorPayload struct {
	Code    uint64 `cbor:"1,keyasint"`
	Service uint64 `cbor:"2,keyasint"`
	Detail  string `cbor:"3,keyasint"`
}

func (stream *Stream) sendError(request wire.Frame, handlerError error) error {
	protocolError := &ProtocolError{Code: statusCrypto, Detail: "service failure"}
	var supplied *ProtocolError
	if errors.As(handlerError, &supplied) && supplied != nil &&
		supplied.Code >= 1 && supplied.Code <= 22 {
		protocolError.Code = supplied.Code
		protocolError.Detail = sanitizeDetail(supplied.Detail)
	}
	options := cbor.CanonicalEncOptions()
	mode, err := options.EncMode()
	if err != nil {
		return err
	}
	payload, err := mode.Marshal(errorPayload{
		Code:    protocolError.Code,
		Service: uint64(request.Service),
		Detail:  protocolError.Detail,
	})
	if err != nil {
		return err
	}
	return stream.sendErrorFrame(wire.Frame{
		Service:   request.Service,
		Type:      wire.MessageError,
		RequestID: request.RequestID,
		Payload:   payload,
	})
}

func sanitizeDetail(detail string) string {
	if detail == "" || !utf8.ValidString(detail) {
		return "service failure"
	}
	if len(detail) <= maxErrorDetail {
		return detail
	}
	truncated := detail[:maxErrorDetail]
	for !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}
