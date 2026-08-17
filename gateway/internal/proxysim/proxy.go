package proxysim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const copyBufferSize = 16 * 1024

var (
	ErrArgument       = errors.New("invalid proxy simulator argument")
	ErrAuthentication = errors.New("gateway authentication failed")
	ErrTLSProfile     = errors.New("gateway TLS profile rejected")
	ErrInjectedDrop   = errors.New("injected byte-stream drop")
)

type ByteRange struct {
	Offset int64
	Length int64
}

type Faults struct {
	FragmentSize  int
	Delay         time.Duration
	DropAfter     *int64
	Duplicate     *ByteRange
	BitFlipOffset *int64
}

type Config struct {
	GatewayAddress   string
	ServerName       string
	PinnedSPKI       []byte
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	Upstream         Faults
	Downstream       Faults
}

type Proxy struct {
	gatewayAddress   string
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	tlsConfig        *tls.Config
	upstream         Faults
	downstream       Faults
}

func validFaults(faults Faults) bool {
	if faults.FragmentSize < 0 || faults.FragmentSize > copyBufferSize || faults.Delay < 0 {
		return false
	}
	if faults.DropAfter != nil && *faults.DropAfter < 0 {
		return false
	}
	if faults.BitFlipOffset != nil && *faults.BitFlipOffset < 0 {
		return false
	}
	if faults.Duplicate != nil {
		if faults.Duplicate.Offset < 0 || faults.Duplicate.Length <= 0 ||
			faults.Duplicate.Length > copyBufferSize ||
			faults.Duplicate.Offset > int64(^uint64(0)>>1)-faults.Duplicate.Length {
			return false
		}
	}
	return true
}

func cloneFaults(faults Faults) Faults {
	cloned := faults
	if faults.DropAfter != nil {
		value := *faults.DropAfter
		cloned.DropAfter = &value
	}
	if faults.Duplicate != nil {
		value := *faults.Duplicate
		cloned.Duplicate = &value
	}
	if faults.BitFlipOffset != nil {
		value := *faults.BitFlipOffset
		cloned.BitFlipOffset = &value
	}
	return cloned
}

func New(config Config) (*Proxy, error) {
	if config.GatewayAddress == "" || config.ServerName == "" ||
		strings.IndexByte(config.ServerName, 0) >= 0 || len(config.PinnedSPKI) != sha256.Size ||
		config.DialTimeout <= 0 || config.HandshakeTimeout <= 0 ||
		!validFaults(config.Upstream) || !validFaults(config.Downstream) {
		return nil, ErrArgument
	}
	if _, _, err := net.SplitHostPort(config.GatewayAddress); err != nil {
		return nil, ErrArgument
	}
	expectedSPKI := append([]byte(nil), config.PinnedSPKI...)
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		NextProtos:         []string{"pbns/1"},
		ServerName:         config.ServerName,
		InsecureSkipVerify: true,
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return ErrAuthentication
		}
		certificate := state.PeerCertificates[0]
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok || publicKey.Curve != elliptic.P256() {
			return ErrTLSProfile
		}
		if err := certificate.VerifyHostname(config.ServerName); err != nil {
			return ErrAuthentication
		}
		digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		if !hmac.Equal(digest[:], expectedSPKI) {
			return ErrAuthentication
		}
		return nil
	}
	return &Proxy{
		gatewayAddress:   config.GatewayAddress,
		dialTimeout:      config.DialTimeout,
		handshakeTimeout: config.HandshakeTimeout,
		tlsConfig:        tlsConfig,
		upstream:         cloneFaults(config.Upstream),
		downstream:       cloneFaults(config.Downstream),
	}, nil
}

type copyDirection uint8

const (
	copyUpstream copyDirection = iota
	copyDownstream
)

type copyResult struct {
	direction copyDirection
	err       error
}

type readerOnly struct {
	io.Reader
}

func closeWrite(connection io.Writer) error {
	if halfConnection, ok := connection.(interface{ CloseWrite() error }); ok {
		return halfConnection.CloseWrite()
	}
	return nil
}

func copyStream(ctx context.Context, destination io.Writer, source io.Reader, faults Faults, direction copyDirection, results chan<- copyResult) {
	writer, err := newFaultWriterWithContext(destination, faults, ctx)
	if err == nil {
		buffer := make([]byte, copyBufferSize)
		_, err = io.CopyBuffer(writer, readerOnly{Reader: source}, buffer)
	}
	if err == nil {
		err = closeWrite(destination)
	}
	results <- copyResult{direction: direction, err: err}
}

func (proxy *Proxy) Forward(ctx context.Context, local net.Conn) error {
	if proxy == nil || ctx == nil || local == nil {
		return ErrArgument
	}
	defer local.Close()
	dialer := net.Dialer{Timeout: proxy.dialTimeout}
	dialContext, cancelDial := context.WithTimeout(ctx, proxy.dialTimeout)
	remote, err := dialer.DialContext(dialContext, "tcp", proxy.gatewayAddress)
	cancelDial()
	if err != nil {
		return fmt.Errorf("dial gateway: %w", err)
	}
	defer remote.Close()

	tlsConnection := tls.Client(remote, proxy.tlsConfig.Clone())
	handshakeContext, cancelHandshake := context.WithTimeout(ctx, proxy.handshakeTimeout)
	err = tlsConnection.HandshakeContext(handshakeContext)
	cancelHandshake()
	if err != nil {
		if errors.Is(err, ErrAuthentication) || errors.Is(err, ErrTLSProfile) {
			return err
		}
		return fmt.Errorf("gateway TLS handshake: %w", err)
	}
	state := tlsConnection.ConnectionState()
	if state.Version != tls.VersionTLS12 ||
		state.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
		state.NegotiatedProtocol != "pbns/1" {
		return ErrTLSProfile
	}

	stopClosing := make(chan struct{})
	defer close(stopClosing)
	go func() {
		select {
		case <-ctx.Done():
			_ = local.Close()
			_ = tlsConnection.Close()
		case <-stopClosing:
		}
	}()

	results := make(chan copyResult, 2)
	go copyStream(ctx, tlsConnection, local, proxy.upstream, copyUpstream, results)
	go copyStream(ctx, local, tlsConnection, proxy.downstream, copyDownstream, results)
	var firstError error
	for completed := 0; completed < 2; completed++ {
		result := <-results
		if result.err != nil && firstError == nil {
			firstError = fmt.Errorf("copy direction %d: %w", result.direction, result.err)
			_ = local.Close()
			_ = tlsConnection.Close()
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return firstError
}

func (proxy *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	if proxy == nil || ctx == nil || listener == nil {
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
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept local proxy connection: %w", err)
		}
		if err := proxy.Forward(ctx, connection); err != nil {
			return err
		}
	}
}

type faultWriter struct {
	ctx              context.Context
	destination      io.Writer
	faults           Faults
	position         int64
	duplicateEmitted bool
	scratch          [copyBufferSize]byte
	duplicate        [copyBufferSize]byte
}

func newFaultWriter(destination io.Writer, faults Faults) (*faultWriter, error) {
	return newFaultWriterWithContext(destination, faults, context.Background())
}

func newFaultWriterWithContext(destination io.Writer, faults Faults, ctx context.Context) (*faultWriter, error) {
	if destination == nil || ctx == nil || !validFaults(faults) {
		return nil, ErrArgument
	}
	if faults.FragmentSize == 0 {
		faults.FragmentSize = copyBufferSize
	}
	return &faultWriter{ctx: ctx, destination: destination, faults: cloneFaults(faults)}, nil
}

func (writer *faultWriter) writeFragments(source []byte) error {
	for offset := 0; offset < len(source); {
		amount := writer.faults.FragmentSize
		if amount > len(source)-offset {
			amount = len(source) - offset
		}
		written, err := writer.destination.Write(source[offset : offset+amount])
		if written < 0 || written > amount {
			return io.ErrShortWrite
		}
		offset += written
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		if writer.faults.Delay > 0 {
			timer := time.NewTimer(writer.faults.Delay)
			select {
			case <-timer.C:
			case <-writer.ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return writer.ctx.Err()
			}
		}
	}
	return nil
}

func (writer *faultWriter) captureDuplicate(source []byte, start int64) {
	if writer.faults.Duplicate == nil {
		return
	}
	rangeStart := writer.faults.Duplicate.Offset
	rangeEnd := rangeStart + writer.faults.Duplicate.Length
	segmentEnd := start + int64(len(source))
	overlapStart := start
	if overlapStart < rangeStart {
		overlapStart = rangeStart
	}
	overlapEnd := segmentEnd
	if overlapEnd > rangeEnd {
		overlapEnd = rangeEnd
	}
	if overlapStart >= overlapEnd {
		return
	}
	sourceOffset := overlapStart - start
	destinationOffset := overlapStart - rangeStart
	copy(
		writer.duplicate[destinationOffset:destinationOffset+overlapEnd-overlapStart],
		source[sourceOffset:sourceOffset+overlapEnd-overlapStart],
	)
}

func (writer *faultWriter) Write(source []byte) (int, error) {
	if len(source) > len(writer.scratch) {
		return 0, ErrArgument
	}
	allowed := len(source)
	if writer.faults.DropAfter != nil {
		remaining := *writer.faults.DropAfter - writer.position
		if remaining <= 0 {
			return 0, ErrInjectedDrop
		}
		if int64(allowed) > remaining {
			allowed = int(remaining)
		}
	}
	copy(writer.scratch[:allowed], source[:allowed])
	if writer.faults.BitFlipOffset != nil && *writer.faults.BitFlipOffset >= writer.position &&
		*writer.faults.BitFlipOffset < writer.position+int64(allowed) {
		writer.scratch[*writer.faults.BitFlipOffset-writer.position] ^= 0x01
	}

	consumed := 0
	for consumed < allowed {
		segmentLength := allowed - consumed
		if writer.faults.Duplicate != nil && !writer.duplicateEmitted {
			rangeEnd := writer.faults.Duplicate.Offset + writer.faults.Duplicate.Length
			if writer.position < rangeEnd && writer.position+int64(segmentLength) > rangeEnd {
				segmentLength = int(rangeEnd - writer.position)
			}
		}
		segment := writer.scratch[consumed : consumed+segmentLength]
		writer.captureDuplicate(segment, writer.position)
		if err := writer.writeFragments(segment); err != nil {
			return consumed, err
		}
		writer.position += int64(segmentLength)
		consumed += segmentLength
		if writer.faults.Duplicate != nil && !writer.duplicateEmitted &&
			writer.position == writer.faults.Duplicate.Offset+writer.faults.Duplicate.Length {
			length := int(writer.faults.Duplicate.Length)
			if err := writer.writeFragments(writer.duplicate[:length]); err != nil {
				return consumed, err
			}
			writer.duplicateEmitted = true
		}
	}
	if allowed < len(source) {
		return consumed, ErrInjectedDrop
	}
	return consumed, nil
}
