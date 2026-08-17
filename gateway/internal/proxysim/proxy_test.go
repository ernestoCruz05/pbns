package proxysim

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const testServerName = "pbns-gateway.test"

func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "tests", "fixtures", "keys", name)
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(
		fixturePath("tls-gateway-test-cert.pem"),
		fixturePath("tls-gateway-test-key.pem"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func testSPKI(t *testing.T) []byte {
	t.Helper()
	contents, err := os.ReadFile(fixturePath("tls-gateway-test-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatal("certificate PEM did not decode")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return append([]byte(nil), digest[:]...)
}

type echoResult struct {
	capture []byte
	err     error
}

func startEchoServer(t *testing.T) (string, <-chan echoResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan echoResult, 1)
	certificate := testCertificate(t)
	go func() {
		defer close(result)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- echoResult{err: acceptErr}
			return
		}
		defer connection.Close()
		tlsConnection := tls.Server(connection, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			NextProtos:   []string{"pbns/1"},
		})
		if handshakeErr := tlsConnection.Handshake(); handshakeErr != nil {
			result <- echoResult{err: handshakeErr}
			return
		}
		capture, readErr := io.ReadAll(tlsConnection)
		if readErr == nil {
			_, readErr = tlsConnection.Write(capture)
		}
		if closeWriter, ok := any(tlsConnection).(interface{ CloseWrite() error }); ok {
			if closeErr := closeWriter.CloseWrite(); readErr == nil {
				readErr = closeErr
			}
		}
		result <- echoResult{capture: capture, err: readErr}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String(), result
}

func localConnectionPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptError <- acceptErr
			return
		}
		accepted <- connection.(*net.TCPConn)
	}()
	applicationConnection, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case proxyConnection := <-accepted:
		return applicationConnection, proxyConnection
	case err := <-acceptError:
		_ = applicationConnection.Close()
		t.Fatal(err)
	case <-time.After(time.Second):
		_ = applicationConnection.Close()
		t.Fatal("local connection accept timed out")
	}
	return nil, nil
}

func testConfig(t *testing.T, address string) Config {
	t.Helper()
	return Config{
		GatewayAddress:   address,
		ServerName:       testServerName,
		PinnedSPKI:       testSPKI(t),
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
		Upstream:         Faults{FragmentSize: 37},
		Downstream:       Faults{FragmentSize: 37},
	}
}

func writeVaryingFragments(writer io.Writer, payload []byte) error {
	for offset, fragment := 0, 1; offset < len(payload); fragment = fragment%37 + 1 {
		amount := fragment
		if amount > len(payload)-offset {
			amount = len(payload) - offset
		}
		written, err := writer.Write(payload[offset : offset+amount])
		if err != nil {
			return err
		}
		if written != amount {
			return io.ErrShortWrite
		}
		offset += amount
	}
	return nil
}

func TestProxyPreservesOneMiBInBothDirections(t *testing.T) {
	payload := make([]byte, 1<<20)
	for index := range payload {
		payload[index] = byte(index)
	}
	address, serverResult := startEchoServer(t)
	proxy, err := New(testConfig(t, address))
	if err != nil {
		t.Fatal(err)
	}
	applicationConnection, proxyConnection := localConnectionPair(t)
	defer applicationConnection.Close()
	forwardResult := make(chan error, 1)
	go func() {
		forwardResult <- proxy.Forward(context.Background(), proxyConnection)
	}()

	if err := writeVaryingFragments(applicationConnection, payload); err != nil {
		proxyErr := <-forwardResult
		server := <-serverResult
		t.Fatalf("application write: %v; proxy: %v; server: %v", err, proxyErr, server.err)
	}
	if err := applicationConnection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	echoed, err := io.ReadAll(applicationConnection)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("reverse direction mismatch: got %d bytes", len(echoed))
	}
	select {
	case err := <-forwardResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not stop")
	}
	result := <-serverResult
	if result.err != nil {
		t.Fatal(result.err)
	}
	if !bytes.Equal(result.capture, payload) {
		t.Fatalf("upstream mismatch: got %d bytes", len(result.capture))
	}
}

type readCountingConnection struct {
	net.Conn
	readCalls atomic.Int64
}

func (connection *readCountingConnection) Read(destination []byte) (int, error) {
	connection.readCalls.Add(1)
	return connection.Conn.Read(destination)
}

func TestWrongSPKIFailsBeforeReadingApplicationBytes(t *testing.T) {
	address, serverResult := startEchoServer(t)
	config := testConfig(t, address)
	config.PinnedSPKI[0] ^= 0xff
	proxy, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	applicationConnection, rawProxyConnection := localConnectionPair(t)
	defer applicationConnection.Close()
	counted := &readCountingConnection{Conn: rawProxyConnection}
	if _, err := applicationConnection.Write([]byte("must-not-cross-pin-check")); err != nil {
		t.Fatal(err)
	}

	err = proxy.Forward(context.Background(), counted)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("got %v, want authentication error", err)
	}
	if counted.readCalls.Load() != 0 {
		t.Fatalf("application read occurred before pin validation: %d", counted.readCalls.Load())
	}
	_ = applicationConnection.Close()
	result := <-serverResult
	if result.err == nil {
		t.Fatal("TLS server unexpectedly accepted wrong-pin session")
	}
}

type recordingWriter struct {
	bytes.Buffer
	writeSizes []int
}

func (writer *recordingWriter) Write(source []byte) (int, error) {
	writer.writeSizes = append(writer.writeSizes, len(source))
	return writer.Buffer.Write(source)
}

func int64Pointer(value int64) *int64 {
	return &value
}

func TestFaultWriterAppliesByteOffsetFaultsWithoutParsing(t *testing.T) {
	t.Run("bit-flip-and-fragment", func(t *testing.T) {
		destination := &recordingWriter{}
		writer, err := newFaultWriter(destination, Faults{
			FragmentSize:  3,
			BitFlipOffset: int64Pointer(4),
		})
		if err != nil {
			t.Fatal(err)
		}
		input := []byte{0x00, 0x50, 0x42, 0x4e, 0x53, 0xff, 0x00}
		if written, err := writer.Write(input); err != nil || written != len(input) {
			t.Fatalf("Write = %d, %v", written, err)
		}
		expected := append([]byte(nil), input...)
		expected[4] ^= 0x01
		if !bytes.Equal(destination.Bytes(), expected) {
			t.Fatalf("got %x, want %x", destination.Bytes(), expected)
		}
		for _, size := range destination.writeSizes {
			if size > 3 {
				t.Fatalf("fragment exceeded limit: %d", size)
			}
		}
	})

	t.Run("duplicate-range", func(t *testing.T) {
		destination := &recordingWriter{}
		writer, err := newFaultWriter(destination, Faults{
			Duplicate: &ByteRange{Offset: 2, Length: 3},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range [][]byte{[]byte("ab"), []byte("cd"), []byte("efgh")} {
			if _, err := writer.Write(fragment); err != nil {
				t.Fatal(err)
			}
		}
		if got, want := destination.String(), "abcdecdefgh"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})

	t.Run("drop-after-byte", func(t *testing.T) {
		destination := &recordingWriter{}
		writer, err := newFaultWriter(destination, Faults{DropAfter: int64Pointer(4)})
		if err != nil {
			t.Fatal(err)
		}
		written, err := writer.Write([]byte("abcdefgh"))
		if written != 4 || !errors.Is(err, ErrInjectedDrop) {
			t.Fatalf("Write = %d, %v", written, err)
		}
		if destination.String() != "abcd" {
			t.Fatalf("unexpected prefix %q", destination.String())
		}
	})
}

type signalingWriter struct {
	wrote chan struct{}
}

func (writer *signalingWriter) Write(source []byte) (int, error) {
	select {
	case writer.wrote <- struct{}{}:
	default:
	}
	return len(source), nil
}

func TestFaultDelayHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	destination := &signalingWriter{wrote: make(chan struct{}, 1)}
	writer, err := newFaultWriterWithContext(destination, Faults{
		FragmentSize: 1,
		Delay:        time.Hour,
	}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write([]byte("x"))
		result <- writeErr
	}()
	select {
	case <-destination.wrote:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("fault writer did not reach delayed fragment")
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fault delay ignored context cancellation")
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	address, _ := startEchoServer(t)
	valid := testConfig(t, address)
	tests := map[string]Config{
		"empty-address":      func() Config { value := valid; value.GatewayAddress = ""; return value }(),
		"empty-server-name":  func() Config { value := valid; value.ServerName = ""; return value }(),
		"short-pin":          func() Config { value := valid; value.PinnedSPKI = make([]byte, 31); return value }(),
		"zero-dial-timeout":  func() Config { value := valid; value.DialTimeout = 0; return value }(),
		"oversized-fragment": func() Config { value := valid; value.Upstream.FragmentSize = copyBufferSize + 1; return value }(),
		"negative-delay":     func() Config { value := valid; value.Upstream.Delay = -1; return value }(),
		"negative-drop":      func() Config { value := valid; value.Upstream.DropAfter = int64Pointer(-1); return value }(),
		"empty-duplicate":    func() Config { value := valid; value.Upstream.Duplicate = &ByteRange{}; return value }(),
		"large-duplicate": func() Config {
			value := valid
			value.Upstream.Duplicate = &ByteRange{Offset: 0, Length: copyBufferSize + 1}
			return value
		}(),
		"negative-bit-offset": func() Config { value := valid; value.Upstream.BitFlipOffset = int64Pointer(-1); return value }(),
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := New(config); !errors.Is(err, ErrArgument) {
				t.Fatalf("got %v, want argument error", err)
			}
		})
	}
}
