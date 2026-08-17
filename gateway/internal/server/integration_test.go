package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"pbns.local/gateway/internal/proxysim"
	"pbns.local/gateway/internal/wire"
)

func integrationSPKI(t *testing.T) []byte {
	t.Helper()
	contents, err := os.ReadFile(serverFixturePath("tls-gateway-test-cert.pem"))
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

func integrationConnectionPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
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

func TestProxySimulatorCarriesCorrelatedGatewayResponse(t *testing.T) {
	handler := HandlerFunc(func(_ context.Context, request wire.Frame, stream *Stream) error {
		return stream.Send(wire.Frame{
			Service:   request.Service,
			Type:      wire.MessageResponse,
			RequestID: request.RequestID,
			Sequence:  request.Sequence,
			Payload:   []byte("proxy-integration"),
		})
	})
	instance, err := New(validServerConfig(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	address, _, _ := startServer(t, instance)
	proxy, err := proxysim.New(proxysim.Config{
		GatewayAddress:   address,
		ServerName:       "pbns-gateway.test",
		PinnedSPKI:       integrationSPKI(t),
		DialTimeout:      time.Second,
		HandshakeTimeout: time.Second,
		Upstream:         proxysim.Faults{FragmentSize: 7},
		Downstream:       proxysim.Faults{FragmentSize: 11},
	})
	if err != nil {
		t.Fatal(err)
	}
	applicationConnection, proxyConnection := integrationConnectionPair(t)
	defer applicationConnection.Close()
	forwardResult := make(chan error, 1)
	go func() {
		forwardResult <- proxy.Forward(context.Background(), proxyConnection)
	}()

	encoded, err := wire.Encode(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applicationConnection.Write(encoded); err != nil {
		t.Fatal(err)
	}
	response := readFrame(t, applicationConnection)
	if response.Type != wire.MessageResponse || string(response.Payload) != "proxy-integration" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if err := applicationConnection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, applicationConnection)
	select {
	case err := <-forwardResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("proxy did not stop")
	}
}
