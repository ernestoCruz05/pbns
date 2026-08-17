package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/proxysim"
	"pbns.local/gateway/internal/recovery"
	. "pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/store"
	timeservice "pbns.local/gateway/internal/time"
	"pbns.local/gateway/internal/wire"
)

const recoveryIntegrationTimeout = 3 * time.Second

type recoveryLiveFixture struct {
	repositoryRoot   string
	artifact         recovery.Artifact
	artifactBytes    []byte
	policyAuth       []byte
	hostKey          *ecdsa.PrivateKey
	hostFingerprint  [32]byte
	manifestKeyID    []byte
	policyKeyID      []byte
	manifestVerifier cose.Verifier
	service          *recovery.Service
	server           *Server
	listener         net.Listener
	serverCancel     context.CancelFunc
	serverDone       <-chan error
	gatewayAddress   string
	pinnedSPKI       []byte
	store            *store.Store
	sensitive        [][]byte
}

type recoveryLiveReader struct {
	reader  *bufio.Reader
	decoder *wire.Decoder
}

func TestRecoveryEndToEnd(t *testing.T) {
	var capturedLogs bytes.Buffer
	previousLogWriter := log.Writer()
	log.SetOutput(&capturedLogs)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })
	rootTest := t
	fixtures := make([]*recoveryLiveFixture, 0, 2)
	newFixture := func() *recoveryLiveFixture {
		fixture := newRecoveryLiveFixture(rootTest)
		fixtures = append(fixtures, fixture)
		return fixture
	}
	fixture := newFixture()
	t.Run("authenticated-manifest-and-artifact-through-proxy", func(t *testing.T) {
		manifestRequest := fixture.request(t, recovery.OperationManifest, [32]byte{}, 1)
		manifestConnection, manifestReader, manifestProxyDone := fixture.proxyConnection(t)
		writeLiveFrame(t, manifestConnection, fixture.signedFrame(t, manifestRequest, fixture.hostKey))
		manifestResponse := manifestReader.next(t, manifestConnection)
		if manifestResponse.Type != wire.MessageResponse || manifestResponse.Sequence != 0 ||
			manifestResponse.RequestID != wire.RequestID(manifestRequest.RequestID) {
			t.Fatal("manifest response did not preserve the authenticated correlation")
		}
		manifest, err := recovery.VerifyManifest(manifestResponse.Payload, fixture.manifestVerifier,
			recovery.Expectation{
				RequestID: manifestRequest.RequestID, HostBinding: manifestRequest.HostFingerprint,
				Nonce: manifestRequest.Nonce, RecoverySigningKeyID: fixture.manifestKeyID,
				ExpectedPolicyKeyID: fixture.policyKeyID, CurrentVersion: 0,
				TrustedEarliestNS: time.Now().Add(-time.Minute).UnixNano(),
				TrustedLatestNS:   time.Now().Add(time.Minute).UnixNano(),
			})
		if err != nil {
			t.Fatalf("dynamic manifest failed pinned Sign1/AAD/binding/time verification: %v", err)
		}
		if manifest.ArtifactDigest != fixture.artifact.Digest || manifest.ImageSize != fixture.artifact.Size ||
			manifest.ArtifactVersion != 7 || manifest.MinimumVersion != 6 ||
			manifest.ChunkSize != wire.DataPayloadMax || manifest.Architecture != recovery.ArchitectureX8664 ||
			manifest.Format != recovery.FormatUKIPECOFF || !bytes.Equal(manifest.PolicyAuthorization, fixture.policyAuth) ||
			!bytes.Equal(manifest.PolicyKeyID, fixture.policyKeyID) {
			t.Fatal("manifest publication/profile binding changed")
		}
		signedManifest := append([]byte(nil), manifestResponse.Payload...)
		freshManifestRequest := fixture.request(t, recovery.OperationManifest, [32]byte{}, 9)
		if freshManifestRequest.RequestID == manifestRequest.RequestID || freshManifestRequest.Nonce == manifestRequest.Nonce {
			t.Fatal("fresh manifest replay expectations were not distinct")
		}
		for _, replay := range []struct {
			requestID [16]byte
			nonce     [32]byte
		}{
			{freshManifestRequest.RequestID, manifestRequest.Nonce},
			{manifestRequest.RequestID, freshManifestRequest.Nonce},
			{freshManifestRequest.RequestID, freshManifestRequest.Nonce},
		} {
			if _, err := recovery.VerifyManifest(signedManifest, fixture.manifestVerifier, recovery.Expectation{
				RequestID: replay.requestID, HostBinding: freshManifestRequest.HostFingerprint,
				Nonce: replay.nonce, RecoverySigningKeyID: fixture.manifestKeyID,
				ExpectedPolicyKeyID: fixture.policyKeyID, CurrentVersion: 0,
				TrustedEarliestNS: time.Now().Add(-time.Minute).UnixNano(),
				TrustedLatestNS:   time.Now().Add(time.Minute).UnixNano(),
			}); err == nil {
				t.Fatal("old manifest replay was accepted")
			}
		}
		closeLiveConnection(t, manifestConnection, manifestProxyDone)

		artifactRequest := fixture.request(t, recovery.OperationArtifact, manifest.ArtifactDigest, 2)
		artifactConnection, artifactReader, artifactProxyDone := fixture.proxyConnection(t)
		writeLiveFrame(t, artifactConnection, fixture.signedFrame(t, artifactRequest, fixture.hostKey))
		received := make([]byte, 0, len(fixture.artifactBytes))
		var dataSequence, ackSequence uint32
		for {
			frame := artifactReader.next(t, artifactConnection)
			switch frame.Type {
			case wire.MessageData:
				if frame.RequestID != wire.RequestID(artifactRequest.RequestID) || frame.Sequence != dataSequence ||
					dataSequence > 16 || len(frame.Payload) == 0 || len(frame.Payload) > wire.DataPayloadMax ||
					(dataSequence < 16 && len(frame.Payload) != wire.DataPayloadMax) ||
					(dataSequence == 16 && len(frame.Payload) != 373) {
					t.Fatal("artifact DATA did not follow the exact 16KiB chunk profile")
				}
				received = append(received, frame.Payload...)
				dataSequence++
				if dataSequence%recovery.ACKWindow == 0 {
					if (dataSequence == 8 && ackSequence != 0) || (dataSequence == 16 && ackSequence != 1) {
						t.Fatal("artifact ACK sequence did not independently start at zero")
					}
					ack := recovery.ACKFrame(wire.RequestID(artifactRequest.RequestID), ackSequence, dataSequence)
					if ack.Sequence != ackSequence || binary.BigEndian.Uint32(ack.Payload[:4]) != dataSequence ||
						binary.BigEndian.Uint32(ack.Payload[4:]) != recovery.ACKWindow {
						t.Fatal("artifact ACK did not carry the exact next sequence/window")
					}
					writeLiveFrame(t, artifactConnection, ack)
					ackSequence++
				}
			case wire.MessageComplete:
				if frame.RequestID != wire.RequestID(artifactRequest.RequestID) || frame.Sequence != 17 ||
					dataSequence != 17 || len(frame.Payload) != 0 || ackSequence != 2 {
					t.Fatal("artifact COMPLETE did not follow DATA/ACK counters")
				}
				wantDigest := sha256.Sum256(fixture.artifactBytes)
				gotDigest := sha256.Sum256(received)
				if !bytes.Equal(received, fixture.artifactBytes) || gotDigest != wantDigest {
					t.Fatal("artifact bytes or final SHA-256 changed in transit")
				}
				closeLiveConnection(t, artifactConnection, artifactProxyDone)
				return
			default:
				t.Fatal("artifact operation returned a non-stream frame")
			}
		}
	})

	t.Run("request-authentication-and-correlation-reject-substitution", func(t *testing.T) {
		unknown, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		wrongSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		fixture.sensitive = append(fixture.sensitive, p256Scalar(unknown), p256Scalar(wrongSigner))
		for name, test := range map[string]struct {
			request recovery.Request
			signer  *ecdsa.PrivateKey
			mutate  func(*wire.Frame)
		}{
			"unknown-host":                     {fixture.request(t, recovery.OperationManifest, [32]byte{}, 3), unknown, nil},
			"bad-signature":                    {fixture.request(t, recovery.OperationManifest, [32]byte{}, 4), wrongSigner, nil},
			"digest-substitution":              {fixture.request(t, recovery.OperationArtifact, changedDigest(fixture.artifact.Digest), 5), fixture.hostKey, nil},
			"request-correlation-substitution": {fixture.request(t, recovery.OperationManifest, [32]byte{}, 6), fixture.hostKey, func(frame *wire.Frame) { frame.RequestID[0] ^= 1 }},
		} {
			t.Run(name, func(t *testing.T) {
				connection, reader, proxyDone := fixture.proxyConnection(t)
				frame := fixture.signedFrame(t, test.request, test.signer)
				if name == "unknown-host" {
					frame = fixture.signedFrame(t, test.request, fixture.hostKey)
					frame.Payload = fixture.signedRequest(t, requestWithFingerprint(test.request, fingerprintForKey(t, unknown)), unknown)
				}
				if test.mutate != nil {
					test.mutate(&frame)
				}
				writeCoalescedLiveFrames(t, connection, frame, frame)
				for range 2 {
					requireLiveError(t, reader, connection, frame.RequestID, 0)
				}
				closeLiveConnection(t, connection, proxyDone)
			})
		}
	})

	t.Run("request-frame-replay-with-fresh-header-id-is-rejected", func(t *testing.T) {
		original := fixture.request(t, recovery.OperationManifest, [32]byte{}, 7)
		replayed := fixture.signedFrame(t, original, fixture.hostKey)
		fresh := fixture.request(t, recovery.OperationManifest, [32]byte{}, 8)
		replayed.RequestID = wire.RequestID(fresh.RequestID)
		connection, reader, proxyDone := fixture.proxyConnection(t)
		writeLiveFrame(t, connection, replayed)
		requireLiveError(t, reader, connection, replayed.RequestID, 0)
		closeLiveConnection(t, connection, proxyDone)
	})

	t.Run("ack-cancel-and-reconnect-fail-closed", func(t *testing.T) {
		for name, mutate := range map[string]func(*wire.Frame){
			"ack-request":  func(frame *wire.Frame) { frame.RequestID[0] ^= 1 },
			"ack-sequence": func(frame *wire.Frame) { frame.Sequence++ },
			"ack-next":     func(frame *wire.Frame) { frame.Payload[3] ^= 1 },
			"ack-window":   func(frame *wire.Frame) { frame.Payload[7] ^= 1 },
		} {
			t.Run(name, func(t *testing.T) {
				request := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, byte(20+len(name)))
				connection, reader, proxyDone := fixture.proxyConnection(t)
				writeLiveFrame(t, connection, fixture.signedFrame(t, request, fixture.hostKey))
				for sequence := uint32(0); sequence < recovery.ACKWindow; sequence++ {
					frame := reader.next(t, connection)
					if frame.Type != wire.MessageData || frame.Sequence != sequence {
						t.Fatal("ACK substitution setup did not receive the exact data window")
					}
				}
				ack := recovery.ACKFrame(wire.RequestID(request.RequestID), 0, recovery.ACKWindow)
				mutate(&ack)
				writeLiveFrame(t, connection, ack)
				requireLiveError(t, reader, connection, wire.RequestID(request.RequestID), recovery.ACKWindow)
				closeLiveConnection(t, connection, proxyDone)
			})
		}

		cancelRequest := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, 30)
		connection, reader, proxyDone := fixture.proxyConnection(t)
		writeLiveFrame(t, connection, fixture.signedFrame(t, cancelRequest, fixture.hostKey))
		first := reader.next(t, connection)
		if first.Type != wire.MessageData || first.Sequence != 0 {
			t.Fatal("cancel setup did not receive DATA sequence zero")
		}
		writeLiveFrame(t, connection, wire.Frame{Service: wire.ServiceRecoveryArtifact,
			Type: wire.MessageCancel, RequestID: wire.RequestID(cancelRequest.RequestID)})
		for {
			response := reader.next(t, connection)
			if response.Type == wire.MessageError {
				if response.RequestID != wire.RequestID(cancelRequest.RequestID) || response.Sequence != recovery.ACKWindow {
					t.Fatal("cancel rejection did not preserve error correlation")
				}
				break
			}
			if response.Type != wire.MessageData {
				t.Fatal("cancel returned an unexpected stream frame")
			}
		}
		closeLiveConnection(t, connection, proxyDone)

		restart := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, 31)
		restartConnection, restartReader, restartProxyDone := fixture.proxyConnection(t)
		writeLiveFrame(t, restartConnection, fixture.signedFrame(t, restart, fixture.hostKey))
		if first = restartReader.next(t, restartConnection); first.Type != wire.MessageData || first.Sequence != 0 {
			t.Fatal("reconnect did not restart DATA sequence at zero")
		}
		closeLiveConnection(t, restartConnection, restartProxyDone)
	})

	t.Run("gateway-stop-and-repository-mutation-close-the-wire", func(t *testing.T) {
		request := fixture.request(t, recovery.OperationManifest, [32]byte{}, 40)
		connection, reader, proxyDone := fixture.proxyConnection(t)
		writeLiveFrame(t, connection, fixture.signedFrame(t, request, fixture.hostKey))
		fixture.serverCancel()
		_ = connection.SetReadDeadline(time.Now().Add(recoveryIntegrationTimeout))
		if _, err := reader.reader.ReadByte(); err == nil {
			t.Fatal("gateway stop left the proxied TLS connection usable")
		}
		closeLiveConnection(t, connection, proxyDone)

		// A separate live server retains the same immutable publication only long
		// enough to prove preflight detects a local repository mutation.
		mutatedFixture := newFixture()
		artifactPath := filepath.Join(mutatedFixture.repositoryRoot, "artifacts", hex.EncodeToString(mutatedFixture.artifact.Digest[:]))
		if err := os.Chmod(artifactPath, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(artifactPath, bytes.Repeat([]byte{0x5a}, len(mutatedFixture.artifactBytes)), 0o600); err != nil {
			t.Fatal(err)
		}
		mutated := mutatedFixture.request(t, recovery.OperationManifest, [32]byte{}, 41)
		connection, reader, proxyDone = mutatedFixture.proxyConnection(t)
		writeLiveFrame(t, connection, mutatedFixture.signedFrame(t, mutated, mutatedFixture.hostKey))
		requireLiveError(t, reader, connection, wire.RequestID(mutated.RequestID), 0)
		closeLiveConnection(t, connection, proxyDone)
	})

	t.Run("inventory-and-log-audit", func(t *testing.T) {
		logs := capturedLogs.Bytes()
		for _, current := range fixtures {
			hosts, err := current.store.ListHosts()
			if err != nil || len(hosts) != 1 {
				t.Fatal("gateway inventory was not available for secret audit")
			}
			inventory := []byte(hosts[0].String())
			for _, sensitive := range current.sensitive {
				for _, representation := range liveSensitiveRepresentations(sensitive) {
					if bytes.Contains(inventory, representation) || bytes.Contains(logs, representation) {
						t.Fatal("gateway inventory or logs exposed sensitive recovery material")
					}
				}
			}
		}
	})
}

func newRecoveryLiveFixture(t *testing.T) *recoveryLiveFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	certificatePath := copyLiveFixture(t, directory, "tls-cert.pem", liveServerFixturePath("tls-gateway-test-cert.pem"), 0o600)
	keyPath := copyLiveFixture(t, directory, "tls-key.pem", liveServerFixturePath("tls-gateway-test-key.pem"), 0o600)
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTLSPrivatePEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certificateDER := certificate.Certificate[0]
	parsedCertificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	spki := sha256.Sum256(parsedCertificate.RawSubjectPublicKeyInfo)

	hostKey := generateLiveKey(t)
	identity := encodeLiveIdentity(t, &hostKey.PublicKey)
	fingerprint := sha256.Sum256(identity)
	database, err := store.Open(filepath.Join(directory, "enrollment.db"), store.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transcript := sha256.Sum256([]byte("recovery-live-enrollment"))
	pending, err := database.BeginEnrollment(issued.Plaintext, transcript)
	if err != nil {
		t.Fatal(err)
	}
	baseline := sha256.Sum256([]byte("recovery-live-baseline"))
	if err := database.CompleteEnrollment(pending.ID, model.HostRecord{
		Fingerprint: fingerprint, IdentityCOSEKey: identity, Assurance: model.AssuranceSoftware,
		BaselineID: baseline, EnrolledAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	repositoryRoot := filepath.Join(directory, "repository")
	repository, err := recovery.OpenRepository(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes := bytes.Repeat([]byte("PBNS-recovery-live-artifact/"), (16*wire.DataPayloadMax+373)/28+1)
	artifactBytes = artifactBytes[:16*wire.DataPayloadMax+373]
	artifactSource := filepath.Join(directory, "recovery.efi")
	if err := os.WriteFile(artifactSource, artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := repository.Publish(artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	manifestKey := generateLiveKey(t)
	policyKey := generateLiveKey(t)
	secureBootKey := generateLiveKey(t)
	manifestKeyID := []byte("recovery-live-manifest")
	policyKeyID := []byte("recovery-live-policy")
	manifestSigner, err := keys.NewPinnedOnlineSigner(keys.RoleRecoveryManifest, manifestKeyID, manifestKey)
	if err != nil {
		t.Fatal(err)
	}
	policyAuth, err := recovery.CreateVersionAuthorization(policyKey, recovery.RecoveryNVIndex, 7)
	if err != nil {
		t.Fatal(err)
	}
	service, err := recovery.NewService(recovery.ServiceConfig{
		Repository: repository, ArtifactDigest: artifact.Digest, TargetVersion: 7, MinimumVersion: 6,
		PolicyAuthorization: policyAuth, PolicyKeyID: policyKeyID, PolicyPublicKey: &policyKey.PublicKey,
		ManifestSigner: manifestSigner, SecureBootImageKey: &secureBootKey.PublicKey,
		Hosts: timeservice.StoreHostResolver{Store: database}, Clock: time.Now,
		ValidityLead: 2 * time.Minute, ValidityTrailing: 2 * time.Minute, TransferTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestVerifier, err := cose.NewVerifier(cose.AlgorithmES256, &manifestKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{
		TLS: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, NextProtos: []string{"pbns/1"}},
		Handlers: map[wire.ServiceID]Handler{wire.ServiceRecoveryArtifact: service}, Limits: wire.DefaultLimits(),
		HandshakeTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxConnections: 8,
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
	fixture := &recoveryLiveFixture{repositoryRoot: repositoryRoot, artifact: artifact, artifactBytes: artifactBytes,
		policyAuth: policyAuth, hostKey: hostKey, hostFingerprint: fingerprint, manifestKeyID: manifestKeyID,
		policyKeyID: policyKeyID, manifestVerifier: manifestVerifier, service: service, server: instance,
		listener: listener, serverCancel: cancel, serverDone: done, gatewayAddress: listener.Addr().String(),
		pinnedSPKI: spki[:], store: database,
		sensitive: cloneLiveSensitive(artifactBytes, policyAuth, []byte(issued.Plaintext), issued.Digest[:],
			transcript[:], runtimeTLSPrivatePEM, p256Scalar(hostKey), p256Scalar(manifestKey),
			p256Scalar(policyKey), p256Scalar(secureBootKey)),
	}
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("recovery TLS server: %v", err)
			}
		case <-time.After(recoveryIntegrationTimeout):
			t.Error("recovery TLS server did not stop")
		}
	})
	return fixture
}

func (fixture *recoveryLiveFixture) proxyConnection(t *testing.T) (net.Conn, *recoveryLiveReader, <-chan error) {
	t.Helper()
	proxy, err := proxysim.New(proxysim.Config{GatewayAddress: fixture.gatewayAddress, ServerName: "pbns-gateway.test",
		PinnedSPKI: fixture.pinnedSPKI, DialTimeout: time.Second, HandshakeTimeout: time.Second,
		Upstream: proxysim.Faults{FragmentSize: 7}, Downstream: proxysim.Faults{FragmentSize: 11}})
	if err != nil {
		t.Fatal(err)
	}
	client, proxySide := liveConnectionPair(t)
	done := make(chan error, 1)
	go func() { done <- proxy.Forward(context.Background(), proxySide) }()
	decoder, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return client, &recoveryLiveReader{reader: bufio.NewReaderSize(client, wire.WireMax), decoder: decoder}, done
}

func (fixture *recoveryLiveFixture) request(t *testing.T, operation recovery.Operation, digest [32]byte, salt byte) recovery.Request {
	t.Helper()
	request := recovery.Request{Domain: recovery.RequestDomain, Version: recovery.RequestVersion,
		Service: recovery.ServiceRecoveryArtifact, Operation: operation, HostFingerprint: fixture.hostFingerprint,
		ArtifactDigest: digest}
	for index := range request.RequestID {
		request.RequestID[index] = byte(index+1) ^ salt
	}
	for index := range request.Nonce {
		request.Nonce[index] = byte(index+0x41) ^ salt
	}
	fixture.sensitive = append(fixture.sensitive, append([]byte(nil), request.Nonce[:]...))
	return request
}

func (fixture *recoveryLiveFixture) signedRequest(t *testing.T, request recovery.Request, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := recovery.SignRequest(request, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func (fixture *recoveryLiveFixture) signedFrame(t *testing.T, request recovery.Request, key *ecdsa.PrivateKey) wire.Frame {
	t.Helper()
	return wire.Frame{Service: wire.ServiceRecoveryArtifact, Type: wire.MessageRequest,
		RequestID: wire.RequestID(request.RequestID), Payload: fixture.signedRequest(t, request, key)}
}

func p256Scalar(key *ecdsa.PrivateKey) []byte {
	if key == nil || key.D == nil {
		return nil
	}
	return key.D.FillBytes(make([]byte, 32))
}

func cloneLiveSensitive(values ...[]byte) [][]byte {
	clones := make([][]byte, 0, len(values))
	for _, value := range values {
		clones = append(clones, append([]byte(nil), value...))
	}
	return clones
}

func liveSensitiveRepresentations(value []byte) [][]byte {
	if len(value) == 0 {
		return nil
	}
	lowerHex := hex.EncodeToString(value)
	upperHex := strings.ToUpper(lowerHex)
	return [][]byte{
		value,
		[]byte(lowerHex),
		[]byte(upperHex),
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.URLEncoding.EncodeToString(value)),
		[]byte(base64.RawURLEncoding.EncodeToString(value)),
		[]byte(fmt.Sprint(value)),
	}
}

func requireLiveError(t *testing.T, reader *recoveryLiveReader, connection net.Conn,
	requestID wire.RequestID, sequence uint32) {
	t.Helper()
	response := reader.next(t, connection)
	if response.Type != wire.MessageError || response.RequestID != requestID || response.Sequence != sequence {
		t.Fatal("recovery rejection did not preserve error correlation")
	}
}

func (reader *recoveryLiveReader) next(t *testing.T, connection net.Conn) wire.Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(recoveryIntegrationTimeout)); err != nil {
		t.Fatal(err)
	}
	record, err := reader.reader.ReadBytes(0)
	if err != nil {
		t.Fatal("proxied TLS recovery response was not received")
	}
	frame, err := reader.decoder.Decode(record)
	if err != nil {
		t.Fatal("proxied recovery frame was not canonical")
	}
	return frame
}

func writeLiveFrame(t *testing.T, connection net.Conn, frame wire.Frame) {
	t.Helper()
	encoded, err := wire.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	for offset, size := 0, 1; offset < len(encoded); size = size%13 + 1 {
		end := offset + size
		if end > len(encoded) {
			end = len(encoded)
		}
		if written, err := connection.Write(encoded[offset:end]); err != nil || written != end-offset {
			t.Fatal("fragmented application write to proxy failed")
		}
		offset = end
	}
}

// writeCoalescedLiveFrames deliberately emits complete adjacent records in one
// TCP write; proxysim then deterministically splits that opaque byte stream.
func writeCoalescedLiveFrames(t *testing.T, connection net.Conn, frames ...wire.Frame) {
	t.Helper()
	var joined []byte
	for _, frame := range frames {
		encoded, err := wire.Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		joined = append(joined, encoded...)
	}
	if written, err := connection.Write(joined); err != nil || written != len(joined) {
		t.Fatal("coalesced application write to proxy failed")
	}
}

func closeLiveConnection(t *testing.T, connection net.Conn, proxyDone <-chan error) {
	t.Helper()
	_ = connection.Close()
	select {
	case <-proxyDone:
		// A client close may race either copy direction. The result is consumed
		// solely to prove bounded proxy cleanup; application semantics were
		// already asserted before this close.
	case <-time.After(recoveryIntegrationTimeout):
		t.Fatal("proxy did not stop")
	}
}

func liveConnectionPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- connection.(*net.TCPConn)
		}
	}()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case proxySide := <-accepted:
		return client, proxySide
	case <-time.After(recoveryIntegrationTimeout):
		_ = client.Close()
		t.Fatal("proxy-side local socket was not accepted")
	}
	return nil, nil
}

func generateLiveKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func encodeLiveIdentity(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	mode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mode.Marshal(map[int64]any{1: int64(2), -1: int64(1),
		-2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func fingerprintForKey(t *testing.T, key *ecdsa.PrivateKey) [32]byte {
	t.Helper()
	return sha256.Sum256(encodeLiveIdentity(t, &key.PublicKey))
}

func requestWithFingerprint(request recovery.Request, fingerprint [32]byte) recovery.Request {
	request.HostFingerprint = fingerprint
	return request
}

func changedDigest(digest [32]byte) [32]byte {
	digest[0] ^= 1
	return digest
}

func liveServerFixturePath(name string) string {
	return filepath.Join("..", "..", "..", "tests", "fixtures", "keys", name)
}

func copyLiveFixture(t *testing.T, directory, name, source string, mode os.FileMode) string {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
