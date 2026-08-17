package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veraison/go-cose"

	"pbns.local/gateway/internal/config"
	"pbns.local/gateway/internal/evalevidence"
	"pbns.local/gateway/internal/gatewayapp"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/model"
	"pbns.local/gateway/internal/proxysim"
	"pbns.local/gateway/internal/recovery"
	. "pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/store"
	"pbns.local/gateway/internal/wire"
)

// TestRecoveryEvaluationEndToEnd keeps the closed evaluation faults on the
// production configured-handler/TCP/TLS path. It deliberately does not call a
// handler directly: requests cross the proxy's pinned TLS connection.
func TestRecoveryEvaluationEndToEnd(t *testing.T) {
	var capturedLogs bytes.Buffer
	previousLogWriter := log.Writer()
	log.SetOutput(&capturedLogs)
	t.Cleanup(func() { log.SetOutput(previousLogWriter) })
	fixture := newRecoveryEvaluationFixture(t)
	eventPaths := make([]string, 0, 4)

	t.Run("production-options-remain-the-exact-baseline", func(t *testing.T) {
		runtime := fixture.start(t, gatewayapp.Options{}, nil)
		defer runtime.stop(t)
		connection, reader, stopProxy := fixture.proxyConnection(t, runtime.address)
		request := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, 1)
		writeEvaluationFrame(t, connection, fixture.signedFrame(t, request))
		frames := readEvaluationArtifact(t, reader, connection, request)
		if got, want := encodeEvaluationFrames(t, frames), fixture.goldenArtifact(t, request); !bytes.Equal(got, want) {
			t.Fatal("gatewayapp.Options{} changed the production artifact bytes or sequence profile")
		}
		stopProxy()
	})

	t.Run("digest-mismatch-reaches-canonical-artifact-wire", func(t *testing.T) {
		events := fixture.eventPath(t, "digest")
		eventPaths = append(eventPaths, events)
		options, sink, _ := fixture.evaluationOptions(t, events, recovery.EvaluationFaultArtifactDigestMismatch)
		runtime := fixture.start(t, options, sink)
		connection, reader, stopProxy := fixture.proxyConnection(t, runtime.address)
		manifestRequest := fixture.request(t, recovery.OperationManifest, [32]byte{}, 2)
		writeEvaluationFrame(t, connection, fixture.signedFrame(t, manifestRequest))
		manifestFrame := reader.next(t, connection)
		manifest, err := recovery.VerifyManifest(manifestFrame.Payload, fixture.manifestVerifier, recovery.Expectation{
			RequestID: manifestRequest.RequestID, HostBinding: manifestRequest.HostFingerprint, Nonce: manifestRequest.Nonce,
			RecoverySigningKeyID: fixture.manifestKeyID, ExpectedPolicyKeyID: fixture.policyKeyID,
			CurrentVersion: 0, TrustedEarliestNS: time.Now().Add(-30 * time.Second).UnixNano(), TrustedLatestNS: time.Now().Add(30 * time.Second).UnixNano(),
		})
		if err != nil || manifest.ArtifactDigest != fixture.artifact.Digest {
			t.Fatalf("authenticated manifest = %#v, %v", manifest, err)
		}
		artifactRequest := fixture.request(t, recovery.OperationArtifact, manifest.ArtifactDigest, 3)
		writeEvaluationFrame(t, connection, fixture.signedFrame(t, artifactRequest))
		frames := readEvaluationArtifact(t, reader, connection, artifactRequest)
		received := joinEvaluationData(t, frames)
		if got := sha256.Sum256(received); got == manifest.ArtifactDigest {
			t.Fatal("digest mismatch did not reach the final artifact digest")
		}
		assertCanonicalEvaluationStream(t, frames, artifactRequest)
		stopProxy()
		runtime.stop(t)
		fixture.auditEventFile(t, events, recovery.EvaluationFaultArtifactDigestMismatch, "injected", 0)
	})

	t.Run("chunk-sequence-reaches-wire", func(t *testing.T) {
		events := fixture.eventPath(t, "sequence")
		eventPaths = append(eventPaths, events)
		options, sink, _ := fixture.evaluationOptions(t, events, recovery.EvaluationFaultChunkSequence)
		runtime := fixture.start(t, options, sink)
		defer runtime.stop(t)
		connection, reader, stopProxy := fixture.proxyConnection(t, runtime.address)
		request := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, 4)
		writeEvaluationFrame(t, connection, fixture.signedFrame(t, request))
		first := reader.next(t, connection)
		second := reader.next(t, connection)
		if first.Type != wire.MessageData || first.Sequence != 0 || second.Type != wire.MessageData || second.Sequence != 2 {
			t.Fatalf("chunk fault frames = %#v, %#v; want DATA 0 then DATA 2", first, second)
		}
		stopProxy()
		runtime.stop(t)
		fixture.auditEventFile(t, events, recovery.EvaluationFaultChunkSequence, "injected", 2)
	})

	t.Run("interruption-is-synced-cancelled-and-restarts-at-zero", func(t *testing.T) {
		events := fixture.eventPath(t, "interrupt")
		eventPaths = append(eventPaths, events)
		options, sink, barrier := fixture.evaluationOptions(t, events, recovery.EvaluationFaultInterruptAfterData7)
		runtime := fixture.start(t, options, sink)
		connection, reader, stopProxy := fixture.proxyConnection(t, runtime.address)
		request := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, 5)
		writeEvaluationFrame(t, connection, fixture.signedFrame(t, request))
		for sequence := uint32(0); sequence <= 7; sequence++ {
			frame := reader.next(t, connection)
			if frame.Type != wire.MessageData || frame.Sequence != sequence {
				t.Fatalf("DATA %d = %#v", sequence, frame)
			}
		}
		barrier.waitForInterruptRecord(t)
		fixture.auditEventFile(t, events, recovery.EvaluationFaultInterruptAfterData7, "interrupt-ready", 7)
		runtime.stop(t)
		if err := connection.SetReadDeadline(time.Now().Add(recoveryIntegrationTimeout)); err != nil {
			t.Fatal(err)
		}
		if record, err := reader.reader.ReadBytes(0); err == nil || len(record) != 0 {
			t.Fatalf("cancellation emitted protocol bytes %x, err=%v", record, err)
		}
		stopProxy()

		freshEvents := fixture.eventPath(t, "restart")
		eventPaths = append(eventPaths, freshEvents)
		freshOptions, freshSink, _ := fixture.evaluationOptions(t, freshEvents, recovery.EvaluationFaultInterruptAfterData7)
		fresh := fixture.start(t, freshOptions, freshSink)
		defer fresh.stop(t)
		freshConnection, freshReader, stopFreshProxy := fixture.proxyConnection(t, fresh.address)
		freshRequest := fixture.request(t, recovery.OperationArtifact, fixture.artifact.Digest, 6)
		writeEvaluationFrame(t, freshConnection, fixture.signedFrame(t, freshRequest))
		if frame := freshReader.next(t, freshConnection); frame.Type != wire.MessageData || frame.Sequence != 0 {
			t.Fatalf("fresh server artifact start = %#v, want DATA 0", frame)
		}
		stopFreshProxy()
		fresh.stop(t)
		fixture.auditEventFile(t, freshEvents, recovery.EvaluationFaultInterruptAfterData7, "sent", 0)
	})
	fixture.auditSensitiveRepresentations(t, capturedLogs.Bytes(), eventPaths...)
}

type recoveryEvaluationFixture struct {
	directory        string
	databasePath     string
	gatewayConfig    config.Config
	artifact         recovery.Artifact
	artifactBytes    []byte
	hostKey          *ecdsa.PrivateKey
	hostFingerprint  [sha256.Size]byte
	manifestKeyID    []byte
	policyKeyID      []byte
	manifestVerifier cose.Verifier
	pinnedSPKI       []byte
	sensitive        [][]byte
}

type recoveryEvaluationRuntime struct {
	address string
	cancel  context.CancelFunc
	done    <-chan error
	cleanup func()
	sink    *evalevidence.Sink
	once    sync.Once
}

type recoveryEvaluationReader struct {
	reader  *bufio.Reader
	decoder *wire.Decoder
}

// evaluationObserverBarrier observes only after the real event sink has
// written and synchronized an event. It is test-only and does not alter the
// production recovery handler or sink.
type evaluationObserverBarrier struct {
	sink           *evalevidence.Sink
	interruptReady chan struct{}
	once           sync.Once
}

func (observer *evaluationObserverBarrier) Record(event recovery.EvaluationEvent) error {
	err := observer.sink.Record(event)
	if err == nil && event.Fault == recovery.EvaluationFaultInterruptAfterData7 &&
		event.Operation == "artifact" && event.Frame == "DATA" && event.Sequence == 7 &&
		event.Outcome == "interrupt-ready" {
		observer.once.Do(func() { close(observer.interruptReady) })
	}
	return err
}

func (observer *evaluationObserverBarrier) waitForInterruptRecord(t *testing.T) {
	t.Helper()
	select {
	case <-observer.interruptReady:
	case <-time.After(recoveryIntegrationTimeout):
		t.Fatal("DATA7 event sink Record did not return after synchronization")
	}
}

func newRecoveryEvaluationFixture(t *testing.T) *recoveryEvaluationFixture {
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
	parsedCertificate, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsedCertificate.DNSNames) != 1 || parsedCertificate.DNSNames[0] != "pbns-gateway.test" {
		t.Fatal("test certificate SAN does not bind the proxied gateway name")
	}
	spki := sha256.Sum256(parsedCertificate.RawSubjectPublicKeyInfo)
	runtimeTLSPrivatePEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}

	hostKey := generateLiveKey(t)
	identity := encodeLiveIdentity(t, &hostKey.PublicKey)
	hostFingerprint := sha256.Sum256(identity)
	databasePath := filepath.Join(directory, "enrollment.db")
	database, err := store.Open(databasePath, store.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := database.CreateEnrollment(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transcript := sha256.Sum256([]byte("recovery-evaluation-enrollment"))
	pending, err := database.BeginEnrollment(issued.Plaintext, transcript)
	if err != nil {
		t.Fatal(err)
	}
	baseline := sha256.Sum256([]byte("recovery-evaluation-baseline"))
	if err := database.CompleteEnrollment(pending.ID, model.HostRecord{
		Fingerprint: hostFingerprint, IdentityCOSEKey: identity, Assurance: model.AssuranceSoftware,
		BaselineID: baseline, EnrolledAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	repositoryRoot := filepath.Join(directory, "repository")
	repository, err := recovery.OpenRepository(repositoryRoot)
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes := bytes.Repeat([]byte("PBNS-recovery-evaluation-artifact/"), (8*wire.DataPayloadMax+37)/34+1)
	artifactBytes = artifactBytes[:8*wire.DataPayloadMax+37]
	artifactSource := filepath.Join(directory, "recovery.efi")
	if err := os.WriteFile(artifactSource, artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := repository.Publish(artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(repositoryRoot, "artifacts", hex.EncodeToString(artifact.Digest[:]))
	if info, err := os.Stat(artifactPath); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("published immutable artifact mode = %v, %v", info.Mode(), err)
	}

	manifestKey, policyKey, secureBootKey := generateLiveKey(t), generateLiveKey(t), generateLiveKey(t)
	manifestKeyID, policyKeyID := []byte("evaluation-manifest"), []byte("evaluation-policy")
	manifestPath := filepath.Join(directory, "manifest.pem")
	policyPath := filepath.Join(directory, "policy.pem")
	secureBootPath := filepath.Join(directory, "secureboot.pem")
	if err := keys.SaveECPrivateKey(manifestPath, manifestKey); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(policyPath, &policyKey.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(secureBootPath, &secureBootKey.PublicKey); err != nil {
		t.Fatal(err)
	}
	policyAuthorization, err := recovery.CreateVersionAuthorization(policyKey, recovery.RecoveryNVIndex, 7)
	if err != nil {
		t.Fatal(err)
	}
	policyAuthorizationPath := filepath.Join(directory, "policy-authorization.cbor")
	if err := os.WriteFile(policyAuthorizationPath, policyAuthorization, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestVerifier, err := cose.NewVerifier(cose.AlgorithmES256, &manifestKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	gatewayConfig := config.Default()
	gatewayConfig.TLSCertFile, gatewayConfig.TLSKeyFile = certificatePath, keyPath
	gatewayConfig.EnrollmentStoreFile = databasePath
	gatewayConfig.RecoveryRepository = repositoryRoot
	gatewayConfig.RecoveryArtifactSHA256 = hex.EncodeToString(artifact.Digest[:])
	gatewayConfig.RecoveryTargetVersion, gatewayConfig.RecoveryMinimumVersion = 7, 6
	gatewayConfig.RecoveryPolicyAuthorizationFile = policyAuthorizationPath
	gatewayConfig.RecoveryPolicyPublicKeyFile, gatewayConfig.RecoveryPolicyKID = policyPath, string(policyKeyID)
	gatewayConfig.RecoveryManifestSigningKeyFile, gatewayConfig.RecoveryManifestSigningKID = manifestPath, string(manifestKeyID)
	gatewayConfig.RecoverySecureBootPublicKeyFile = secureBootPath
	gatewayConfig.RecoveryValidityLead, gatewayConfig.RecoveryValidityTrailing = time.Minute, time.Minute
	gatewayConfig.RecoveryTransferTimeout = time.Minute
	gatewayConfig.HandshakeTimeout, gatewayConfig.ReadTimeout, gatewayConfig.WriteTimeout = time.Second, time.Second, time.Second
	gatewayConfig.MaxConnections = 4
	if err := gatewayConfig.Validate(); err != nil {
		t.Fatal(err)
	}
	return &recoveryEvaluationFixture{
		directory: directory, databasePath: databasePath, gatewayConfig: gatewayConfig, artifact: artifact, artifactBytes: artifactBytes,
		hostKey: hostKey, hostFingerprint: hostFingerprint, manifestKeyID: manifestKeyID, policyKeyID: policyKeyID,
		manifestVerifier: manifestVerifier, pinnedSPKI: append([]byte(nil), spki[:]...),
		sensitive: cloneLiveSensitive(artifactBytes, policyAuthorization, []byte(issued.Plaintext), issued.Digest[:],
			transcript[:], runtimeTLSPrivatePEM, p256Scalar(hostKey), p256Scalar(manifestKey),
			p256Scalar(policyKey), p256Scalar(secureBootKey)),
	}
}

func (fixture *recoveryEvaluationFixture) start(t *testing.T, options gatewayapp.Options, sink *evalevidence.Sink) *recoveryEvaluationRuntime {
	t.Helper()
	tlsConfig, err := fixture.gatewayConfig.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	handlers, cleanup, err := gatewayapp.ConfiguredHandlers(fixture.gatewayConfig, options)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := New(Config{TLS: tlsConfig, Handlers: handlers, Limits: fixture.gatewayConfig.Limits,
		HandshakeTimeout: fixture.gatewayConfig.HandshakeTimeout, ReadTimeout: fixture.gatewayConfig.ReadTimeout,
		WriteTimeout: fixture.gatewayConfig.WriteTimeout, MaxConnections: fixture.gatewayConfig.MaxConnections})
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Serve(ctx, listener) }()
	runtime := &recoveryEvaluationRuntime{address: listener.Addr().String(), cancel: cancel, done: done, cleanup: cleanup, sink: sink}
	t.Cleanup(func() { runtime.stop(t) })
	return runtime
}

func (fixture *recoveryEvaluationFixture) evaluationOptions(t *testing.T, eventPath string, fault recovery.EvaluationFault) (gatewayapp.Options, *evalevidence.Sink, *evaluationObserverBarrier) {
	t.Helper()
	sink, err := evalevidence.Open(eventPath, "tls-evaluation", fault)
	if err != nil {
		t.Fatal(err)
	}
	observer := &evaluationObserverBarrier{sink: sink, interruptReady: make(chan struct{})}
	return gatewayapp.Options{WrapRecovery: func(service *recovery.Service) (Handler, error) {
		return recovery.NewEvaluationHandler(service, fault, observer)
	}}, sink, observer
}

func (runtime *recoveryEvaluationRuntime) stop(t *testing.T) {
	t.Helper()
	runtime.once.Do(func() {
		runtime.cancel()
		select {
		case err := <-runtime.done:
			if err != nil {
				t.Errorf("evaluation gateway: %v", err)
			}
		case <-time.After(recoveryIntegrationTimeout):
			t.Error("evaluation gateway did not stop")
		}
		if runtime.sink != nil {
			if err := runtime.sink.Close(); err != nil {
				t.Errorf("evaluation event sink: %v", err)
			}
		}
		runtime.cleanup()
	})
}

func (fixture *recoveryEvaluationFixture) eventPath(t *testing.T, name string) string {
	t.Helper()
	parent := filepath.Join(fixture.directory, "events-"+name)
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "events.jsonl")
}

func (fixture *recoveryEvaluationFixture) proxyConnection(t *testing.T, address string) (net.Conn, *recoveryEvaluationReader, func()) {
	t.Helper()
	proxy, err := proxysim.New(proxysim.Config{GatewayAddress: address, ServerName: "pbns-gateway.test",
		PinnedSPKI: fixture.pinnedSPKI, DialTimeout: time.Second, HandshakeTimeout: time.Second,
		Upstream: proxysim.Faults{FragmentSize: 7}, Downstream: proxysim.Faults{FragmentSize: 11}})
	if err != nil {
		t.Fatal(err)
	}
	client, proxySide := liveConnectionPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Forward(ctx, proxySide) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = client.Close()
			select {
			case <-done:
			case <-time.After(recoveryIntegrationTimeout):
				t.Errorf("evaluation proxy did not stop")
			}
		})
	}
	t.Cleanup(stop)
	decoder, err := wire.NewDecoder(wire.DefaultLimits())
	if err != nil {
		stop()
		t.Fatal(err)
	}
	return client, &recoveryEvaluationReader{reader: bufio.NewReaderSize(client, wire.WireMax), decoder: decoder}, stop
}

func (fixture *recoveryEvaluationFixture) request(t *testing.T, operation recovery.Operation, digest [32]byte, salt byte) recovery.Request {
	t.Helper()
	request := recovery.Request{Domain: recovery.RequestDomain, Version: recovery.RequestVersion, Service: recovery.ServiceRecoveryArtifact,
		Operation: operation, HostFingerprint: fixture.hostFingerprint, ArtifactDigest: digest}
	for index := range request.RequestID {
		request.RequestID[index] = byte(index+1) ^ salt
	}
	for index := range request.Nonce {
		request.Nonce[index] = byte(index+0x41) ^ salt
	}
	fixture.sensitive = append(fixture.sensitive, append([]byte(nil), request.Nonce[:]...))
	return request
}

func (fixture *recoveryEvaluationFixture) signedFrame(t *testing.T, request recovery.Request) wire.Frame {
	t.Helper()
	signer, err := cose.NewSigner(cose.AlgorithmES256, fixture.hostKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := recovery.SignRequest(request, signer)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Frame{Service: wire.ServiceRecoveryArtifact, Type: wire.MessageRequest,
		RequestID: wire.RequestID(request.RequestID), Payload: payload}
}

func (fixture *recoveryEvaluationFixture) goldenArtifact(t *testing.T, request recovery.Request) []byte {
	frames := make([]wire.Frame, 0, 10)
	for sequence, offset := uint32(0), 0; offset < len(fixture.artifactBytes); sequence++ {
		end := offset + wire.DataPayloadMax
		if end > len(fixture.artifactBytes) {
			end = len(fixture.artifactBytes)
		}
		frames = append(frames, wire.Frame{Service: wire.ServiceRecoveryArtifact, Type: wire.MessageData,
			RequestID: wire.RequestID(request.RequestID), Sequence: sequence, Payload: fixture.artifactBytes[offset:end]})
		offset = end
	}
	frames = append(frames, wire.Frame{Service: wire.ServiceRecoveryArtifact, Type: wire.MessageComplete,
		RequestID: wire.RequestID(request.RequestID), Sequence: uint32(len(frames))})
	return encodeEvaluationFrames(t, frames)
}

type recoveryEvaluationEventRecord struct {
	Schema     string                   `json:"schema"`
	Case       string                   `json:"case"`
	Connection uint64                   `json:"connection"`
	Operation  string                   `json:"operation"`
	Frame      string                   `json:"frame"`
	Sequence   uint32                   `json:"sequence"`
	Next       uint32                   `json:"next"`
	Window     uint32                   `json:"window"`
	Fault      recovery.EvaluationFault `json:"fault"`
	Outcome    string                   `json:"outcome"`
}

var recoveryEvaluationEventKeys = map[string]struct{}{
	"schema": {}, "case": {}, "connection": {}, "operation": {}, "frame": {},
	"sequence": {}, "next": {}, "window": {}, "fault": {}, "outcome": {},
}

func TestRecoveryEvaluationEventJSONOracleRejectsNonExactValues(t *testing.T) {
	valid := `{"schema":"pbns-recovery-evaluation-v1","case":"tls-evaluation","connection":1,"operation":"artifact","frame":"DATA","sequence":0,"next":0,"window":0,"fault":"artifact-digest-mismatch","outcome":"injected"}`
	if err := validateRecoveryEvaluationEventJSON([]byte(valid)); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	values := map[string]string{
		"schema": `"pbns-recovery-evaluation-v1"`, "case": `"tls-evaluation"`, "connection": "1",
		"operation": `"artifact"`, "frame": `"DATA"`, "sequence": "0", "next": "0", "window": "0",
		"fault": `"artifact-digest-mismatch"`, "outcome": `"injected"`,
	}
	for key, value := range values {
		t.Run("null-"+key, func(t *testing.T) {
			invalid := strings.Replace(valid, `"`+key+`":`+value, `"`+key+`":null`, 1)
			if err := validateRecoveryEvaluationEventJSON([]byte(invalid)); err == nil {
				t.Fatalf("null %s accepted: %s", key, invalid)
			}
		})
	}
	for key, replacement := range map[string]string{
		"schema": `"other-schema"`, "case": `"other-case"`, "connection": "2",
		"operation": `"manifest"`, "frame": `"RESPONSE"`, "sequence": "1", "next": "1", "window": "1",
		"fault": `"chunk-sequence"`, "outcome": `"sent"`,
	} {
		t.Run("wrong-value-"+key, func(t *testing.T) {
			invalid := strings.Replace(valid, `"`+key+`":`+values[key], `"`+key+`":`+replacement, 1)
			if err := validateRecoveryEvaluationEventJSON([]byte(invalid)); err == nil {
				t.Fatalf("wrong value %s accepted: %s", key, invalid)
			}
		})
	}
	for _, key := range []string{"schema", "case", "operation", "frame", "fault", "outcome"} {
		t.Run("non-string-"+key, func(t *testing.T) {
			invalid := strings.Replace(valid, `"`+key+`":`+values[key], `"`+key+`":0`, 1)
			if err := validateRecoveryEvaluationEventJSON([]byte(invalid)); err == nil {
				t.Fatalf("non-string %s accepted: %s", key, invalid)
			}
		})
	}
	for _, key := range []string{"connection", "sequence", "next", "window"} {
		for name, value := range map[string]string{
			"fractional": "0.5", "negative": "-1", "quoted": `"0"`,
			"out-of-range": map[string]string{
				"connection": "18446744073709551616", "sequence": "4294967296",
				"next": "4294967296", "window": "4294967296",
			}[key],
		} {
			t.Run(name+"-"+key, func(t *testing.T) {
				invalid := strings.Replace(valid, `"`+key+`":`+values[key], `"`+key+`":`+value, 1)
				if err := validateRecoveryEvaluationEventJSON([]byte(invalid)); err == nil {
					t.Fatalf("%s %s accepted: %s", name, key, invalid)
				}
			})
		}
	}
	for name, invalid := range map[string]string{
		"duplicate":               strings.Replace(valid, `"outcome":"injected"`, `"outcome":"injected","outcome":"injected"`, 1),
		"extra":                   strings.Replace(valid, `}`, `,"extra":0}`, 1),
		"missing":                 strings.Replace(valid, `,"window":0`, ``, 1),
		"fractional-sequence":     strings.Replace(valid, `"sequence":0`, `"sequence":0.5`, 1),
		"negative-next":           strings.Replace(valid, `"next":0`, `"next":-1`, 1),
		"out-of-range-window":     strings.Replace(valid, `"window":0`, `"window":4294967296`, 1),
		"out-of-range-connection": strings.Replace(valid, `"connection":1`, `"connection":18446744073709551616`, 1),
		"quoted-sequence":         strings.Replace(valid, `"sequence":0`, `"sequence":"0"`, 1),
		"trailing":                valid + ` {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRecoveryEvaluationEventJSON([]byte(invalid)); err == nil {
				t.Fatalf("invalid event accepted: %s", invalid)
			}
		})
	}
}

func validateRecoveryEvaluationEventJSON(line []byte) error {
	event, err := decodeRecoveryEvaluationEvent(line)
	if err != nil {
		return err
	}
	return validateRecoveryEvaluationEvent(event, recovery.EvaluationFaultArtifactDigestMismatch)
}

func (fixture *recoveryEvaluationFixture) auditEventFile(t *testing.T, path string, fault recovery.EvaluationFault, outcome string, sequence uint32) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		t.Fatalf("event file is not complete JSONL: %q", contents)
	}
	found := false
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		event, decodeErr := decodeRecoveryEvaluationEvent([]byte(line))
		if decodeErr != nil {
			t.Fatalf("event schema = %q: %v", line, decodeErr)
		}
		if err := validateRecoveryEvaluationEvent(event, fault); err != nil {
			t.Fatalf("event values = %q: %v", line, err)
		}
		found = found || (event.Outcome == outcome && event.Sequence == sequence)
	}
	if !found {
		t.Fatalf("event %q/%d for %q not found in %q", outcome, sequence, fault, contents)
	}
}

func decodeRecoveryEvaluationEvent(line []byte) (recoveryEvaluationEventRecord, error) {
	values, err := decodeRecoveryEvaluationEventValues(line)
	if err != nil {
		return recoveryEvaluationEventRecord{}, err
	}
	for _, key := range []string{"schema", "case", "operation", "frame", "fault", "outcome"} {
		if err := requireJSONString(values[key]); err != nil {
			return recoveryEvaluationEventRecord{}, fmt.Errorf("%s must be a JSON string: %w", key, err)
		}
	}
	for _, key := range []string{"connection", "sequence", "next", "window"} {
		bits := 32
		if key == "connection" {
			bits = 64
		}
		if _, err := requireJSONUnsigned(values[key], bits); err != nil {
			return recoveryEvaluationEventRecord{}, fmt.Errorf("%s must be an unsigned JSON integer: %w", key, err)
		}
	}
	var event recoveryEvaluationEventRecord
	if err := json.Unmarshal(line, &event); err != nil {
		return recoveryEvaluationEventRecord{}, err
	}
	return event, nil
}

func decodeRecoveryEvaluationEventValues(line []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, errors.New("event is not a JSON object")
	}
	values := make(map[string]json.RawMessage, len(recoveryEvaluationEventKeys))
	for decoder.More() {
		token, tokenErr := decoder.Token()
		key, isString := token.(string)
		if tokenErr != nil || !isString {
			return nil, errors.New("event object key is invalid")
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("event has duplicate key %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("event value for %q: %w", key, err)
		}
		values[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("event object close is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("event has trailing JSON")
	}
	if len(values) != len(recoveryEvaluationEventKeys) {
		return nil, fmt.Errorf("event key count = %d, want %d", len(values), len(recoveryEvaluationEventKeys))
	}
	for key := range recoveryEvaluationEventKeys {
		if _, exists := values[key]; !exists {
			return nil, fmt.Errorf("event is missing key %q", key)
		}
	}
	return values, nil
}

func requireJSONString(value json.RawMessage) error {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return errors.New("wrong JSON type")
	}
	var decoded string
	return json.Unmarshal(value, &decoded)
}

func requireJSONUnsigned(value json.RawMessage, bits int) (uint64, error) {
	if len(value) == 0 || bytes.IndexFunc(value, func(r rune) bool {
		return r < '0' || r > '9'
	}) >= 0 {
		return 0, errors.New("wrong JSON type")
	}
	return strconv.ParseUint(string(value), 10, bits)
}

func validateRecoveryEvaluationEvent(event recoveryEvaluationEventRecord, expectedFault recovery.EvaluationFault) error {
	if event.Schema != "pbns-recovery-evaluation-v1" || event.Case != "tls-evaluation" ||
		event.Connection != 1 || event.Fault != expectedFault {
		return fmt.Errorf("event fixed values = %#v", event)
	}
	if event.Operation == "manifest" {
		if event.Frame != "RESPONSE" || event.Sequence != 0 || event.Next != 0 || event.Window != 0 || event.Outcome != "sent" {
			return fmt.Errorf("manifest event fields = %#v", event)
		}
		return nil
	}
	if event.Operation != "artifact" {
		return fmt.Errorf("event operation = %#v", event)
	}
	switch event.Frame {
	case "DATA":
		if event.Next != 0 || event.Window != 0 {
			return fmt.Errorf("DATA counters = %#v", event)
		}
		switch event.Fault {
		case recovery.EvaluationFaultArtifactDigestMismatch:
			if (event.Sequence == 0 && event.Outcome != "injected") ||
				(event.Sequence > 0 && event.Sequence <= 8 && event.Outcome != "sent") || event.Sequence > 8 {
				return fmt.Errorf("digest DATA event = %#v", event)
			}
		case recovery.EvaluationFaultChunkSequence:
			if (event.Sequence == 2 && event.Outcome != "injected" && event.Outcome != "sent") ||
				(event.Sequence == 0 && event.Outcome != "sent") ||
				(event.Sequence >= 3 && event.Sequence <= 7 && event.Outcome != "sent") ||
				event.Sequence == 1 || event.Sequence > 7 {
				return fmt.Errorf("chunk DATA event = %#v", event)
			}
		case recovery.EvaluationFaultInterruptAfterData7:
			if (event.Sequence <= 6 && event.Outcome != "sent") ||
				(event.Sequence == 7 && event.Outcome != "interrupt-ready") || event.Sequence > 7 {
				return fmt.Errorf("interruption DATA event = %#v", event)
			}
		default:
			return fmt.Errorf("unknown fault event = %#v", event)
		}
	case "ACK":
		if event.Fault != recovery.EvaluationFaultArtifactDigestMismatch || event.Sequence != 0 ||
			event.Next != recovery.ACKWindow || event.Window != recovery.ACKWindow || event.Outcome != "accepted" {
			return fmt.Errorf("ACK event fields = %#v", event)
		}
	case "COMPLETE":
		if event.Fault != recovery.EvaluationFaultArtifactDigestMismatch || event.Sequence != 9 ||
			event.Next != 0 || event.Window != 0 || event.Outcome != "sent" {
			return fmt.Errorf("COMPLETE event fields = %#v", event)
		}
	default:
		return fmt.Errorf("event frame = %#v", event)
	}
	return nil
}

func (fixture *recoveryEvaluationFixture) auditSensitiveRepresentations(t *testing.T, logs []byte, eventPaths ...string) {
	t.Helper()
	database, err := store.Open(fixture.databasePath, store.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := database.ListHosts()
	closeErr := database.Close()
	if err != nil || closeErr != nil || len(hosts) != 1 {
		t.Fatalf("bbolt host inventory = %d hosts, list=%v close=%v", len(hosts), err, closeErr)
	}
	sources := [][]byte{logs, []byte(hosts[0].String())}
	for _, path := range eventPaths {
		contents, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		sources = append(sources, contents)
	}
	for _, sensitive := range fixture.sensitive {
		for _, representation := range liveSensitiveRepresentations(sensitive) {
			for _, source := range sources {
				if bytes.Contains(source, representation) {
					t.Fatalf("gateway log, bbolt inventory, or event JSON exposed sensitive representation %q", representation)
				}
			}
		}
	}
}

func (reader *recoveryEvaluationReader) next(t *testing.T, connection net.Conn) wire.Frame {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(recoveryIntegrationTimeout)); err != nil {
		t.Fatal(err)
	}
	record, err := reader.reader.ReadBytes(0)
	if err != nil {
		t.Fatal("proxied TLS evaluation response was not received")
	}
	frame, err := reader.decoder.Decode(record)
	if err != nil {
		t.Fatal("proxied evaluation frame was not canonical")
	}
	return frame
}

func writeEvaluationFrame(t *testing.T, connection net.Conn, frame wire.Frame) {
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
			t.Fatal("fragmented evaluation write failed")
		}
		offset = end
	}
}

func readEvaluationArtifact(t *testing.T, reader *recoveryEvaluationReader, connection net.Conn, request recovery.Request) []wire.Frame {
	t.Helper()
	frames := make([]wire.Frame, 0, 10)
	var data, acknowledgements uint32
	for {
		frame := reader.next(t, connection)
		frame.Payload = append([]byte(nil), frame.Payload...)
		frames = append(frames, frame)
		if frame.Type == wire.MessageComplete {
			return frames
		}
		if frame.Type != wire.MessageData {
			t.Fatalf("artifact stream frame = %#v", frame)
		}
		data++
		if data%recovery.ACKWindow == 0 {
			writeEvaluationFrame(t, connection, recovery.ACKFrame(wire.RequestID(request.RequestID), acknowledgements, data))
			acknowledgements++
		}
	}
}

func assertCanonicalEvaluationStream(t *testing.T, frames []wire.Frame, request recovery.Request) {
	t.Helper()
	if len(frames) < 2 || frames[len(frames)-1].Type != wire.MessageComplete {
		t.Fatalf("artifact stream is not DATA/COMPLETE: %#v", frames)
	}
	for sequence, frame := range frames[:len(frames)-1] {
		if frame.Type != wire.MessageData || frame.RequestID != wire.RequestID(request.RequestID) || frame.Sequence != uint32(sequence) {
			t.Fatalf("noncanonical DATA %d = %#v", sequence, frame)
		}
	}
	complete := frames[len(frames)-1]
	if complete.RequestID != wire.RequestID(request.RequestID) || complete.Sequence != uint32(len(frames)-1) || len(complete.Payload) != 0 {
		t.Fatalf("noncanonical COMPLETE = %#v", complete)
	}
}

func joinEvaluationData(t *testing.T, frames []wire.Frame) []byte {
	t.Helper()
	var data []byte
	for _, frame := range frames {
		if frame.Type == wire.MessageData {
			data = append(data, frame.Payload...)
		}
	}
	return data
}

func encodeEvaluationFrames(t *testing.T, frames []wire.Frame) []byte {
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
