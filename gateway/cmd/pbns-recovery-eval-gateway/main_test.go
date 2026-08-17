package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"pbns.local/gateway/internal/config"
	"pbns.local/gateway/internal/gatewayapp"
	"pbns.local/gateway/internal/keys"
	"pbns.local/gateway/internal/recovery"
	"pbns.local/gateway/internal/server"
	"pbns.local/gateway/internal/wire"
)

func recoverySuffix() []string {
	return []string{
		"--tls-cert", "certificate.pem", "--tls-key", "private-key.pem",
		"--enrollment-store", "gateway.db",
		"--recovery-repository", "repository",
		"--recovery-artifact-sha256", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--recovery-target-version", "1", "--recovery-minimum-version", "0",
		"--recovery-policy-authorization", "authorization.bin",
		"--recovery-policy-public-key", "policy.pem", "--recovery-policy-kid", "policy-kid",
		"--recovery-manifest-signing-key", "manifest.pem", "--recovery-manifest-signing-kid", "manifest-kid",
		"--recovery-secureboot-public-key", "secureboot.pem",
		"--recovery-validity-lead", "1s", "--recovery-validity-trailing", "1s",
		"--recovery-transfer-timeout", "1s",
	}
}

func evaluationArguments(t *testing.T) []string {
	t.Helper()
	return append([]string{
		"--case", "case-1", "--fault", "chunk-sequence",
		"--events", filepath.Join(t.TempDir(), "events.jsonl"), "--",
	}, recoverySuffix()...)
}

func TestParseArgumentsAcceptsClosedPrefixAndUnchangedRecoverySuffix(t *testing.T) {
	arguments := evaluationArguments(t)
	parsed, err := parseArguments(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.caseName != "case-1" || parsed.fault != recovery.EvaluationFaultChunkSequence {
		t.Fatalf("parsed prefix = %#v", parsed)
	}
	if !reflect.DeepEqual(parsed.suffix, recoverySuffix()) {
		t.Fatalf("suffix = %q, want %q", parsed.suffix, recoverySuffix())
	}
	gatewayConfig, err := config.Parse(parsed.suffix)
	if err != nil || !gatewayConfig.RecoveryEnabled() {
		t.Fatalf("suffix config = %#v, %v; want recovery enabled", gatewayConfig, err)
	}
}

func TestParseArgumentsAcceptsEachClosedFault(t *testing.T) {
	for _, fault := range []recovery.EvaluationFault{
		recovery.EvaluationFaultInterruptAfterData7,
		recovery.EvaluationFaultArtifactDigestMismatch,
		recovery.EvaluationFaultChunkSequence,
	} {
		t.Run(string(fault), func(t *testing.T) {
			arguments := evaluationArguments(t)
			arguments[3] = string(fault)
			parsed, err := parseArguments(arguments)
			if err != nil || parsed.fault != fault {
				t.Fatalf("parseArguments() = %#v, %v", parsed, err)
			}
		})
	}
}

func TestParseArgumentsRejectsInvalidGrammarAndClosedValues(t *testing.T) {
	valid := evaluationArguments(t)
	existing := filepath.Join(t.TempDir(), "existing.jsonl")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := map[string][]string{
		"missing-separator":    valid[:len(valid)-len(recoverySuffix())-1],
		"extra-separator":      append(append([]string{}, valid...), "--"),
		"prefix-positional":    append([]string{"case-1"}, valid...),
		"duplicate-case":       append([]string{"--case", "again"}, valid...),
		"unknown-prefix-flag":  append([]string{"--unknown", "value"}, valid...),
		"equals-prefix-flag":   append([]string{"--case=case-1"}, valid[2:]...),
		"missing-prefix-value": append([]string{"--case"}, valid[2:]...),
		"invalid-case":         append([]string{"--case", "Case"}, valid[2:]...),
		"invalid-fault":        append([]string{"--case", "case-1", "--fault", "unknown"}, valid[4:]...),
		"combined-fault":       append([]string{"--case", "case-1", "--fault", "chunk-sequence,artifact-digest-mismatch"}, valid[4:]...),
		"existing-events":      append([]string{"--case", "case-1", "--fault", "chunk-sequence", "--events", existing}, valid[6:]...),
		"no-recovery": append(
			append([]string{}, valid[:7]...), "--tls-cert", "certificate.pem", "--tls-key", "private-key.pem",
		),
		"invalid-production-config": append(valid[:7], "--not-production"),
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseArguments(arguments); err == nil {
				t.Fatalf("parseArguments(%q) succeeded", arguments)
			}
		})
	}
}

func TestRunRejectsUnsafeEventPathBeforeStartingGateway(t *testing.T) {
	originalRun := runGateway
	t.Cleanup(func() { runGateway = originalRun })
	runGateway = func(context.Context, []string, gatewayapp.Options) error {
		t.Fatal("gateway started with unsafe event path")
		return nil
	}
	arguments := evaluationArguments(t)
	arguments[5] = filepath.Dir(arguments[5]) + "/./events.jsonl"
	if err := run(context.Background(), arguments); err == nil {
		t.Fatal("run accepted noncanonical event path")
	}
}

func TestEvaluationCommandKeepsProductionFlagsSeparate(t *testing.T) {
	if _, err := config.Parse([]string{"--fault", "chunk-sequence"}); err == nil {
		t.Fatal("production parsing accepted --fault")
	}
	if _, err := parseArguments(append([]string{"--fault", "chunk-sequence", "--"}, recoverySuffix()...)); err == nil {
		t.Fatal("evaluation command accepted an unprefixed fault")
	}
}

type testSink struct {
	closeErr   error
	closeCalls int
}

func (sink *testSink) Record(recovery.EvaluationEvent) error { return nil }
func (sink *testSink) Close() error {
	sink.closeCalls++
	return sink.closeErr
}

func installCommandSeams(t *testing.T) {
	t.Helper()
	originalOpen, originalRun := openEventSink, runGateway
	originalHandler, originalNotify := newEvaluationHandler, notifyContext
	t.Cleanup(func() {
		openEventSink, runGateway = originalOpen, originalRun
		newEvaluationHandler, notifyContext = originalHandler, originalNotify
	})
}

func TestRunOpensClosesAndConfiguresEvaluationWrapperForRecoveryOnly(t *testing.T) {
	installCommandSeams(t)
	sink := &testSink{}
	openCalls, runCalls := 0, 0
	openEventSink = func(path, caseName string, fault recovery.EvaluationFault) (evaluationSink, error) {
		openCalls++
		if path == "" || caseName != "case-1" || fault != recovery.EvaluationFaultChunkSequence {
			t.Fatalf("sink open arguments = %q, %q, %q", path, caseName, fault)
		}
		return sink, nil
	}
	runGateway = func(_ context.Context, arguments []string, options gatewayapp.Options) error {
		runCalls++
		if !reflect.DeepEqual(arguments, recoverySuffix()) || options.WrapRecovery == nil {
			t.Fatalf("gateway arguments/options = %q, %#v", arguments, options)
		}

		originalWrapper := options.WrapRecovery
		wrapperCalls := 0
		var evaluationHandler server.Handler
		options.WrapRecovery = func(service *recovery.Service) (server.Handler, error) {
			wrapperCalls++
			handler, err := originalWrapper(service)
			if err != nil || handler == nil {
				t.Fatalf("evaluation wrapper = %T, %v", handler, err)
			}
			evaluationHandler = handler
			return handler, err
		}
		handlers, cleanup, err := gatewayapp.ConfiguredHandlers(evaluationRecoveryConfig(t), options)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if wrapperCalls != 1 || evaluationHandler == nil ||
			fmt.Sprintf("%T", evaluationHandler) != "*recovery.evaluationHandler" ||
			handlers[wire.ServiceRecoveryArtifact] != evaluationHandler {
			t.Fatalf("recovery wrapper calls=%d handler=%T installed=%T", wrapperCalls,
				evaluationHandler, handlers[wire.ServiceRecoveryArtifact])
		}
		err = evaluationHandler.Handle(context.Background(), wire.Frame{}, nil)
		var protocolError *server.ProtocolError
		if !errors.As(err, &protocolError) {
			t.Fatalf("evaluation handler did not handle an invalid request: %v", err)
		}

		wrapperCalls = 0
		handlers, cleanup, err = gatewayapp.ConfiguredHandlers(config.Default(), options)
		if err != nil {
			t.Fatal(err)
		}
		cleanup()
		if wrapperCalls != 0 || handlers[wire.ServiceRecoveryArtifact] == nil {
			t.Fatalf("recovery-only wrapper calls=%d handler=%T", wrapperCalls,
				handlers[wire.ServiceRecoveryArtifact])
		}
		return nil
	}

	if err := run(context.Background(), evaluationArguments(t)); err != nil {
		t.Fatal(err)
	}
	if openCalls != 1 || runCalls != 1 || sink.closeCalls != 1 {
		t.Fatalf("open/run/close calls = %d/%d/%d, want 1/1/1", openCalls, runCalls, sink.closeCalls)
	}
}

func TestRunBindsParsedFaultAndOpenedSinkToEvaluationConstructor(t *testing.T) {
	installCommandSeams(t)
	sink := &testSink{}
	openEventSink = func(string, string, recovery.EvaluationFault) (evaluationSink, error) { return sink, nil }
	constructorCalls := 0
	newEvaluationHandler = func(service *recovery.Service, fault recovery.EvaluationFault,
		observer recovery.EvaluationObserver) (server.Handler, error) {
		constructorCalls++
		if service == nil || fault != recovery.EvaluationFaultChunkSequence || observer != sink {
			t.Fatalf("evaluation constructor inputs = service %T fault %q observer %T",
				service, fault, observer)
		}
		return service, nil
	}
	runGateway = func(_ context.Context, _ []string, options gatewayapp.Options) error {
		handlers, cleanup, err := gatewayapp.ConfiguredHandlers(evaluationRecoveryConfig(t), options)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if handlers[wire.ServiceRecoveryArtifact] == nil {
			t.Fatal("recovery handler missing")
		}
		return nil
	}

	if err := run(context.Background(), evaluationArguments(t)); err != nil {
		t.Fatal(err)
	}
	if constructorCalls != 1 || sink.closeCalls != 1 {
		t.Fatalf("constructor/close calls = %d/%d, want 1/1", constructorCalls, sink.closeCalls)
	}
}

func TestRunJoinsGatewayAndCloseErrorsExactlyOnce(t *testing.T) {
	installCommandSeams(t)
	runErr := errors.New("gateway stopped")
	sink := &testSink{closeErr: errors.New("sync failed")}
	openCalls, runCalls := 0, 0
	openEventSink = func(string, string, recovery.EvaluationFault) (evaluationSink, error) {
		openCalls++
		return sink, nil
	}
	runGateway = func(_ context.Context, arguments []string, options gatewayapp.Options) error {
		runCalls++
		if !reflect.DeepEqual(arguments, recoverySuffix()) || options.WrapRecovery == nil {
			t.Fatalf("gateway arguments/options = %q, %#v", arguments, options)
		}
		return runErr
	}

	err := run(context.Background(), evaluationArguments(t))
	if !errors.Is(err, sink.closeErr) || !errors.Is(err, runErr) ||
		openCalls != 1 || runCalls != 1 || sink.closeCalls != 1 {
		t.Fatalf("run=%v calls open/run/close=%d/%d/%d", err, openCalls, runCalls, sink.closeCalls)
	}
}

func TestRunOpenFailureDoesNotRunOrClose(t *testing.T) {
	installCommandSeams(t)
	openErr := errors.New("cannot open events")
	openCalls, runCalls := 0, 0
	openEventSink = func(string, string, recovery.EvaluationFault) (evaluationSink, error) {
		openCalls++
		return nil, openErr
	}
	runGateway = func(context.Context, []string, gatewayapp.Options) error {
		runCalls++
		return nil
	}

	err := run(context.Background(), evaluationArguments(t))
	if !errors.Is(err, openErr) || openCalls != 1 || runCalls != 0 {
		t.Fatalf("run=%v calls open/run=%d/%d", err, openCalls, runCalls)
	}
}

func TestExecutePassesInjectableSignalContextAndStopsLifecycle(t *testing.T) {
	installCommandSeams(t)
	sink := &testSink{}
	openEventSink = func(string, string, recovery.EvaluationFault) (evaluationSink, error) { return sink, nil }
	var cancel context.CancelFunc
	stopCalls := 0
	notifyContext = func(parent context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
		if parent != context.Background() || len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
			t.Fatalf("signal context inputs = %v", signals)
		}
		ctx, stop := context.WithCancel(parent)
		cancel = stop
		return ctx, func() {
			stopCalls++
			stop()
		}
	}
	runGateway = func(ctx context.Context, _ []string, _ gatewayapp.Options) error {
		cancel()
		<-ctx.Done()
		return nil
	}

	if status := execute(evaluationArguments(t), &bytes.Buffer{}); status != 0 {
		t.Fatalf("execute status = %d, want 0", status)
	}
	if stopCalls != 1 || sink.closeCalls != 1 {
		t.Fatalf("stop/close calls = %d/%d, want 1/1", stopCalls, sink.closeCalls)
	}
}

func TestExecuteWritesErrorAndReturnsNonzero(t *testing.T) {
	installCommandSeams(t)
	sink := &testSink{}
	openEventSink = func(string, string, recovery.EvaluationFault) (evaluationSink, error) { return sink, nil }
	runErr := errors.New("gateway failed")
	runGateway = func(context.Context, []string, gatewayapp.Options) error { return runErr }
	stderr := &bytes.Buffer{}

	if status := execute(evaluationArguments(t), stderr); status != 1 {
		t.Fatalf("execute status = %d, want 1", status)
	}
	if !strings.Contains(stderr.String(), runErr.Error()) || sink.closeCalls != 1 {
		t.Fatalf("stderr=%q close calls=%d", stderr.String(), sink.closeCalls)
	}
}

func evaluationRecoveryConfig(t *testing.T) config.Config {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secureBoot, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.pem")
	policyPath := filepath.Join(directory, "policy.pem")
	secureBootPath := filepath.Join(directory, "secureboot.pem")
	if err := keys.SaveECPrivateKey(manifestPath, manifest); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(policyPath, &policy.PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := keys.SaveECPublicKey(secureBootPath, &secureBoot.PublicKey); err != nil {
		t.Fatal(err)
	}
	authorization, err := recovery.CreateVersionAuthorization(policy, recovery.RecoveryNVIndex, 5)
	if err != nil {
		t.Fatal(err)
	}
	authorizationPath := filepath.Join(directory, "policy.cbor")
	if err := os.WriteFile(authorizationPath, authorization, 0o644); err != nil {
		t.Fatal(err)
	}
	repositoryPath := filepath.Join(directory, "repository")
	repository, err := recovery.OpenRepository(repositoryPath)
	if err != nil {
		t.Fatal(err)
	}
	artifactSource := filepath.Join(directory, "recovery.efi")
	if err := os.WriteFile(artifactSource, []byte("active recovery artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := repository.Publish(artifactSource)
	if err != nil {
		t.Fatal(err)
	}
	return config.Config{
		ListenAddress: "127.0.0.1:8443", HandshakeTimeout: time.Second,
		ReadTimeout: time.Second, WriteTimeout: time.Second, MaxConnections: 1,
		Limits: config.Default().Limits, EnrollmentStoreFile: filepath.Join(directory, "gateway.db"),
		RecoveryRepository: repositoryPath, RecoveryArtifactSHA256: fmt.Sprintf("%x", artifact.Digest),
		RecoveryTargetVersion: 5, RecoveryPolicyAuthorizationFile: authorizationPath,
		RecoveryPolicyPublicKeyFile: policyPath, RecoveryPolicyKID: "policy-1",
		RecoveryManifestSigningKeyFile: manifestPath, RecoveryManifestSigningKID: "manifest-1",
		RecoverySecureBootPublicKeyFile: secureBootPath, RecoveryValidityLead: time.Second,
		RecoveryValidityTrailing: time.Second, RecoveryTransferTimeout: time.Second,
	}
}
