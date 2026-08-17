package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"pbns.local/gateway/internal/config"
	"pbns.local/gateway/internal/evalevidence"
	"pbns.local/gateway/internal/gatewayapp"
	"pbns.local/gateway/internal/recovery"
	"pbns.local/gateway/internal/server"
)

var errInvalidArguments = errors.New("invalid recovery evaluation gateway arguments")

var casePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

type commandArguments struct {
	caseName string
	fault    recovery.EvaluationFault
	events   string
	suffix   []string
}

type evaluationSink interface {
	recovery.EvaluationObserver
	Close() error
}

var openEventSink = func(path, caseName string, fault recovery.EvaluationFault) (evaluationSink, error) {
	return evalevidence.Open(path, caseName, fault)
}

var runGateway = gatewayapp.Run

var newEvaluationHandler = recovery.NewEvaluationHandler

var notifyContext = signal.NotifyContext

func main() {
	os.Exit(execute(os.Args[1:], os.Stderr))
}

func execute(arguments []string, stderr io.Writer) int {
	ctx, stop := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, arguments); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func run(ctx context.Context, arguments []string) (err error) {
	parsed, err := parseArguments(arguments)
	if err != nil {
		return err
	}
	sink, err := openEventSink(parsed.events, parsed.caseName, parsed.fault)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, sink.Close()) }()
	options := gatewayapp.Options{
		WrapRecovery: func(service *recovery.Service) (server.Handler, error) {
			return newEvaluationHandler(service, parsed.fault, sink)
		},
	}
	return runGateway(ctx, parsed.suffix, options)
}

func parseArguments(arguments []string) (commandArguments, error) {
	separator := -1
	for index, argument := range arguments {
		if argument != "--" {
			continue
		}
		if separator >= 0 {
			return commandArguments{}, invalidArguments("exactly one separator is required")
		}
		separator = index
	}
	if separator < 0 {
		return commandArguments{}, invalidArguments("exactly one separator is required")
	}
	prefix, suffix := arguments[:separator], arguments[separator+1:]
	if len(prefix) != 6 {
		return commandArguments{}, invalidArguments("prefix must contain exactly three flags")
	}

	values := make(map[string]string, 3)
	for index := 0; index < len(prefix); index += 2 {
		name, value := prefix[index], prefix[index+1]
		if name != "--case" && name != "--fault" && name != "--events" ||
			value == "" || value == "--" || len(value) > 2 && value[:2] == "--" {
			return commandArguments{}, invalidArguments("invalid evaluation prefix")
		}
		if _, exists := values[name]; exists {
			return commandArguments{}, invalidArguments("evaluation prefix flag repeated")
		}
		values[name] = value
	}
	caseName, casePresent := values["--case"]
	faultValue, faultPresent := values["--fault"]
	events, eventsPresent := values["--events"]
	if !casePresent || !faultPresent || !eventsPresent || !casePattern.MatchString(caseName) {
		return commandArguments{}, invalidArguments("invalid evaluation prefix")
	}
	fault := recovery.EvaluationFault(faultValue)
	if !validFault(fault) {
		return commandArguments{}, invalidArguments("invalid evaluation fault")
	}
	if _, err := os.Lstat(events); err == nil {
		return commandArguments{}, invalidArguments("event path must not exist")
	} else if !errors.Is(err, os.ErrNotExist) {
		return commandArguments{}, fmt.Errorf("%w: inspect event path: %v", errInvalidArguments, err)
	}
	gatewayConfig, err := config.Parse(suffix)
	if err != nil {
		return commandArguments{}, fmt.Errorf("%w: production gateway suffix: %v", errInvalidArguments, err)
	}
	if !gatewayConfig.RecoveryEnabled() {
		return commandArguments{}, invalidArguments("recovery must be enabled")
	}
	return commandArguments{caseName: caseName, fault: fault, events: events, suffix: suffix}, nil
}

func validFault(fault recovery.EvaluationFault) bool {
	switch fault {
	case recovery.EvaluationFaultInterruptAfterData7,
		recovery.EvaluationFaultArtifactDigestMismatch,
		recovery.EvaluationFaultChunkSequence:
		return true
	default:
		return false
	}
}

func invalidArguments(message string) error {
	return fmt.Errorf("%w: %s", errInvalidArguments, message)
}
