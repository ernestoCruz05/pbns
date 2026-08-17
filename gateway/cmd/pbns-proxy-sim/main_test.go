package main

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"pbns.local/gateway/internal/proxysim"
)

func validArguments() []string {
	pin := make([]byte, 32)
	for index := range pin {
		pin[index] = byte(index)
	}
	return []string{
		"--listen", "/tmp/pbns-proxy-sim-test.sock",
		"--gateway", "127.0.0.1:8443",
		"--server-name", "pbns-gateway.test",
		"--spki-sha256", hex.EncodeToString(pin),
	}
}

func TestParseArgumentsBuildsBoundedBidirectionalFaults(t *testing.T) {
	arguments := append(validArguments(),
		"--fragment-size", "37",
		"--delay", "2ms",
		"--drop-after", "4096",
		"--duplicate-offset", "7",
		"--duplicate-length", "11",
		"--bit-flip-offset", "13",
	)
	options, err := parseArguments(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if options.listenPath != "/tmp/pbns-proxy-sim-test.sock" {
		t.Fatalf("unexpected listen path %q", options.listenPath)
	}
	if options.config.Upstream.FragmentSize != 37 || options.config.Downstream.FragmentSize != 37 ||
		options.config.Upstream.Delay != 2*time.Millisecond || options.config.Downstream.Delay != 2*time.Millisecond {
		t.Fatal("fragment and delay settings were not applied bidirectionally")
	}
	for _, faults := range []proxysim.Faults{options.config.Upstream, options.config.Downstream} {
		if faults.DropAfter == nil || *faults.DropAfter != 4096 ||
			faults.Duplicate == nil || faults.Duplicate.Offset != 7 || faults.Duplicate.Length != 11 ||
			faults.BitFlipOffset == nil || *faults.BitFlipOffset != 13 {
			t.Fatalf("unexpected fault configuration: %#v", faults)
		}
	}
}

func TestParseArgumentsRejectsInvalidOrIncompleteConfiguration(t *testing.T) {
	tests := map[string][]string{
		"missing-required":    nil,
		"bad-pin":             append(validArguments()[:len(validArguments())-1], "abcd"),
		"duplicate-half":      append(validArguments(), "--duplicate-offset", "3"),
		"negative-drop":       append(validArguments(), "--drop-after", "-2"),
		"unexpected-position": append(validArguments(), "extra"),
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseArguments(arguments); !errors.Is(err, errConfiguration) {
				t.Fatalf("got %v, want configuration error", err)
			}
		})
	}
}
