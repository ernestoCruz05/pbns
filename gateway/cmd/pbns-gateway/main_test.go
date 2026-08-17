package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"pbns.local/gateway/internal/config"
	"pbns.local/gateway/internal/gatewayapp"
)

func TestRunRejectsMissingTLSCredentials(t *testing.T) {
	if err := gatewayapp.Run(context.Background(), nil, gatewayapp.Options{}); !errors.Is(err, config.ErrTLSCredentials) {
		t.Fatalf("got %v, want ErrTLSCredentials", err)
	}
}

func TestProductionCommandHasNoEvaluationSurface(t *testing.T) {
	encoded, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"--fault", "--events", "--case", "evaluation", "eval-gateway"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("production main contains %q", forbidden)
		}
	}
	for _, arguments := range [][]string{
		{"--fault", "chunk-sequence"},
		{"--events", "events.jsonl"},
		{"--case", "forged-chunk"},
	} {
		if _, err := config.Parse(arguments); err == nil {
			t.Fatalf("production parsing accepted %v", arguments)
		}
	}
}
