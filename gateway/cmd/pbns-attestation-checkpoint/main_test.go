package main

import (
	"bytes"
	"testing"
)

func TestRunRequiresExactlyOneCheckpointOutput(t *testing.T) {
	for name, arguments := range map[string][]string{
		"neither": {},
		"both":    {"--candidate-output", "/tmp/candidate", "--receipt-output", "/tmp/receipt"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if status := run(arguments, &stdout, &stderr); status != 2 {
				t.Fatalf("status=%d stderr=%s", status, stderr.String())
			}
		})
	}
}
