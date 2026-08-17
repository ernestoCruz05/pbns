package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"strings"

	"pbns.local/gateway/internal/baseline"
)

func main() {
	output := flag.String("output", "", "generated C include")
	provenance := flag.String("provenance", "", "vector provenance")
	flag.Parse()
	if *output == "" || *provenance == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "generate_controlled requires --output and --provenance")
		os.Exit(2)
	}
	controlled := baseline.Controlled{
		Record: baseline.Record{
			Version:           1,
			MeasurementDigest: sha256.Sum256([]byte("measured")),
			SecureBoot:        true,
			SetupMode:         false,
			DBDigest:          sha256.Sum256([]byte("db")),
			DBXDigest:         sha256.Sum256([]byte("dbx")),
			FirmwareDigest:    baseline.FirmwareIdentity("vendor", "1"),
			Inventory: baseline.InventoryRule{
				MemoryMiBDelta:   128,
				StorageGiBDelta:  4,
				BlockDeviceDelta: 1,
			},
		},
		MemoryMiB:    4096,
		StorageGiB:   64,
		BlockDevices: 1,
	}
	encoded, err := baseline.Encode(controlled)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	content := "/* Gerado pelo codificador Go canónico; não editar. */\n" +
		cArray("controlled_baseline_measurement_digest", controlled.Record.MeasurementDigest[:]) +
		cArray("controlled_baseline_db_digest", controlled.Record.DBDigest[:]) +
		cArray("controlled_baseline_dbx_digest", controlled.Record.DBXDigest[:]) +
		cArray("controlled_baseline_firmware_digest", controlled.Record.FirmwareDigest[:]) +
		cArray("controlled_baseline_vector", encoded)
	content = strings.TrimRight(content, "\n") + "\n"
	if err := os.WriteFile(*output, []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	digest := sha256.Sum256(encoded)
	proof := fmt.Sprintf("generator: pbns/gateway/internal/baseline/testdata/generate_controlled.go\nrebuild: (cd pbns/gateway && go run ./internal/baseline/testdata/generate_controlled.go --output ../tests/vectors/controlled-baseline-v1/controlled_baseline.inc --provenance ../tests/vectors/controlled-baseline-v1/provenance.txt)\nencoder: github.com/fxamacker/cbor/v2 v2.9.2 canonical\nvector-sha256: %x\n", digest)
	if err := os.WriteFile(*provenance, []byte(proof), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func cArray(name string, value []byte) string {
	var result strings.Builder
	fmt.Fprintf(&result, "static const uint8_t %s[%d] = {\n", name, len(value))
	for offset := 0; offset < len(value); offset += 12 {
		end := offset + 12
		if end > len(value) {
			end = len(value)
		}
		result.WriteString("    ")
		for index := offset; index < end; index++ {
			fmt.Fprintf(&result, "0x%02xU,", value[index])
			if index+1 < end {
				result.WriteByte(' ')
			}
		}
		result.WriteByte('\n')
	}
	result.WriteString("};\n\n")
	return result.String()
}
