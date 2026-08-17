# PBNS: Secure Wi-Fi-Backed Pre-Boot Services without Native UEFI Wireless Support
## USENIX Security Artifact Reproduction Package

PBNS enables secure wireless pre-boot services (authenticated time, RAM-only UKI recovery, and TPM 2.0 attestation) on commodity computing platforms without native UEFI wireless support. A low-cost microcontroller (Raspberry Pi Pico W) offloads 802.11 association, DHCP, and TCP streaming over standard USB CDC-ACM, while host UEFI retains TLS termination, immutable SPKI pinning, canonical CBOR/COSE object validation, and independent Secure Boot execution policy.

---

## 1. Repository Structure

```
.
├── CMakeLists.txt              # Top-level CMake build definition for host C core
├── PbnsPkg.dec                 # EDK II package declaration
├── PbnsPkg.dsc                 # EDK II package description
├── dependencies.lock           # Cryptographic lockfile for all external dependencies
├── LICENSE                     # Top-level BSD-3-Clause license
├── LICENSES/                   # License texts for PBNS and third-party dependencies
├── cmake/                      # CMake toolchain modules and compiler flag policies
├── docs/                       # Architectural specifications and hardware documentation
│   └── hardware/               # BM-1 bare-metal specs, Pico provisioning, and diagnostics
├── eval/                       # Evaluation datasets, raw trials, and analysis scripts
│   ├── raw/                    # Raw empirical trial logs (performance, attacks, fuzzing, BM-1)
│   │   ├── performance/        # 100-trial benchmark JSONL files & resource metrics
│   │   ├── adversarial/        # 22-case attack evaluation records
│   │   ├── fuzzing/            # 120 CPU-hour fuzzer logs & summary
│   │   └── bare-metal/         # Physical BM-1 platform logs & 30 absent-boot trials
│   ├── analysis/               # Analysis scripts deriving LaTeX tables from raw records
│   ├── runners/                # Benchmark and attack suite execution runners
│   ├── sources/                # Systematic comparative evidence
│   └── generated/              # Auto-generated LaTeX tables included in paper
├── gateway/                    # Reference Go gateway service (TLS & COSE endpoints)
├── include/                    # Portable C17 header definitions
├── integration/                # HIL, QEMU, TLS replay, and security test harnesses
├── patches/                    # Upstream EDK II and library patches
├── pico/                       # Pico SDK C firmware for Raspberry Pi Pico W bridge
├── protocol/                   # Canonical protocol message definitions
├── recovery/                   # Streaming UKI recovery client and manifest validators
├── src/                        # Portable C17 host core implementation
├── tests/                      # Unit, property, and mock-adapter test suites
├── tools/                      # Build, verification, audit, and benchmark scripts
├── uefi/                       # EDK II UEFI application entry points and drivers
└── vendor/                     # Vendored cryptographic and serialization libraries
```

---

## 2. Hardware and Environment Requirements

The evaluation is structured across two complementary testbeds:

1. **Hardware-in-the-Loop (HIL) Testbed (Reviewer reproduction without bare-metal risk):**
   - **Host:** Linux x86-64 system with QEMU, KVM hardware acceleration (`-enable-kvm`), OVMF firmware, and `swtpm` v0.9.0 (TPM 2.0 emulator).
   - **Bridge:** Physical Raspberry Pi Pico W (RP2040 + CYW43439) attached via USB passthrough, operating on 802.11n (2.4 GHz, WPA2-PSK).
   - **Gateway:** Linux host running the reference PBNS Go gateway over TLS 1.2.

2. **Bare-Metal Platform (BM-1):**
   - **Host:** Physical x86-64 workstation with AMD processor, AMI Aptio V UEFI 2.7+ firmware, integrated AMD Platform Firmware TPM 2.0 (fTPM), xHCI USB controller, and active UEFI Secure Boot.
   - **Wireless:** No native firmware Wi-Fi stack (`EFI_SIMPLE_NETWORK_PROTOCOL` absent); wireless connectivity is exclusively provided via PBNS USB bridge.

---

## 3. Quick Start & Software Build

### 3.1 Prerequisites
Ensure the following tools are installed:
- `gcc`, `clang`, `cmake` (>= 3.25), `ninja-build`
- `python3` (>= 3.10), `nasm`, `uuid-dev`, `libssl-dev`
- `go` (>= 1.22), `swtpm`, `qemu-system-x86_64`

### 3.2 Host Core Build and Unit Tests
```bash
# Fetch and verify pinned external dependencies (Pico SDK submodules)
./tools/bootstrap.sh --fetch-external pico_sdk

# Verify environment and external dependency lock
python3 tools/check_dependencies.py

# Build portable core and test suite
cmake -S . -B build/dev -G Ninja -DPBNS_WERROR=ON
ninja -C build/dev

# Run unit and integration tests (100% pass rate, 71 tests)
ctest --test-dir build/dev --output-on-failure

# Build and run with AddressSanitizer and UndefinedBehaviorSanitizer
cmake -S . -B build/asan -G Ninja -DPBNS_SANITIZE="address,undefined" -DPBNS_WERROR=ON
ninja -C build/asan
ctest --test-dir build/asan --output-on-failure
```

### 3.3 Gateway Build and Tests
```bash
cd gateway
go test ./...
cd ..
```

---

## 4. Reproducing Evaluation Results

The artifact derives all empirical tables in the manuscript directly from raw timestamped observation records:

### 4.1 Reproducing Performance Tables (RQ2 — Latency & Resources)
Calculates exact medians, IQRs, minimums, maximums, and 95th percentiles across 100 trials ($N=30$ for recovery stream) and derives LaTeX tables:
```bash
python3 eval/analysis/rq2.py
# Outputs:
#   eval/generated/rq2-latency.tex
#   eval/generated/rq2-resources.tex
```

### 4.2 Reproducing Security Tables (RQ3 — Attacks & Fuzzing)
Validates the 22 adversarial attack and fault specifications (asserting passing coverage across both threat tiers) and parses the 120.0 CPU-hour fuzzer logs:
```bash
python3 eval/analysis/rq3.py
# Outputs:
#   eval/generated/rq3-attacks.tex
#   eval/generated/rq3-fuzz.tex
```

### 4.3 Reproducing Architectural Comparison & Feasibility (RQ1 & RQ4)
Verifies physical HIL and bare-metal execution invariants and generates comparison tables:
```bash
python3 eval/analysis/rq4.py
# Outputs:
#   eval/generated/rq4-comparison.tex
#   eval/generated/rq1-summary.tex
```

### 4.4 Live Execution of Adversarial Attack & Fault Injection Suite
To run the compiled suites covering the 22 evaluated attack and fault specifications directly against compiled C core binaries and verify fail-closed rejection with live timing and hashing:
```bash
python3 integration/security/run_attack_suite.py
```

---

## 5. Artifact Packaging & Verification

To verify the integrity and produce a clean distribution archive:
```bash
./tools/package-artifact.sh
# Verifies clean-room structure and outputs dist/pbns-usenix27-artifact.tar.gz
```

---

## 6. License

PBNS is open source software released under the **BSD-3-Clause License** ([`LICENSE`](LICENSE)). Third-party dependencies are governed by their respective upstream open-source licenses preserved in [`LICENSES/`](LICENSES/) and [`dependencies.lock`](dependencies.lock).
