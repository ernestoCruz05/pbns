#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
GATEWAY_DIR="$PBNS_ROOT/gateway"
HARDWARE_DIR="$PBNS_ROOT/deployment/hardware"
DATA_DIR="$HOME/.pbns"

SERVER_IP="${1:-192.168.1.73}"
PORT="${2:-8443}"

# Reset write permissions in case files were marked read-only previously
if [[ -d "$DATA_DIR" ]]; then
    chmod -R u+rwX "$DATA_DIR" 2>/dev/null || true
fi

mkdir -p "$DATA_DIR/deployment" "$DATA_DIR/enrollment"
chmod 700 "$DATA_DIR" "$DATA_DIR/deployment" "$DATA_DIR/enrollment"

echo "=== PBNS Gateway Setup ==="
if [[ -d "$HARDWARE_DIR" && -f "$HARDWARE_DIR/deployment.cbor" ]]; then
    echo "[*] Loading unified hardware deployment keys..."
    cp -f "$HARDWARE_DIR"/* "$DATA_DIR/deployment/" 2>/dev/null || true
    cp -f "$HARDWARE_DIR"/enrollment* "$DATA_DIR/enrollment/" 2>/dev/null || true
    if [[ -f "$HARDWARE_DIR/enrollment.db" && ! -f "$DATA_DIR/enrollment.db" ]]; then
        cp -f "$HARDWARE_DIR/enrollment.db" "$DATA_DIR/enrollment.db"
    fi
fi

# Set exact permissions required by PBNS secure file loaders:
# - Directories: 0700
# - Private keys and database: 0600
# - Public trust bundles and pins: 0444
chmod 700 "$DATA_DIR" "$DATA_DIR/deployment" "$DATA_DIR/enrollment"
chmod 600 "$DATA_DIR/deployment"/*.pem "$DATA_DIR/enrollment"/*.pem 2>/dev/null || true
chmod 600 "$DATA_DIR"/*.db "$DATA_DIR/deployment"/*.db "$DATA_DIR/enrollment"/*.db 2>/dev/null || true
chmod 444 "$DATA_DIR/deployment"/*.cbor "$DATA_DIR/deployment"/*.sha256 "$DATA_DIR/enrollment"/*.cbor 2>/dev/null || true

# Pre-generate a 24-hour enrollment token if database is available
cd "$GATEWAY_DIR"
TOKEN_OUTPUT=$(go run ./cmd/pbnsctl --db "$DATA_DIR/enrollment.db" enrollment create --ttl 24h 2>/dev/null || true)
if [[ -n "$TOKEN_OUTPUT" ]]; then
    echo "========================================================="
    echo "[*] Active Enrollment Token for PBNS Clients:"
    echo "$TOKEN_OUTPUT"
    echo "========================================================="
fi

if [[ ! -f "$PBNS_ROOT/build/dev/cose-c/install/include/cn-cbor/cn-cbor.h" ]]; then
    if [[ ! -d "$PBNS_ROOT/.deps/pico_sdk" ]]; then
        echo "[*] Fetching pinned Pico SDK for crypto headers..."
        bash "$SCRIPT_DIR/bootstrap.sh" --fetch-external pico_sdk
    fi
    echo "[*] Building native COSE bridge dependencies (cmake)..."
    cmake -S "$PBNS_ROOT" -B "$PBNS_ROOT/build/dev" -G Ninja
    cmake --build "$PBNS_ROOT/build/dev" --target pbns-cose-c-external -j2
fi

echo "[*] Building PBNS Gateway..."
cd "$GATEWAY_DIR"
go build -o ./pbns-gateway ./cmd/pbns-gateway

echo "[*] Starting PBNS Gateway on 0.0.0.0:$PORT (TLS SAN: $SERVER_IP) ..."
exec ./pbns-gateway \
    --listen "0.0.0.0:$PORT" \
    --tls-cert "$DATA_DIR/deployment/tls-cert.pem" \
    --tls-key "$DATA_DIR/deployment/tls-key.pem" \
    --enrollment-store "$DATA_DIR/enrollment.db" \
    --enrollment-bundle "$DATA_DIR/deployment/enrollment.cbor" \
    --enrollment-recipient-key "$DATA_DIR/deployment/enrollment-recipient-key.pem" \
    --enrollment-recipient-kid "pbns-enrollment-recipient-v1" \
    --enrollment-signing-key "$DATA_DIR/deployment/enrollment-signer-key.pem" \
    --enrollment-signing-kid "pbns-enrollment-signer-v1" \
    --deployment-bundle "$DATA_DIR/deployment/deployment.cbor" \
    --attestation-recipient-key "$DATA_DIR/deployment/recipient-key.pem" \
    --attestation-recipient-kid "pbns-recipient-v1" \
    --attestation-signing-key "$DATA_DIR/deployment/challenge-key.pem" \
    --attestation-signing-kid "pbns-challenge-v1" \
    --attestation-receipt-signing-key "$DATA_DIR/deployment/receipt-key.pem" \
    --attestation-receipt-signing-kid "pbns-receipt-v1" \
    --time-signing-key "$DATA_DIR/deployment/time-key.pem" \
    --time-signing-kid "pbns-time-v1" \
    --time-uncertainty 0s \
    --time-quality checkpoint
