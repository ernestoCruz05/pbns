#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )); then
    printf 'usage: %s OUTPUT_DIR [SERVER_NAME]\n' "$0" >&2
    exit 2
fi
for tool in openssl python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required tool: %s\n' "$tool" >&2
        exit 1
    }
done

SERVER_NAME=${2:-pbns-gateway.test}
server_san=$(
    python3 - "$SERVER_NAME" <<'PY'
import ipaddress
import re
import sys

server_name = sys.argv[1]
try:
    address = ipaddress.ip_address(server_name)
except ValueError:
    label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    labels = server_name.split(".")
    if (
        not server_name
        or len(server_name) > 253
        or any(label.fullmatch(item) is None for item in labels)
    ):
        print("invalid TLS server name", file=sys.stderr)
        raise SystemExit(1)
    print(f"DNS:{server_name}")
else:
    print(f"IP:{address.compressed}")
PY
)

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
OUTPUT_DIR=$1
FIXTURES="$PBNS_ROOT/tests/fixtures/keys"
SOURCE_KEY="$FIXTURES/tls-gateway-test-key.pem"
SOURCE_CERT="$FIXTURES/tls-gateway-test-cert.pem"

mkdir -p -- "$OUTPUT_DIR"
rm -f -- \
    "$OUTPUT_DIR/gateway-cert.pem" \
    "$OUTPUT_DIR/gateway-cert.der" \
    "$OUTPUT_DIR/gateway-reissued-cert.pem" \
    "$OUTPUT_DIR/gateway-reissued-cert.der" \
    "$OUTPUT_DIR/gateway-reissued-cert.csr" \
    "$OUTPUT_DIR/gateway-reissued-cert.ext" \
    "$OUTPUT_DIR/ipv4-cert.der" \
    "$OUTPUT_DIR/ipv4-cert.csr" \
    "$OUTPUT_DIR/ipv4-cert.pem" \
    "$OUTPUT_DIR/ipv4-cert.ext" \
    "$OUTPUT_DIR/ipv6-cert.der" \
    "$OUTPUT_DIR/ipv6-cert.csr" \
    "$OUTPUT_DIR/ipv6-cert.pem" \
    "$OUTPUT_DIR/ipv6-cert.ext" \
    "$OUTPUT_DIR/wrong-san-cert.der" \
    "$OUTPUT_DIR/wrong-san-cert.csr" \
    "$OUTPUT_DIR/wrong-san-cert.pem" \
    "$OUTPUT_DIR/wrong-san-cert.ext" \
    "$OUTPUT_DIR/cn-only-cert.der" \
    "$OUTPUT_DIR/cn-only-cert.csr" \
    "$OUTPUT_DIR/cn-only-cert.pem" \
    "$OUTPUT_DIR/cn-only-cert.ext" \
    "$OUTPUT_DIR/missing-ku-cert.der" \
    "$OUTPUT_DIR/missing-ku-cert.csr" \
    "$OUTPUT_DIR/missing-ku-cert.pem" \
    "$OUTPUT_DIR/missing-ku-cert.ext" \
    "$OUTPUT_DIR/wrong-ku-cert.der" \
    "$OUTPUT_DIR/wrong-ku-cert.csr" \
    "$OUTPUT_DIR/wrong-ku-cert.pem" \
    "$OUTPUT_DIR/wrong-ku-cert.ext" \
    "$OUTPUT_DIR/missing-eku-cert.der" \
    "$OUTPUT_DIR/missing-eku-cert.csr" \
    "$OUTPUT_DIR/missing-eku-cert.pem" \
    "$OUTPUT_DIR/missing-eku-cert.ext" \
    "$OUTPUT_DIR/wrong-eku-cert.der" \
    "$OUTPUT_DIR/wrong-eku-cert.csr" \
    "$OUTPUT_DIR/wrong-eku-cert.pem" \
    "$OUTPUT_DIR/wrong-eku-cert.ext" \
    "$OUTPUT_DIR/ca-true-cert.der" \
    "$OUTPUT_DIR/ca-true-cert.csr" \
    "$OUTPUT_DIR/ca-true-cert.pem" \
    "$OUTPUT_DIR/ca-true-cert.ext" \
    "$OUTPUT_DIR/missing-basic-cert.der" \
    "$OUTPUT_DIR/missing-basic-cert.csr" \
    "$OUTPUT_DIR/missing-basic-cert.pem" \
    "$OUTPUT_DIR/missing-basic-cert.ext" \
    "$OUTPUT_DIR/noncritical-basic-cert.der" \
    "$OUTPUT_DIR/noncritical-basic-cert.csr" \
    "$OUTPUT_DIR/noncritical-basic-cert.pem" \
    "$OUTPUT_DIR/noncritical-basic-cert.ext" \
    "$OUTPUT_DIR/p384-key.pem" \
    "$OUTPUT_DIR/p384.csr" \
    "$OUTPUT_DIR/p384.ext" \
    "$OUTPUT_DIR/p384-cert.pem" \
    "$OUTPUT_DIR/p384-cert.der" \
    "$OUTPUT_DIR/wrong-key.pem" \
    "$OUTPUT_DIR/wrong-key.csr" \
    "$OUTPUT_DIR/wrong-key.ext" \
    "$OUTPUT_DIR/wrong-key-cert.pem" \
    "$OUTPUT_DIR/wrong-key-cert.der" \
    "$OUTPUT_DIR/rsa-key.pem" \
    "$OUTPUT_DIR/rsa.csr" \
    "$OUTPUT_DIR/rsa-cert.pem" \
    "$OUTPUT_DIR/rsa-cert.der" \
    "$OUTPUT_DIR/corrupt-signature-cert.der" \
    "$OUTPUT_DIR/malformed-cert.der"

make_leaf() {
    local output=$1
    local subject=$2
    local extensions=$3
    local serial=$4
    local retain_pem=${5:-no}
    local csr="$OUTPUT_DIR/${output%.der}.csr"
    local pem="$OUTPUT_DIR/${output%.der}.pem"
    local ext="$OUTPUT_DIR/${output%.der}.ext"
    openssl req -new -key "$SOURCE_KEY" -subj "$subject" -out "$csr"
    printf '%s\n' "$extensions" >"$ext"
    openssl x509 -req -in "$csr" -signkey "$SOURCE_KEY" -sha256 -days 3650 \
        -set_serial "$serial" -extfile "$ext" -out "$pem"
    openssl x509 -in "$pem" -outform DER -out "$OUTPUT_DIR/$output"
    rm -f -- "$csr" "$ext"
    if [[ $retain_pem != yes ]]; then
        rm -f -- "$pem"
    fi
}

leaf_extensions() {
    local san=$1
    local basic=$2
    local ku=$3
    local eku=$4
    if [[ -n $basic ]]; then
        printf 'basicConstraints=%s\n' "$basic"
    fi
    if [[ -n $ku ]]; then
        printf 'keyUsage=%s\n' "$ku"
    fi
    if [[ -n $eku ]]; then
        printf 'extendedKeyUsage=%s\n' "$eku"
    fi
    if [[ -n $san ]]; then
        printf 'subjectAltName=%s\n' "$san"
    fi
}

cp -- "$SOURCE_CERT" "$OUTPUT_DIR/gateway-cert.pem"
openssl x509 -in "$SOURCE_CERT" -outform DER -out "$OUTPUT_DIR/gateway-cert.der"

make_leaf gateway-reissued-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions "$server_san" 'critical,CA:FALSE' 'critical,digitalSignature' 'serverAuth')" 0x50424e5302 yes
make_leaf ipv4-cert.der '/CN=192.168.1.180' \
    "$(leaf_extensions 'IP:192.168.1.180' 'critical,CA:FALSE' 'critical,digitalSignature' 'serverAuth')" 0x50424e5303
make_leaf ipv6-cert.der '/CN=2001:db8::180' \
    "$(leaf_extensions 'IP:2001:db8::180' 'critical,CA:FALSE' 'critical,digitalSignature' 'serverAuth')" 0x50424e5304
make_leaf wrong-san-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:other.test' 'critical,CA:FALSE' 'critical,digitalSignature' 'serverAuth')" 0x50424e5305
make_leaf cn-only-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions '' 'critical,CA:FALSE' 'critical,digitalSignature' 'serverAuth')" 0x50424e5306
make_leaf missing-ku-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' 'critical,CA:FALSE' '' 'serverAuth')" 0x50424e5307
make_leaf wrong-ku-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' 'critical,CA:FALSE' 'critical,keyEncipherment' 'serverAuth')" 0x50424e5308
make_leaf missing-eku-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' 'critical,CA:FALSE' 'critical,digitalSignature' '')" 0x50424e5309
make_leaf wrong-eku-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' 'critical,CA:FALSE' 'critical,digitalSignature' 'clientAuth')" 0x50424e530a
make_leaf ca-true-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' 'critical,CA:TRUE' 'critical,digitalSignature' 'serverAuth')" 0x50424e530b
make_leaf missing-basic-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' '' 'critical,digitalSignature' 'serverAuth')" 0x50424e530c
make_leaf noncritical-basic-cert.der '/CN=pbns-gateway.test' \
    "$(leaf_extensions 'DNS:pbns-gateway.test' 'CA:FALSE' 'critical,digitalSignature' 'serverAuth')" 0x50424e5310

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out "$OUTPUT_DIR/p384-key.pem" >/dev/null 2>&1
openssl req -new -key "$OUTPUT_DIR/p384-key.pem" -subj '/CN=pbns-gateway.test' \
    -out "$OUTPUT_DIR/p384.csr"
cat >"$OUTPUT_DIR/p384.ext" <<'EXTENSIONS'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:pbns-gateway.test
EXTENSIONS
openssl x509 -req -in "$OUTPUT_DIR/p384.csr" -signkey "$OUTPUT_DIR/p384-key.pem" \
    -sha256 -days 3650 -set_serial 0x50424e530d -extfile "$OUTPUT_DIR/p384.ext" \
    -out "$OUTPUT_DIR/p384-cert.pem"
openssl x509 -in "$OUTPUT_DIR/p384-cert.pem" -outform DER -out "$OUTPUT_DIR/p384-cert.der"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$OUTPUT_DIR/wrong-key.pem" >/dev/null 2>&1
openssl req -new -key "$OUTPUT_DIR/wrong-key.pem" -subj '/CN=pbns-gateway.test' \
    -out "$OUTPUT_DIR/wrong-key.csr"
cat >"$OUTPUT_DIR/wrong-key.ext" <<EXTENSIONS
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=$server_san
EXTENSIONS
openssl x509 -req -in "$OUTPUT_DIR/wrong-key.csr" -signkey "$OUTPUT_DIR/wrong-key.pem" \
    -sha256 -days 3650 -set_serial 0x50424e530e -extfile "$OUTPUT_DIR/wrong-key.ext" \
    -out "$OUTPUT_DIR/wrong-key-cert.pem"
openssl x509 -in "$OUTPUT_DIR/wrong-key-cert.pem" -outform DER \
    -out "$OUTPUT_DIR/wrong-key-cert.der"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$OUTPUT_DIR/rsa-key.pem" >/dev/null 2>&1
openssl req -new -key "$OUTPUT_DIR/rsa-key.pem" -subj '/CN=pbns-gateway.test' \
    -out "$OUTPUT_DIR/rsa.csr"
openssl x509 -req -in "$OUTPUT_DIR/rsa.csr" -signkey "$OUTPUT_DIR/rsa-key.pem" \
    -sha256 -days 3650 -set_serial 0x50424e530f -extfile "$OUTPUT_DIR/wrong-key.ext" \
    -out "$OUTPUT_DIR/rsa-cert.pem"
openssl x509 -in "$OUTPUT_DIR/rsa-cert.pem" -outform DER -out "$OUTPUT_DIR/rsa-cert.der"

cp -- "$OUTPUT_DIR/gateway-reissued-cert.der" "$OUTPUT_DIR/corrupt-signature-cert.der"
corrupt_size=$(wc -c <"$OUTPUT_DIR/corrupt-signature-cert.der")
last_byte=$(od -An -tu1 -j "$((corrupt_size - 1))" -N 1 \
    "$OUTPUT_DIR/corrupt-signature-cert.der" | tr -d '[:space:]')
printf -v replacement '\\%03o' "$((last_byte ^ 1))"
printf '%b' "$replacement" | dd of="$OUTPUT_DIR/corrupt-signature-cert.der" bs=1 \
    seek="$((corrupt_size - 1))" conv=notrunc status=none
printf '\060\003\001\001' >"$OUTPUT_DIR/malformed-cert.der"
rm -f -- \
    "$OUTPUT_DIR/p384.csr" \
    "$OUTPUT_DIR/p384.ext" \
    "$OUTPUT_DIR/wrong-key.csr" \
    "$OUTPUT_DIR/wrong-key.ext" \
    "$OUTPUT_DIR/rsa.csr" \
    "$OUTPUT_DIR/p384-cert.pem" \
    "$OUTPUT_DIR/rsa-cert.pem"
chmod 600 -- \
    "$OUTPUT_DIR/p384-key.pem" \
    "$OUTPUT_DIR/wrong-key.pem" \
    "$OUTPUT_DIR/rsa-key.pem"
printf 'TLS TEST PKI READY %s\n' "$OUTPUT_DIR"
