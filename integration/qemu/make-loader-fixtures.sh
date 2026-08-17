#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
PBNS_EDK2_DIR=${PBNS_EDK2_DIR:-$PBNS_ROOT/.deps/edk2}
PBNS_BUILD_TARGET=${PBNS_BUILD_TARGET:-DEBUG}

if [[ $PBNS_BUILD_TARGET != DEBUG && $PBNS_BUILD_TARGET != RELEASE ]]; then
    printf 'unsupported fixture build target: %s\n' "$PBNS_BUILD_TARGET" >&2
    exit 2
fi
for tool in openssl python3 sbsign sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing loader-fixture tool: %s\n' "$tool" >&2
        exit 1
    }
done
PBNS_EDK2_DIR=$(cd -- "$PBNS_EDK2_DIR" && pwd -P)
BUILD_ROOT="$PBNS_EDK2_DIR/Build/PbnsPkg/${PBNS_BUILD_TARGET}_GCC/X64"
RETURN_ERROR="$BUILD_ROOT/ReturnError.efi"
RETURN_SUCCESS="$BUILD_ROOT/ReturnSuccess.efi"
TRUNCATE="$PBNS_ROOT/uefi/Tests/Fixtures/Truncated/make-truncated.py"
KEY_SOURCE="$PBNS_ROOT/tests/fixtures/keys/uki-secureboot-test-key.pem"
CERT_SOURCE="$PBNS_ROOT/tests/fixtures/keys/uki-secureboot-test-cert.pem"
for input in "$RETURN_ERROR" "$RETURN_SUCCESS" "$TRUNCATE" "$KEY_SOURCE" "$CERT_SOURCE"; do
    [[ -f $input ]] || {
        printf 'missing loader-fixture input: %s\n' "$input" >&2
        exit 1
    }
done

FIXTURE_PARENT="$PBNS_ROOT/integration/state/fixtures"
FIXTURE_ROOT="$FIXTURE_PARENT/loader-v1"
mkdir -p -- "$FIXTURE_PARENT"
chmod 0700 "$FIXTURE_PARENT"
RUN_DIR=$(mktemp -d "$FIXTURE_PARENT/loader-v1.tmp.XXXXXX")
chmod 0700 "$RUN_DIR"
cleanup() {
    if [[ -n ${RUN_DIR:-} && -d $RUN_DIR ]]; then
        rm -rf -- "$RUN_DIR"
    fi
}
trap cleanup EXIT INT TERM

for name in missing truncated untrusted return-error return-success; do
    mkdir -m 0700 -- "$RUN_DIR/$name"
done
cp -- "$RETURN_ERROR" "$RUN_DIR/return-error/loader.efi"
cp -- "$RETURN_SUCCESS" "$RUN_DIR/return-success/loader.efi"
python3 "$TRUNCATE" "$RETURN_SUCCESS" "$RUN_DIR/truncated/loader.efi"

PRIVATE_DIR="$RUN_DIR/private"
mkdir -m 0700 -- "$PRIVATE_DIR"
cp -- "$KEY_SOURCE" "$PRIVATE_DIR/image-key.pem"
cp -- "$CERT_SOURCE" "$PRIVATE_DIR/image-cert.pem"
chmod 0600 "$PRIVATE_DIR/image-key.pem" "$PRIVATE_DIR/image-cert.pem"
sbsign \
    --key "$PRIVATE_DIR/image-key.pem" \
    --cert "$PRIVATE_DIR/image-cert.pem" \
    --output "$RUN_DIR/untrusted/loader.efi" \
    "$RETURN_SUCCESS" >"$PRIVATE_DIR/sbsign.log" 2>&1
rm -rf -- "$PRIVATE_DIR"
find "$RUN_DIR" -type f -exec chmod 0600 {} +

python3 - "$RUN_DIR" "$CERT_SOURCE" <<'PY'
import hashlib
import json
import pathlib
import ssl
import sys

root = pathlib.Path(sys.argv[1])
certificate = pathlib.Path(sys.argv[2])
der = ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
signer_fingerprint = hashlib.sha256(der).hexdigest()
fixtures = {}
for name, expected in (
    ("missing", "load-image-not-found"),
    ("truncated", "load-image-rejected"),
    ("untrusted", "secure-boot-rejected"),
    ("return-error", "start-image-error"),
    ("return-success", "unexpected-start-image-return"),
):
    image = root / name / "loader.efi"
    relative = f"{name}/loader.efi" if image.exists() else None
    fixtures[name] = {
        "directory": name,
        "expected": expected,
        "image": relative,
        "sha256": hashlib.sha256(image.read_bytes()).hexdigest() if image.exists() else None,
    }
fixtures["untrusted"]["signer_certificate_sha256"] = signer_fingerprint
manifest = {"schema": "pbns-loader-fixtures-v1", "fixtures": fixtures}
path = root / "manifest.json"
path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
(
    cd -- "$RUN_DIR"
    sha256sum \
        truncated/loader.efi \
        untrusted/loader.efi \
        return-error/loader.efi \
        return-success/loader.efi >SHA256SUMS
    chmod 0600 SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)

rm -rf -- "$FIXTURE_ROOT"
mv -- "$RUN_DIR" "$FIXTURE_ROOT"
RUN_DIR=
printf '[PASS] %s\n' "$FIXTURE_ROOT/manifest.json"
printf '[PASS] %s\n' "$FIXTURE_ROOT/SHA256SUMS"
printf '%s\n' 'FIXTURES PASS'
