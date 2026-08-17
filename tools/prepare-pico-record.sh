#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
PRIVATE_DIR="$HOME/.pbns-provision"
RECORD="$PRIVATE_DIR/credentials.cbor"
PIN="${PBNS_PIN:-$PBNS_ROOT/deployment/hardware/spki.sha256}"
if [[ ! -f $PIN ]]; then
    PIN="$PBNS_ROOT/tests/fixtures/keys/tls-gateway-test-spki.sha256"
fi
VALIDATOR="$PBNS_ROOT/build/dev/pbns-pico-record-validate"
SSID_FILE="$PRIVATE_DIR/ssid.bin"
PSK_FILE="$PRIVATE_DIR/psk.bin"
RUN_DIR=
SOURCE_MODE=
SSID=
PSK=
GATEWAY_HOST=
FINAL_CREATED=false
umask 077

cleanup() {
    local status=$?
    SSID=
    PSK=
    GATEWAY_HOST=
    unset SSID PSK GATEWAY_HOST
    if [[ -n $RUN_DIR ]]; then
        rm -rf -- "$RUN_DIR"
    fi
    if (( status != 0 )) && [[ $FINAL_CREATED == true ]]; then
        rm -f -- "$RECORD"
    fi
    return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if (( $# != 0 )); then
    printf 'usage: %s\n' "$0" >&2
    exit 2
fi

for tool in chmod go install ln mktemp python3 rm stat; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required record-preparation tool: %s\n' "$tool" >&2
        exit 1
    }
done
if [[ ! -f $PIN ]]; then
    printf '%s\n' 'missing pinned gateway SPKI file' >&2
    exit 1
fi
if [[ ! -x $VALIDATOR ]]; then
    printf '%s\n' 'missing Pico C validator; run the software-only transport gate first' >&2
    exit 1
fi
if [[ -L $PRIVATE_DIR ]]; then
    printf '%s\n' 'private credential directory must not be a symbolic link' >&2
    exit 1
fi
install -d -m 0700 -- "$PRIVATE_DIR"
if [[ $(stat -c '%F' -- "$PRIVATE_DIR") != directory ]] ||
   [[ $(stat -c '%a' -- "$PRIVATE_DIR") != 700 ]]; then
    printf '%s\n' 'private credential directory must be a mode-0700 directory' >&2
    exit 1
fi
if [[ -e $RECORD || -L $RECORD ]]; then
    printf '%s\n' 'credential output already exists; refusing to overwrite it' >&2
    exit 1
fi

if [[ (-e $SSID_FILE || -L $SSID_FILE) &&
      (-e $PSK_FILE || -L $PSK_FILE) ]]; then
    SOURCE_MODE=existing
    for private_input in "$SSID_FILE" "$PSK_FILE"; do
        if [[ ! -f $private_input || -L $private_input ]] ||
           [[ $(stat -c '%F' -- "$private_input") != 'regular file' ]] ||
           [[ $(stat -c '%a' -- "$private_input") != 600 ]]; then
            printf '%s\n' 'SSID and PSK inputs must be non-symlink mode-0600 regular files' >&2
            exit 1
        fi
    done
elif [[ ! -e $SSID_FILE && ! -L $SSID_FILE &&
        ! -e $PSK_FILE && ! -L $PSK_FILE ]]; then
    SOURCE_MODE=prompt
    printf '%s' '2.4 GHz SSID: ' >&2
    if ! IFS= read -r SSID; then
        printf '\n%s\n' 'cannot read SSID from the local terminal' >&2
        exit 1
    fi
    printf '%s' 'WiFi PSK: ' >&2
    if ! IFS= read -r -s PSK; then
        printf '\n%s\n' 'cannot read WiFi PSK from the local terminal' >&2
        exit 1
    fi
    printf '\n' >&2
else
    printf '%s\n' 'SSID and PSK inputs must either both exist or both be absent' >&2
    exit 1
fi

printf '%s' 'Gateway LAN IPv4: ' >&2
if ! IFS= read -r GATEWAY_HOST; then
    printf '\n%s\n' 'cannot read gateway IPv4 from the local terminal' >&2
    exit 1
fi
if ! python3 - "$GATEWAY_HOST" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
if (
    address.version != 4
    or address.is_unspecified
    or address.is_multicast
    or address.is_loopback
    or address.is_link_local
):
    raise SystemExit(1)
PY
then
    printf '%s\n' 'gateway address must be a non-loopback LAN IPv4 address' >&2
    exit 1
fi

RUN_DIR=$(mktemp -d "$PRIVATE_DIR/.prepare.XXXXXX")
chmod 0700 -- "$RUN_DIR"
STAGED_RECORD="$RUN_DIR/credentials.cbor"
if [[ $SOURCE_MODE == prompt ]]; then
    SSID_FILE="$RUN_DIR/ssid.bin"
    PSK_FILE="$RUN_DIR/psk.bin"
    printf '%s' "$SSID" >"$SSID_FILE"
    printf '%s' "$PSK" >"$PSK_FILE"
    chmod 0600 -- "$SSID_FILE" "$PSK_FILE"
    SSID=
    PSK=
    unset SSID PSK
fi

(
    cd -- "$PBNS_ROOT/gateway"
    go run -mod=readonly ./cmd/pbns-pico-record \
        --ssid-file "$SSID_FILE" \
        --psk-file "$PSK_FILE" \
        --host "$GATEWAY_HOST" \
        --port 8443 \
        --spki-sha256-file "$PIN" \
        --output "$STAGED_RECORD"
)
"$VALIDATOR" "$STAGED_RECORD" "$PIN"
if [[ $(stat -c '%F' -- "$STAGED_RECORD") != 'regular file' ]] ||
   [[ $(stat -c '%a' -- "$STAGED_RECORD") != 600 ]]; then
    printf '%s\n' 'generated credential record has invalid type or permissions' >&2
    exit 1
fi
ln -- "$STAGED_RECORD" "$RECORD"
FINAL_CREATED=true
if [[ $(stat -c '%F' -- "$RECORD") != 'regular file' ]] ||
   [[ $(stat -c '%a' -- "$RECORD") != 600 ]]; then
    printf '%s\n' 'published credential record has invalid type or permissions' >&2
    exit 1
fi
if [[ $SOURCE_MODE == existing ]]; then
    rm -f -- "$SSID_FILE" "$PSK_FILE"
    if [[ -e $SSID_FILE || -L $SSID_FILE || -e $PSK_FILE || -L $PSK_FILE ]]; then
        printf '%s\n' 'cannot remove private SSID/PSK inputs after publication' >&2
        exit 1
    fi
fi
printf 'PBNS PICO RECORD READY %s\n' "$RECORD"
printf '%s\n' 'Next: hold BOOTSEL for 2 seconds while PBNS is running; do not open CDC1.'
