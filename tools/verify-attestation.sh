#!/usr/bin/env bash
set -euo pipefail
umask 077
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$script_dir/verify_attestation.py" "$@"
