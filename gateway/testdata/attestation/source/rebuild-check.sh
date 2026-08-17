#!/bin/sh
# Rebuild without consulting expected fixture outputs, then compare every byte.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/pbns-attestation-fixture.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
(cd "$root/../.." && go run ./cmd/pbns-attestation-fixturegen -source "$root/source" -out "$tmp")
cmp "$tmp/valid-swtpm-evidence.cbor" "$root/valid-swtpm-evidence.cbor"
for f in eventlog.bin extend-digests.hex pcrvals.hex qual.hex; do cmp "$tmp/$f" "$root/expected/$f"; done
for f in "$root"/invalid/*; do cmp "$tmp/invalid/$(basename "$f")" "$f"; done
(cd "$root" && sha256sum -c SHA256SUMS)
