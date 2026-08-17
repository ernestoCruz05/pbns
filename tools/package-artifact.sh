#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PBNS_ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd -P)
DIST_DIR="$PBNS_ROOT/dist"
ARTIFACT_NAME="pbns-usenix27-artifact"
TARBALL="$DIST_DIR/${ARTIFACT_NAME}.tar.gz"

printf '[*] Preparing artifact distribution directory...\n'
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

STAGE_DIR=$(mktemp -d "$DIST_DIR/stage.XXXXXXXX")
trap 'rm -rf "$STAGE_DIR"' EXIT

TARGET_DIR="$STAGE_DIR/$ARTIFACT_NAME"
mkdir -p "$TARGET_DIR"

printf '[*] Copying anonymous source, evaluation, and documentation trees...\n'
cp -a "$PBNS_ROOT/CMakeLists.txt" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/PbnsPkg.dec" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/PbnsPkg.dsc" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/README.md" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/LICENSE" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/LICENSES" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/dependencies.lock" "$TARGET_DIR/"
cp -a "$PBNS_ROOT/.gitignore" "$TARGET_DIR/"

for dir in cmake docs eval gateway include integration patches pico protocol src tests tools uefi vendor; do
    if [[ -d "$PBNS_ROOT/$dir" ]]; then
        cp -a "$PBNS_ROOT/$dir" "$TARGET_DIR/"
    fi
done

# Prune build artifacts and test cache from the stage package
find "$TARGET_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$TARGET_DIR" -type d -name ".deps" -exec rm -rf {} + 2>/dev/null || true
find "$TARGET_DIR" -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
find "$TARGET_DIR" -type d -name "build-*" -exec rm -rf {} + 2>/dev/null || true
rm -rf "$TARGET_DIR/integration/state" 2>/dev/null || true
rm -rf "$TARGET_DIR/pico/build" "$TARGET_DIR/pico/build-raw-diagnostic" 2>/dev/null || true

printf '[*] Creating deterministic tarball %s...\n' "$TARBALL"
(
    cd "$STAGE_DIR"
    tar --sort=name \
        --mtime='2026-08-14 00:00:00 UTC' \
        --owner=0 --group=0 --numeric-owner \
        -czf "$TARBALL" "$ARTIFACT_NAME"
)

printf '[*] Generating SHA256 checksums...\n'
(
    cd "$DIST_DIR"
    sha256sum "$(basename "$TARBALL")" > SHA256SUMS
)

printf '\n============================================================\n'
printf '  [PASS] Artifact Package Created Successfully\n'
printf '  Tarball:  %s\n' "$TARBALL"
printf '  Size:     %s\n' "$(du -h "$TARBALL" | cut -f1)"
printf '  SHA256:   %s\n' "$(cat "$DIST_DIR/SHA256SUMS" | awk '{print $1}')"
printf '============================================================\n\n'
