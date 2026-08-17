# TPM attestation fixtures

This is a reproducible, privacy-safe Task 5 fixture. All metadata labels and
event literals are synthetic. No device, network, account, filesystem, or
location identifier is present.

## Source, outputs, and verification

`source/metadata.json` is the one strict, human-reviewable declarative source
for protocol/context/challenge, inventory/baseline/host fields, PCR selection,
and ordered literal TCG2 events. It contains no completed CBOR, event-log,
PCR, qualifying-data, or corpus bytes. The only opaque public cryptographic
inputs are `ak.pub`, `ak.name`, `quote.bin`, `signature.bin`, and the independent
RSA profile-rejection public artifact `ak-rsa.pub`.

`expected/` and `invalid/` are generated outputs, never generator inputs. Run
from any working directory:

```sh
/path/to/pbns/gateway/testdata/attestation/source/rebuild-check.sh
```

The script creates a private temporary output, invokes the generator with a
separate source/output path, byte-compares valid evidence, all expected
components, and every invalid corpus output, verifies the complete manifest,
and cleans up with a trap. The manifest test rejects unlisted regular files;
only `SHA256SUMS` is excluded because a file cannot hash itself. NUL transport
protects the shell manifest pipeline, while PBNS fixture paths are deliberately
whitespace- and backslash-free for the line-oriented Go verifier.

No private AK or swtpm state is checked in. Fresh fixture production therefore
requires the recipe below; `rm -rf` removes the temporary state available to
the user but cannot promise physical-media secure erasure.

## Exact fresh-fixture recipe

The checked-in fixture used `swtpm 0.9.0`, `tpm2-tools 5.7`, and `tpm2-tss
4.1.3`; Go dependencies are pinned by `go.mod`. Run every command below from
`pbns/gateway` in a clean review worktree.

```sh
set -eu
umask 077
w=$(mktemp -d)
install -d -m 0700 "$w/state" "$w/source" "$w/prequote" "$w/generated"
started=0
cleanup() {
  trap - EXIT HUP INT TERM
  status=0
  if [ "$started" -eq 1 ]; then
    if [ ! -r "$w/swtpm.pid" ]; then
      printf '%s\n' 'missing swtpm pid file; retaining state for diagnosis' >&2
      return 1
    fi
    pid=$(cat "$w/swtpm.pid" 2>/dev/null || :)
    case "$pid" in
      ''|*[!0-9]*) printf '%s\n' 'invalid swtpm pid; retaining state for diagnosis' >&2; return 1 ;;
    esac
    if ! [ "$pid" -gt 1 ] 2>/dev/null; then
      printf '%s\n' 'unsafe swtpm pid; retaining state for diagnosis' >&2
      return 1
    fi
    kill -TERM "$pid" 2>/dev/null || :
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || :
      i=0
      while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
    fi
    if kill -0 "$pid" 2>/dev/null; then
      printf '%s\n' 'swtpm still live; retaining state for diagnosis' >&2
      status=1
    fi
  fi
  if [ "$status" -eq 0 ]; then rm -rf "$w"; fi
  return "$status"
}
on_signal() { cleanup; exit 1; }
trap 'cleanup' EXIT
trap 'on_signal' HUP INT TERM
# Treat startup as active before daemonization. A failed launch without a safe
# pid file therefore retains private state rather than deleting it unchecked.
started=1
swtpm socket --tpm2 --tpmstate dir="$w/state" \
  --ctrl type=unixio,path="$w/tpm.sock.ctrl" \
  --server type=unixio,path="$w/tpm.sock" --pid file="$w/swtpm.pid" \
  --flags not-need-init --daemon
export TPM2TOOLS_TCTI="swtpm:path=$w/tpm.sock"
tpm2_startup -c
tpm2_createek -c "$w/ek.ctx" -G ecc
tpm2_createak -C "$w/ek.ctx" -G ecc -g sha256 -s ecdsa \
  -c "$w/ak.ctx" -u "$w/ak.pub" -n "$w/ak.name"
tpm2_flushcontext 0x80000000
# Separate genuine public RSA signing AK for closed-profile rejection.
tpm2_createek -c "$w/rsa-ek.ctx" -G rsa
tpm2_createak -C "$w/rsa-ek.ctx" -G rsa -g sha256 -s rsassa \
  -c "$w/rsa-ak.ctx" -u "$w/ak-rsa.pub" -n "$w/ak-rsa.name"
# Copy only declared non-secret source input; no expected output is copied in.
install -m 0644 testdata/attestation/source/metadata.json "$w/source/metadata.json"
install -m 0644 "$w/ak.pub" "$w/ak.name" "$w/ak-rsa.pub" "$w/source/"
go run ./cmd/pbns-attestation-fixturegen -prepare \
  -source "$w/source" -out "$w/prequote"
# Extend exactly the generated SHA-256 event digests, then quote the generated
# Task 3 qualifying digest and add the two resulting public artifacts.
while IFS=: read -r pcr digest; do
  tpm2_pcrextend "$pcr":sha256="$digest"
done < "$w/prequote/extend-digests.hex"
tpm2_quote -c "$w/ak.ctx" -l sha256:0,2,4,7 \
  -q "$(tr -d '\n' < "$w/prequote/qual.hex")" \
  -m "$w/source/quote.bin" -s "$w/source/signature.bin" \
  -o "$w/quoted-pcrs.bin"
go run ./cmd/pbns-attestation-fixturegen -source "$w/source" -out "$w/generated"
```

Install exactly the generated/public artifacts and regenerate the stable
manifest (this is intentionally explicit so review sees every destination):

```sh
install -m 0644 "$w/source/ak.pub" "$w/source/ak.name" \
  "$w/source/ak-rsa.pub" "$w/source/quote.bin" "$w/source/signature.bin" \
  testdata/attestation/source/
install -m 0644 "$w/generated/valid-swtpm-evidence.cbor" \
  testdata/attestation/valid-swtpm-evidence.cbor
install -m 0644 "$w/generated/eventlog.bin" "$w/generated/extend-digests.hex" \
  "$w/generated/pcrvals.hex" "$w/generated/qual.hex" testdata/attestation/expected/
rm -rf testdata/attestation/invalid
install -d -m 0755 testdata/attestation/invalid
install -m 0644 "$w/generated/invalid/"* testdata/attestation/invalid/
(
  cd testdata/attestation
  # Exclude exactly ./SHA256SUMS; NUL names, bytewise ordering, and -- make
  # this deterministic even for whitespace or option-like path names.
  LC_ALL=C find . -type f ! -path './SHA256SUMS' -print0 | LC_ALL=C sort -z \
    | xargs -0 -r sha256sum -- | sed 's#  \./#  #' > SHA256SUMS
)
./testdata/attestation/source/rebuild-check.sh
tpm2_shutdown -c
cleanup
trap - EXIT HUP INT TERM
```

The generator uses fxamacker CBOR canonical encoding and upstream go-tpm and
go-attestation for public/quote validation. Its test-only TCG2 construction is
not used by production parsing/replay.
