#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    printf 'usage: %s initialize STATE_DIR VERSION | authorize STATE_DIR CURRENT TARGET LABEL | read STATE_DIR OUTPUT_FILE\n' "$0" >&2
    exit 2
}

[[ $# -ge 1 ]] || usage
operation=$1
case $operation in
    initialize)
        [[ $# -eq 3 && $3 == 5 ]] || usage
        state_arg=$2
        initial_version=$3
        ;;
    authorize)
        [[ $# -eq 5 && $3 =~ ^[0-9]+$ && $4 =~ ^[0-9]+$ ]] || usage
        state_arg=$2
        current_version=$3
        target_version=$4
        label=$5
        [[ $label =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]] || usage
        if [[ $current_version -eq 4 && $target_version -eq 5 &&
              $label == downgrade-5 ]]; then
            : # 4 5 downgrade-5 is retained historical material only.
        elif [[ $target_version -le $current_version ||
                $label != "target-$target_version" ]]; then
            usage
        fi
        ;;
    read)
        [[ $# -eq 3 ]] || usage
        state_arg=$2
        output_arg=$3
        ;;
    *)
        usage
        ;;
esac

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
if [[ ! -d $state_arg || -L $state_arg ]]; then
    printf 'state must be a non-symlink directory\n' >&2
    exit 1
fi
state_dir=$(cd -- "$state_arg" && pwd -P)
if [[ $state_dir != "$state_root"* || $(stat -c %u "$state_dir") -ne $(id -u) ||
      $(stat -c %a "$state_dir") != 700 ]]; then
    printf 'state below integration/state/ must be owned and use mode 0700\n' >&2
    exit 1
fi
if [[ ! -d $state_dir/tpm || -L $state_dir/tpm ||
      $(stat -c %u "$state_dir/tpm") -ne $(id -u) ||
      $(stat -c %a "$state_dir/tpm") != 700 ]]; then
    printf 'invalid disposable TPM state\n' >&2
    exit 1
fi
managed="$state_dir/managed"
if [[ ! -f $managed || -L $managed || $(stat -c %a "$managed") != 600 ||
      $(<"$managed") != PBNS_SWTPM_STATE_V1 ]]; then
    printf 'invalid PBNS_SWTPM_STATE_V1 marker\n' >&2
    exit 1
fi
if ! socket_path=$(python3 "$script_dir/quiesce-swtpm-runtime.py" --verify-live "$state_dir"); then
    printf 'swtpm is not ready\n' >&2
    exit 1
fi
export TPM2TOOLS_TCTI="swtpm:path=$socket_path"
readonly PBNS_RECOVERY_NV_INDEX=0x01801000
readonly PBNS_RECOVERY_NV_ATTRIBUTES=0x02020008

if [[ $operation == read ]]; then
    output_parent=$(dirname -- "$output_arg")
    if [[ ! -d $output_parent || -L $output_parent ]]; then
        printf 'invalid private output parent\n' >&2
        exit 1
    fi
    output_parent=$(cd -- "$output_parent" && pwd -P)
    output_path="$output_parent/$(basename -- "$output_arg")"
    if [[ $output_parent != "$state_dir" && $output_parent != "$state_dir/"* ]] ||
       [[ $(stat -c %u "$output_parent") -ne $(id -u) ||
          $(stat -c %a "$output_parent") != 700 || -e $output_path ||
          -L $output_path ]]; then
        printf 'output must be new below private state\n' >&2
        exit 1
    fi
fi

for tool in go python3 sync tpm2_getcap tpm2_nvdefine tpm2_nvreadpublic \
            tpm2_nvread tpm2_nvwrite tpm2_startauthsession \
            tpm2_policynvwritten tpm2_policycphash tpm2_loadexternal \
            tpm2_verifysignature tpm2_policyauthorize tpm2_flushcontext; do
    command -v "$tool" >/dev/null
done
if ! tpm2_getcap properties-fixed >/dev/null 2>&1; then
    printf 'verified swtpm is unavailable\n' >&2
    exit 1
fi

work_dir=$(mktemp -d "$state_dir/.recovery-policy-live.XXXXXX")
chmod 0700 "$work_dir"
policy_session=
key_context=
flush_gate_contexts() {
    tpm2_flushcontext --transient-object >/dev/null 2>&1 || true
    tpm2_flushcontext --loaded-session >/dev/null 2>&1 || true
    tpm2_flushcontext --saved-session >/dev/null 2>&1 || true
}
cleanup() {
    status=$?
    if [[ -n $key_context && -e $key_context ]]; then
        tpm2_flushcontext "$key_context" >/dev/null 2>&1 || true
    fi
    if [[ -n $policy_session && -e $policy_session ]]; then
        tpm2_flushcontext "$policy_session" >/dev/null 2>&1 || true
    fi
    flush_gate_contexts
    rm -rf -- "$work_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ $operation == read ]]; then
    tpm2_nvread "$PBNS_RECOVERY_NV_INDEX" -C o -s 8 \
        -o "$work_dir/current.bin" >/dev/null
    [[ $(stat -c %s "$work_dir/current.bin") -eq 8 ]]
    (set -o noclobber; cat "$work_dir/current.bin" >"$output_path")
    chmod 0600 "$output_path"
    sync -f "$output_path"
    sync -f "$output_parent"
    current=$(python3 -c 'import pathlib,sys; print(int.from_bytes(pathlib.Path(sys.argv[1]).read_bytes(), "big"))' "$output_path")
    printf 'PBNS RECOVERY POLICY READ PASS current=%s\n' "$current"
    exit 0
fi

for tool in cmp install openssl; do
    command -v "$tool" >/dev/null
done
policy_dir="$state_dir/recovery-policy"
if [[ -e $policy_dir &&
      (! -d $policy_dir || -L $policy_dir ||
       $(stat -c %u "$policy_dir") -ne $(id -u) ||
       $(stat -c %a "$policy_dir") != 700) ]]; then
    printf 'invalid retained policy directory\n' >&2
    exit 1
fi
if [[ ! -e $policy_dir ]]; then
    mkdir -m 0700 "$policy_dir"
fi
(
    cd -- "$pbns_root/gateway"
    go build -o "$work_dir/pbnsctl" ./cmd/pbnsctl
)
chmod 0700 "$work_dir/pbnsctl"
key_root="$pbns_root/tests/fixtures/keys"
install -m 0600 "$key_root/recovery-policy-test-private.pem" \
    "$work_dir/policy-private-source.pem"
openssl ec -in "$work_dir/policy-private-source.pem" \
    -out "$work_dir/policy-private.pem" >/dev/null 2>&1
chmod 0600 "$work_dir/policy-private.pem"
install -m 0600 "$key_root/recovery-policy-test-public.pem" \
    "$work_dir/policy-public.pem"
install -m 0600 "$key_root/recovery-manifest-test-public.pem" \
    "$work_dir/manifest-public.pem"
install -m 0600 "$key_root/uki-secureboot-test-cert.pem" \
    "$work_dir/secureboot-public.pem"

policy_cli() {
    subcommand=$1
    shift
    "$work_dir/pbnsctl" recovery policy "$subcommand" \
        --policy-private-key "$work_dir/policy-private.pem" \
        --policy-public-key "$work_dir/policy-public.pem" \
        --manifest-public-key "$work_dir/manifest-public.pem" \
        --secureboot-public-key "$work_dir/secureboot-public.pem" \
        --nv-index "$PBNS_RECOVERY_NV_INDEX" "$@"
}
validate_result() {
    result_file=$1
    expected_target=$2
    python3 - "$result_file" "$expected_target" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("target_version") != int(sys.argv[2]):
    raise SystemExit("policy target mismatch")
if value.get("kind") not in ("initialize", "advance"):
    raise SystemExit("policy kind mismatch")
PY
}
retain_authorization() {
    source_file=$1
    name=$2
    destination="$policy_dir/$name.cbor"
    if [[ -e $destination || -L $destination ]]; then
        printf 'retained authorization already exists\n' >&2
        exit 1
    fi
    (set -o noclobber; cat "$source_file" >"$destination")
    chmod 0600 "$destination"
    sync -f "$destination"
    sync -f "$policy_dir"
    if find "$policy_dir" -mindepth 1 ! -type f -o -type l | grep -q .; then
        printf 'invalid retained policy inventory\n' >&2
        exit 1
    fi
    find "$policy_dir" -type f -exec chmod 0600 {} +
}
verify_nv_name() {
    expected=$1
    actual_hex=$(tpm2_nvreadpublic "$PBNS_RECOVERY_NV_INDEX" |
        awk '$1 == "name:" { print $2 }')
    expected_hex=$(od -An -tx1 -v "$expected" | tr -d ' \n')
    [[ -n $actual_hex && $actual_hex == "$expected_hex" ]]
}
release_contexts() {
    if [[ -n $key_context ]]; then
        tpm2_flushcontext "$key_context" >/dev/null 2>&1 || true
        rm -f -- "$key_context"
        key_context=
    fi
    if [[ -n $policy_session ]]; then
        tpm2_flushcontext "$policy_session" >/dev/null 2>&1 || true
        rm -f -- "$policy_session"
        policy_session=
    fi
    flush_gate_contexts
}

if [[ $operation == authorize ]]; then
    output="$work_dir/$label.cbor"
    material="$work_dir/$label-material"
    policy_cli advance --current-version "$current_version" \
        --target-version "$target_version" --material-dir "$material" \
        --output "$output" >"$work_dir/$label.json"
    validate_result "$work_dir/$label.json" "$target_version"
    retain_authorization "$output" "$label"
    printf 'PBNS RECOVERY POLICY AUTHORIZATION PASS target=%s\n' "$target_version"
    exit 0
fi

if tpm2_getcap handles-nv-index | grep -Eiq '0x0?1801000'; then
    printf 'recovery NV index already exists\n' >&2
    exit 1
fi
material="$work_dir/initialize-material"
policy_cli initialize --initial-version "$initial_version" \
    --material-dir "$material" --output "$work_dir/initialization.cbor" \
    >"$work_dir/initialization.json"
validate_result "$work_dir/initialization.json" "$initial_version"
tpm2_nvdefine "$PBNS_RECOVERY_NV_INDEX" -C o -s 8 -g sha256 \
    -a "$PBNS_RECOVERY_NV_ATTRIBUTES" -L "$material/final.policy" >/dev/null
verify_nv_name "$material/nv.name"
policy_session="$work_dir/initialize-session.ctx"
key_context="$work_dir/initialize-key.ctx"
tpm2_startauthsession --policy-session -S "$policy_session"
tpm2_policynvwritten -S "$policy_session" c >/dev/null
{
    printf '\x00\x20'
    cat "$material/write.cphash"
} >"$work_dir/initialize-cphash.tpm2b"
tpm2_policycphash -S "$policy_session" \
    --cphash-input "$work_dir/initialize-cphash.tpm2b" >/dev/null
tpm2_loadexternal -C o -u "$material/policy-key.public" \
    -c "$key_context" -n "$work_dir/initialize-key.name" >/dev/null
cmp "$work_dir/initialize-key.name" "$material/policy-key.name"
TPM2TOOLS_AUTOFLUSH=yes tpm2_verifysignature -c "$key_context" \
    -d "$material/approval.digest" -s "$material/signature.tss" \
    -t "$work_dir/initialize.ticket" >/dev/null
tpm2_policyauthorize -S "$policy_session" -i "$material/approved.policy" \
    -q "$material/policy.ref" -n "$material/policy-key.name" \
    -t "$work_dir/initialize.ticket" >/dev/null
tpm2_nvwrite "$PBNS_RECOVERY_NV_INDEX" -C "$PBNS_RECOVERY_NV_INDEX" \
    -P "session:$policy_session" -i "$material/target.bin" \
    --offset 0 >/dev/null
release_contexts
tpm2_nvread "$PBNS_RECOVERY_NV_INDEX" -C o -s 8 \
    -o "$work_dir/current.bin" >/dev/null
cmp "$work_dir/current.bin" "$material/target.bin"
retain_authorization "$work_dir/initialization.cbor" initialization
printf 'PBNS RECOVERY POLICY INITIALIZE PASS current=%s\n' "$initial_version"
