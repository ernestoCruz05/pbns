#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 1 ]]; then
    printf 'usage: %s STATE_DIR\n' "$0" >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
pbns_root=$(cd -- "$script_dir/../.." && pwd -P)
state_root="$pbns_root/integration/state/"
state_dir=$1
if [[ ! -d $state_dir ]]; then
    printf 'swtpm state absent: %s\n' "$state_dir" >&2
    exit 1
fi
state_dir=$(cd -- "$state_dir" && pwd -P)
if [[ $state_dir != "$state_root"* ]]; then
    printf 'state must be below %s\n' "$state_root" >&2
    exit 1
fi
socket_file="$state_dir/socket.path"
pid_file="$state_dir/swtpm.pid"
if [[ ! -s $socket_file || ! -s $pid_file ]]; then
    printf 'swtpm is not ready\n' >&2
    exit 1
fi
socket_path=$(<"$socket_file")
runtime_prefix="${TMPDIR:-/tmp}/pbns-swtpm."
if [[ $socket_path != "$runtime_prefix"*/server.sock || ! -S $socket_path ]]; then
    printf 'invalid disposable swtpm socket\n' >&2
    exit 1
fi
export TPM2TOOLS_TCTI="swtpm:path=$socket_path"
readonly PBNS_RECOVERY_NV_INDEX=0x01801000

work_dir="$state_dir/recovery-policy-oracle"
if [[ -e $work_dir ]]; then
    printf 'recovery policy workspace already exists\n' >&2
    exit 1
fi
mkdir -m 0700 "$work_dir"
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

for tool in go openssl tpm2_getcap tpm2_nvdefine tpm2_nvreadpublic tpm2_nvread \
            tpm2_nvwrite tpm2_startauthsession tpm2_policynvwritten \
            tpm2_policynv tpm2_policycphash tpm2_loadexternal \
            tpm2_verifysignature tpm2_policyauthorize tpm2_flushcontext; do
    command -v "$tool" >/dev/null
done

if tpm2_getcap handles-nv-index | grep -Eiq '0x0?1801000'; then
    printf 'recovery NV index already exists in fresh state\n' >&2
    exit 1
fi

(
    cd -- "$pbns_root/gateway"
    go build -o "$work_dir/pbnsctl" ./cmd/pbnsctl
)
chmod 0700 "$work_dir/pbnsctl"
key_root="$pbns_root/tests/fixtures/keys"
openssl ec -in "$key_root/recovery-policy-test-private.pem" \
    -out "$work_dir/policy-private.pem" >/dev/null 2>&1
chmod 0600 "$work_dir/policy-private.pem"
install -m 0600 "$key_root/recovery-policy-test-public.pem" \
    "$work_dir/policy-public.pem"
install -m 0600 "$key_root/service-signing-test-public.pem" \
    "$work_dir/manifest-public.pem"
install -m 0600 "$key_root/uki-secureboot-test-cert.pem" \
    "$work_dir/secureboot-public.pem"

policy_cli() {
    operation=$1
    shift
    "$work_dir/pbnsctl" recovery policy "$operation" \
        --policy-private-key "$work_dir/policy-private.pem" \
        --policy-public-key "$work_dir/policy-public.pem" \
        --manifest-public-key "$work_dir/manifest-public.pem" \
        --secureboot-public-key "$work_dir/secureboot-public.pem" \
        --nv-index "$PBNS_RECOVERY_NV_INDEX" "$@"
}

policy_cli initialize --initial-version 4 \
    --material-dir "$work_dir/initialize-material" \
    --output "$work_dir/initialize.cbor" >"$work_dir/initialize.json"

tpm2_nvdefine "$PBNS_RECOVERY_NV_INDEX" -C o -s 8 -g sha256 \
    -a 0x02020008 \
    -L "$work_dir/initialize-material/final.policy" >/dev/null
verify_nv_name() {
    expected=$1
    actual_hex=$(tpm2_nvreadpublic "$PBNS_RECOVERY_NV_INDEX" |
        awk '$1 == "name:" { print $2 }')
    expected_hex=$(od -An -tx1 -v "$expected" | tr -d ' \n')
    [[ -n $actual_hex && $actual_hex == "$expected_hex" ]]
}
verify_nv_name "$work_dir/initialize-material/nv.name"

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

prepare_authorization() {
    material=$1
    kind=$2
    label=$3
    policy_session="$work_dir/$label-session.ctx"
    key_context="$work_dir/$label-key.ctx"
    tpm2_startauthsession --policy-session -S "$policy_session"
    if [[ $kind == initialize ]]; then
        tpm2_policynvwritten -S "$policy_session" c
    else
        tpm2_policynv "$PBNS_RECOVERY_NV_INDEX" ult -C o -P '' \
            -S "$policy_session" -i "$material/target.bin" --offset 0
    fi
    {
        printf '\x00\x20'
        cat "$material/write.cphash"
    } >"$work_dir/$label-cphash.tpm2b"
    tpm2_policycphash -S "$policy_session" \
        --cphash-input "$work_dir/$label-cphash.tpm2b"
    tpm2_loadexternal -C o -u "$material/policy-key.public" \
        -c "$key_context" -n "$work_dir/$label-key.name" >/dev/null
    cmp "$work_dir/$label-key.name" "$material/policy-key.name"
    TPM2TOOLS_AUTOFLUSH=yes tpm2_verifysignature -c "$key_context" \
        -d "$material/approval.digest" -s "$material/signature.tss" \
        -t "$work_dir/$label.ticket" >/dev/null
    tpm2_policyauthorize -S "$policy_session" \
        -i "$material/approved.policy" -q "$material/policy.ref" \
        -n "$material/policy-key.name" -t "$work_dir/$label.ticket"
}

execute_authorization() {
    material=$1
    kind=$2
    prepare_authorization "$material" "$kind" "$kind"
    tpm2_nvwrite "$PBNS_RECOVERY_NV_INDEX" -C "$PBNS_RECOVERY_NV_INDEX" \
        -P "session:$policy_session" -i "$material/target.bin" \
        --offset 0 >/dev/null
    release_contexts
}

read_version() {
    output=$1
    tpm2_nvread "$PBNS_RECOVERY_NV_INDEX" -C o -s 8 -o "$output" >/dev/null
}

execute_authorization "$work_dir/initialize-material" initialize
read_version "$work_dir/current.bin"
cmp "$work_dir/current.bin" "$work_dir/initialize-material/target.bin"

initialization_replay() {
    material="$work_dir/initialize-material"
    prepare_authorization "$material" initialize initialization-replay
    if tpm2_nvwrite "$PBNS_RECOVERY_NV_INDEX" \
        -C "$PBNS_RECOVERY_NV_INDEX" -P "session:$policy_session" \
        -i "$material/target.bin" --offset 0 >/dev/null 2>&1; then
        printf 'initialization-replay unexpectedly accepted\n' >&2
        return 1
    fi
    release_contexts
}
initialization_replay

policy_cli advance --current-version 4 --target-version 5 \
    --material-dir "$work_dir/advance-material" \
    --output "$work_dir/advance.cbor" >"$work_dir/advance.json"
verify_nv_name "$work_dir/advance-material/nv.name"
execute_authorization "$work_dir/advance-material" advance
read_version "$work_dir/current.bin"
cmp "$work_dir/current.bin" "$work_dir/advance-material/target.bin"

update_replay() {
    policy_session="$work_dir/update-replay-session.ctx"
    tpm2_startauthsession --policy-session -S "$policy_session"
    if tpm2_policynv "$PBNS_RECOVERY_NV_INDEX" ult -C o -P '' \
        -S "$policy_session" -i "$work_dir/advance-material/target.bin" \
        --offset 0 >/dev/null 2>&1; then
        printf 'update-replay unexpectedly accepted\n' >&2
        return 1
    fi
    tpm2_flushcontext "$policy_session" >/dev/null 2>&1 || true
    rm -f -- "$policy_session"
    policy_session=
}
update_replay

if policy_cli advance --current-version 5 --target-version 5 \
    --material-dir "$work_dir/equal-target-material" \
    --output "$work_dir/equal-target.cbor" >/dev/null 2>&1; then
    printf 'equal-target unexpectedly authorized\n' >&2
    exit 1
fi
if policy_cli advance --current-version 5 --target-version 4 \
    --material-dir "$work_dir/downgrade-material" \
    --output "$work_dir/downgrade.cbor" >/dev/null 2>&1; then
    printf 'downgrade unexpectedly authorized\n' >&2
    exit 1
fi

read_version "$work_dir/final.bin"
printf '\x00\x00\x00\x00\x00\x00\x00\x05' >"$work_dir/expected-final.bin"
cmp "$work_dir/final.bin" "$work_dir/expected-final.bin"
printf '%s\n' 'SWTPM RECOVERY POLICY PASS current=5'
