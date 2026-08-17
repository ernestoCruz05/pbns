import argparse
import dataclasses
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import sys
import threading
import time
from collections.abc import Sequence

try:
    from pbns.integration.tls.test_identity import (
        TLSIdentityError,
        TLS_FIXTURES,
        make_matching_certificate,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from test_identity import (  # type: ignore
        TLSIdentityError,
        TLS_FIXTURES,
        make_matching_certificate,
    )


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
MILESTONE_COUNT = 13
HEAP_CANDIDATES = tuple(range(4096, 65537, 1024))
MBEDTLS_REVISION = "068ff080b369adfac81509f9b57b2afabaf82dc5"
TERMINALS = frozenset(
    (
        "ready",
        "init-entropy",
        "init-resource",
        "init-contract",
        "handshake-encrypted-io",
        "handshake-allocator",
        "handshake-certificate-flags",
        "handshake-pin",
        "handshake-peer-or-protocol",
        "profile-version-handshake-incomplete",
        "profile-version-unknown",
        "profile-version-tls13",
        "profile-version-conversion-inconsistent",
        "profile-version-other",
        "profile-version-unsupported",
        "profile-cipher-unsupported",
        "profile-alpn-unsupported",
        "profile-unsupported",
        "unknown",
    )
)
SERVER_EVENTS = frozenset(
    (
        "tcp-accepted",
        "tls-handshake-complete",
        "alpn-selected",
        "alpn-absent",
        "tls-handshake-failed",
    )
)
EVIDENCE_FIELDS = frozenset(
    (
        "config_sha256",
        "elapsed_ms",
        "executable_sha256",
        "heap_selector",
        "mbedtls_revision",
        "milestones",
        "repetitions",
        "server_events",
        "source_sha256",
        "terminal",
    )
)
SENSITIVE_NAMES = (
    "key",
    "certificate",
    "record",
    "payload",
    "hostname",
    "address",
    "socket",
    "errno",
    "alert",
    "raw",
)
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")


class ReplayError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class ReplayResult:
    terminal: str
    milestones: tuple[bool, ...]
    server_events: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class HeapBoundaries:
    initialization: ReplayResult
    handshake: ReplayResult


class _ReplayServer:
    def __init__(
        self, certificate: pathlib.Path, *, advertise_alpn: bool = True
    ) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
        if advertise_alpn:
            context.set_alpn_protocols(["pbns/1"])
        context.load_cert_chain(
            certificate, TLS_FIXTURES / "tls-gateway-test-key.pem"
        )
        self._context = context
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self._listener.settimeout(0.1)
        self._stop = threading.Event()
        self._events: list[str] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return int(self._listener.getsockname()[1])

    @property
    def events(self) -> tuple[str, ...]:
        return tuple(self._events)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        connection: socket.socket | None = None
        while not self._stop.is_set() and connection is None:
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
        if connection is None:
            return
        with connection:
            connection.settimeout(5.0)
            self._events.append("tcp-accepted")
            try:
                with self._context.wrap_socket(
                    connection, server_side=True
                ) as tls_connection:
                    self._events.append("tls-handshake-complete")
                    selected = tls_connection.selected_alpn_protocol()
                    self._events.append(
                        "alpn-selected" if selected == "pbns/1" else "alpn-absent"
                    )
            except (OSError, ssl.SSLError):
                self._events.append("tls-handshake-failed")

    def stop(self) -> None:
        self._stop.set()
        try:
            self._listener.close()
        except OSError:
            pass
        self._thread.join(timeout=6.0)
        if self._thread.is_alive():
            raise ReplayError("replay server did not stop")


def _milestones_are_prefix(milestones: Sequence[bool]) -> bool:
    gap_seen = False
    for milestone in milestones:
        if not milestone:
            gap_seen = True
        elif gap_seen:
            return False
    return True


def _events_are_valid(events: tuple[str, ...]) -> bool:
    if len(events) != len(set(events)) or any(
        event not in SERVER_EVENTS for event in events
    ):
        return False
    if not events:
        return True
    if events[0] != "tcp-accepted":
        return False
    if "tls-handshake-complete" in events and "tls-handshake-failed" in events:
        return False
    if "alpn-selected" in events and "alpn-absent" in events:
        return False
    if ("alpn-selected" in events or "alpn-absent" in events) and (
        "tls-handshake-complete" not in events
    ):
        return False
    return True


def validate_replay_result(
    terminal: str, milestones: Sequence[bool], server_events: Sequence[str]
) -> ReplayResult:
    if terminal not in TERMINALS:
        raise ReplayError("invalid replay terminal")
    if len(milestones) != MILESTONE_COUNT or any(
        type(milestone) is not bool for milestone in milestones
    ):
        raise ReplayError("invalid replay milestones")
    milestone_tuple = tuple(milestones)
    if not _milestones_are_prefix(milestone_tuple):
        raise ReplayError("impossible replay milestone order")
    if any(type(event) is not str for event in server_events):
        raise ReplayError("invalid replay server event")
    event_tuple = tuple(server_events)
    if not _events_are_valid(event_tuple):
        raise ReplayError("contradictory replay server events")
    if terminal == "ready":
        if not all(milestone_tuple) or event_tuple != (
            "tcp-accepted",
            "tls-handshake-complete",
            "alpn-selected",
        ):
            raise ReplayError("ready replay lacks exact handshake evidence")
    if terminal.startswith("init-") and event_tuple:
        raise ReplayError("initialization failure contradicts server events")
    if terminal == "profile-alpn-unsupported":
        if milestone_tuple != (True,) * 12 + (False,) or event_tuple != (
            "tcp-accepted",
            "tls-handshake-complete",
            "alpn-absent",
        ):
            raise ReplayError("ALPN failure lacks exact handshake evidence")
    if terminal in (
        "profile-version-handshake-incomplete",
        "profile-version-unknown",
        "profile-version-tls13",
        "profile-version-conversion-inconsistent",
        "profile-version-other",
        "profile-version-unsupported",
        "profile-cipher-unsupported",
    ):
        profile_events = (
            ("tcp-accepted", "tls-handshake-complete", "alpn-selected"),
            ("tcp-accepted", "tls-handshake-complete", "alpn-absent"),
        )
        if milestone_tuple != (True,) * 12 + (False,) or event_tuple not in profile_events:
            raise ReplayError("profile discriminator lacks exact handshake evidence")
    return ReplayResult(terminal, milestone_tuple, event_tuple)


def _parse_client_result(encoded: bytes, events: tuple[str, ...]) -> ReplayResult:
    try:
        decoded = json.loads(encoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReplayError("invalid replay client output") from error
    if not isinstance(decoded, dict) or set(decoded) != {"terminal", "milestones"}:
        raise ReplayError("invalid replay client fields")
    terminal = decoded["terminal"]
    milestones = decoded["milestones"]
    if not isinstance(terminal, str) or not isinstance(milestones, list):
        raise ReplayError("invalid replay client types")
    return validate_replay_result(terminal, milestones, events)


def _validate_scenario_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    values = tuple(arguments)
    if any(type(value) is not str or "\x00" in value for value in values):
        raise ReplayError("invalid replay scenario argument")
    forbidden = frozenset(("--port", "--spki", "--host"))
    if any(value in forbidden for value in values):
        raise ReplayError("replay scenario overrides fixed identity")
    return values


def run_replay_scenario(
    executable: pathlib.Path,
    pin: str,
    *,
    arguments: Sequence[str] = (),
    server_alpn: bool = True,
) -> ReplayResult:
    if (
        not executable.is_file()
        or executable.is_symlink()
        or SHA256_HEX.fullmatch(pin) is None
        or type(server_alpn) is not bool
    ):
        raise ReplayError("invalid replay executable or pin")
    scenario_arguments = _validate_scenario_arguments(arguments)
    entropy_failure = "--entropy-fail" in scenario_arguments
    state = pathlib.Path(tempfile.mkdtemp(prefix="pbns-hosted-tls-replay-"))
    state.chmod(0o700)
    server: _ReplayServer | None = None
    try:
        if entropy_failure:
            port = 9
        else:
            certificate = make_matching_certificate(
                state, server_name="127.0.0.1"
            )
            server = _ReplayServer(certificate, advertise_alpn=server_alpn)
            server.start()
            port = server.port
        command = [
            str(executable),
            "--port",
            str(port),
            "--spki",
            pin,
            *scenario_arguments,
        ]
        try:
            process = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=35.0,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReplayError("cannot execute hosted TLS replay") from error
        if server is not None:
            server.stop()
        events = () if server is None else server.events
        if process.returncode != 0 or process.stderr:
            raise ReplayError("hosted TLS replay client failed")
        return _parse_client_result(process.stdout, events)
    except TLSIdentityError as error:
        raise ReplayError("cannot create hosted TLS replay identity") from error
    finally:
        if server is not None and server._thread.is_alive():
            server.stop()
        shutil.rmtree(state, ignore_errors=True)


def find_reduced_heap_boundaries(
    executable: pathlib.Path, pin: str
) -> HeapBoundaries:
    initialization: ReplayResult | None = None
    handshake: ReplayResult | None = None
    for heap_bytes in HEAP_CANDIDATES:
        result = run_replay_scenario(
            executable,
            pin,
            arguments=("--heap-bytes", str(heap_bytes)),
        )
        if result.terminal == "init-resource":
            initialization = result
        elif result.terminal == "handshake-allocator" and handshake is None:
            handshake = result
    if initialization is None or handshake is None:
        raise ReplayError("reduced heap boundaries are incomplete")
    return HeapBoundaries(initialization, handshake)


def run_determinism_campaign(
    executable: pathlib.Path, pin: str, *, repetitions: int
) -> ReplayResult:
    if repetitions < 1 or repetitions > 100:
        raise ReplayError("invalid replay repetition count")
    baseline = run_replay_scenario(executable, pin)
    for _ in range(1, repetitions):
        if run_replay_scenario(executable, pin) != baseline:
            raise ReplayError("hosted TLS replay is nondeterministic")
    return baseline


def self_test(executable: pathlib.Path, pin: str) -> ReplayResult:
    baseline = run_determinism_campaign(executable, pin, repetitions=10)
    boundaries = find_reduced_heap_boundaries(executable, pin)
    if boundaries.initialization.terminal != "init-resource" or (
        boundaries.handshake.terminal != "handshake-allocator"
    ):
        raise ReplayError("reduced heap replay classification failed")
    asynchronous = run_replay_scenario(
        executable,
        pin,
        arguments=(
            "--read-limit",
            "7",
            "--write-limit",
            "11",
            "--would-block-period",
            "3",
        ),
    )
    if asynchronous != baseline:
        raise ReplayError("asynchronous replay changed the baseline result")

    entropy = run_replay_scenario(
        executable, pin, arguments=("--entropy-fail",)
    )
    if entropy.terminal != "init-entropy" or entropy.server_events:
        raise ReplayError("entropy replay classification failed")

    wrong_pin = run_replay_scenario(executable, "0" * 64)
    if wrong_pin.terminal != "handshake-pin":
        raise ReplayError("wrong-pin replay classification failed")

    missing_alpn = run_replay_scenario(executable, pin, server_alpn=False)
    if missing_alpn.terminal != "profile-alpn-unsupported":
        raise ReplayError("missing-ALPN replay classification failed")

    read_failure = run_replay_scenario(
        executable, pin, arguments=("--fail-read-at", "1")
    )
    write_failure = run_replay_scenario(
        executable, pin, arguments=("--fail-write-at", "1")
    )
    if read_failure.terminal != "handshake-encrypted-io":
        raise ReplayError("read-failure replay classification failed")
    if write_failure.terminal != "handshake-encrypted-io":
        raise ReplayError("write-failure replay classification failed")
    return baseline


def _contains_sensitive_name(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(name in lowered for name in SENSITIVE_NAMES):
                return True
            if _contains_sensitive_name(nested):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_sensitive_name(item) for item in value)
    return False


def _validate_evidence(evidence: dict[str, object]) -> None:
    if set(evidence) != EVIDENCE_FIELDS or _contains_sensitive_name(evidence):
        raise ReplayError("invalid replay evidence fields")
    for field in ("config_sha256", "executable_sha256", "source_sha256"):
        value = evidence[field]
        if not isinstance(value, str) or SHA256_HEX.fullmatch(value) is None:
            raise ReplayError("invalid replay evidence digest")
    if evidence["mbedtls_revision"] != MBEDTLS_REVISION:
        raise ReplayError("invalid replay dependency revision")
    if evidence["heap_selector"] not in (
        "exact",
        "reduced-init",
        "reduced-handshake",
    ):
        raise ReplayError("invalid replay heap selector")
    elapsed_ms = evidence["elapsed_ms"]
    repetitions = evidence["repetitions"]
    if type(elapsed_ms) is not int or elapsed_ms < 0:
        raise ReplayError("invalid replay elapsed time")
    if type(repetitions) is not int or repetitions < 1:
        raise ReplayError("invalid replay repetition count")
    terminal = evidence["terminal"]
    milestones = evidence["milestones"]
    events = evidence["server_events"]
    if not isinstance(terminal, str) or not isinstance(milestones, list) or not isinstance(events, list):
        raise ReplayError("invalid replay result fields")
    validate_replay_result(terminal, milestones, events)


def _require_private_directory(directory: pathlib.Path) -> None:
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        information = directory.lstat()
    except OSError as error:
        raise ReplayError("cannot create replay results directory") from error
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(information.st_mode)
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        raise ReplayError("replay results directory must have mode 0700")


def _write_private(path: pathlib.Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _sha256_file(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ReplayError("invalid replay hash input")
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise ReplayError("cannot hash replay input") from error


def _source_sha256() -> str:
    sources = (
        PBNS_ROOT / "CMakeLists.txt",
        PBNS_ROOT / "pico/include/pbns_proxy/tls_client.h",
        PBNS_ROOT / "pico/src/tls_client.c",
        PBNS_ROOT / "pico/tests/tls_replay/observer.c",
        PBNS_ROOT / "pico/tests/tls_replay/endpoint.c",
        PBNS_ROOT / "pico/tests/tls_replay/entropy.c",
        PBNS_ROOT / "pico/tests/tls_replay/main.c",
    )
    digest = hashlib.sha256()
    for source in sources:
        try:
            content = source.read_bytes()
        except OSError as error:
            raise ReplayError("cannot hash replay sources") from error
        encoded_name = source.relative_to(PBNS_ROOT).as_posix().encode("ascii")
        digest.update(len(encoded_name).to_bytes(4, "big"))
        digest.update(encoded_name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _read_public_pin(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ReplayError("invalid replay pin file")
    try:
        pin = path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise ReplayError("cannot read replay pin file") from error
    if SHA256_HEX.fullmatch(pin) is None:
        raise ReplayError("invalid replay pin file")
    return pin


def write_replay_evidence(
    directory: pathlib.Path,
    evidence: dict[str, object],
    *,
    timestamp: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    _validate_evidence(evidence)
    if TIMESTAMP.fullmatch(timestamp) is None:
        raise ReplayError("invalid replay evidence timestamp")
    _require_private_directory(directory)
    result = directory / f"{timestamp}-hosted-tls-replay.json"
    digest = result.with_suffix(".sha256")
    temporary = directory / f".{result.name}.tmp"
    digest_temporary = directory / f".{digest.name}.tmp"
    if result.exists() or digest.exists():
        raise ReplayError("replay evidence already exists")
    encoded = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode()
    try:
        _write_private(temporary, encoded)
        digest_content = (
            f"{hashlib.sha256(encoded).hexdigest()}  {result.name}\n"
        ).encode("ascii")
        _write_private(digest_temporary, digest_content)
        os.replace(temporary, result)
        os.replace(digest_temporary, digest)
    except (OSError, ReplayError) as error:
        temporary.unlink(missing_ok=True)
        digest_temporary.unlink(missing_ok=True)
        raise ReplayError("cannot publish replay evidence") from error
    return result, digest


def run_evidence_campaign(
    executable: pathlib.Path,
    pin: str,
    results_directory: pathlib.Path,
    *,
    repetitions: int,
    timestamp: str,
) -> tuple[ReplayResult, pathlib.Path, pathlib.Path]:
    started = time.monotonic()
    result = run_determinism_campaign(
        executable, pin, repetitions=repetitions
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    evidence: dict[str, object] = {
        "config_sha256": _sha256_file(
            PBNS_ROOT / "pico/include/mbedtls_config.h"
        ),
        "elapsed_ms": elapsed_ms,
        "executable_sha256": _sha256_file(executable),
        "heap_selector": "exact",
        "mbedtls_revision": MBEDTLS_REVISION,
        "milestones": list(result.milestones),
        "repetitions": repetitions,
        "server_events": list(result.server_events),
        "source_sha256": _source_sha256(),
        "terminal": result.terminal,
    }
    result_path, digest_path = write_replay_evidence(
        results_directory, evidence, timestamp=timestamp
    )
    return result, result_path, digest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the hosted PBNS TLS replay")
    subparsers = parser.add_subparsers(dest="command", required=True)
    self_test_parser = subparsers.add_parser("self-test")
    self_test_parser.add_argument("--executable", required=True, type=pathlib.Path)
    self_test_parser.add_argument("--pin-file", required=True, type=pathlib.Path)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--executable", required=True, type=pathlib.Path)
    run_parser.add_argument("--pin-file", required=True, type=pathlib.Path)
    run_parser.add_argument("--results-dir", required=True, type=pathlib.Path)
    run_parser.add_argument("--repetitions", required=True, type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        pin = _read_public_pin(arguments.pin_file)
        if arguments.command == "self-test":
            result = self_test(arguments.executable, pin)
            label = "SELF-TEST PASS"
        elif arguments.command == "run":
            timestamp = datetime.datetime.now(datetime.UTC).strftime(
                "%Y%m%dT%H%M%SZ"
            )
            result, _result_path, _digest_path = run_evidence_campaign(
                arguments.executable,
                pin,
                arguments.results_dir,
                repetitions=arguments.repetitions,
                timestamp=timestamp,
            )
            label = "RESULT"
        else:
            raise ReplayError("unsupported replay command")
    except (OSError, ReplayError):
        print("hosted TLS replay failed", file=sys.stderr)
        return 1
    print(f"HOSTED TLS REPLAY {label} {result.terminal}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
