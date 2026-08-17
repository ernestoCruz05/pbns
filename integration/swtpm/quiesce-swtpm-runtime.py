#!/usr/bin/env python3
"""Durable, descriptor-relative swtpm pause transaction."""
import argparse
import json
import os
import pathlib
import re
import select
import secrets
import shutil
import signal
import stat
import sys


class RuntimeError_(Exception):
    pass


IDENTITY = "process.identity"
ACTIVE = ("swtpm.pid", "owner.pid", "runtime.path", "socket.path", IDENTITY)
REMOVABLE = ("swtpm.pid", "owner.pid", "runtime.path", "socket.path", IDENTITY)


def _dir(path: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise RuntimeError_("invalid private directory")
    return fd


def _file(fd: int, name: str, required: bool = True) -> bytes | None:
    try:
        item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        if required:
            raise RuntimeError_(f"missing {name}")
        return None
    try:
        info = os.fstat(item)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
            raise RuntimeError_(f"invalid {name}")
        return os.read(item, 4097)
    finally:
        os.close(item)


def _text(fd: int, name: str, required: bool = True) -> str | None:
    value = _file(fd, name, required)
    if value is None:
        return None
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError_(f"invalid {name}") from error
    if "\0" in decoded or decoded.count("\n") > 1:
        raise RuntimeError_(f"invalid {name}")
    return decoded[:-1] if decoded.endswith("\n") else decoded


def _write(fd: int, name: str, value: bytes) -> None:
    temporary = f".{name}.{os.getpid()}"
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.write(output, value)
        os.fsync(output)
    finally:
        os.close(output)
    os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
    os.fsync(fd)


def _unlink(fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=fd)
    except FileNotFoundError:
        pass


def _identity(raw: bytes, state: str) -> dict:
    try:
        item = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError_("invalid process identity") from error
    keys = {"version", "pid", "start", "executable", "state"}
    if not isinstance(item, dict) or set(item) != keys or item["version"] != 1:
        raise RuntimeError_("invalid process identity schema")
    if (not isinstance(item["pid"], int) or item["pid"] <= 1 or
            not isinstance(item["start"], str) or not item["start"].isdecimal() or
            not isinstance(item["executable"], str) or not isinstance(item["state"], str) or
            item["state"] != f"dir={state}/tpm,mode=0600"):
        raise RuntimeError_("invalid process identity")
    expected = pathlib.Path(shutil.which("swtpm") or "").resolve()
    try:
        recorded = pathlib.Path(item["executable"]).resolve(strict=True)
    except OSError as error:
        raise RuntimeError_("invalid swtpm executable") from error
    if not expected or recorded != expected:
        raise RuntimeError_("unexpected swtpm executable")
    return item


def _start(pid: int) -> str:
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
        value = raw.rsplit(b") ", 1)[1].split()[19].decode("ascii")
    except (OSError, IndexError, UnicodeDecodeError) as error:
        raise RuntimeError_("invalid process stat") from error
    if not value.isdecimal():
        raise RuntimeError_("invalid process start")
    return value


def _runtime_spec(runtime: str, socket_path: str) -> tuple[pathlib.Path, pathlib.Path]:
    try:
        temporary = pathlib.Path(os.environ.get("TMPDIR", "/tmp")).resolve(strict=True)
    except OSError as error:
        raise RuntimeError_("invalid TMPDIR") from error
    runtime_path = pathlib.Path(runtime)
    if (not runtime_path.is_absolute() or runtime_path.parent != temporary or
            re.fullmatch(r"pbns-swtpm\.[A-Za-z0-9]{6,32}", runtime_path.name) is None or
            socket_path != runtime + "/server.sock"):
        raise RuntimeError_("invalid runtime metadata")
    return runtime_path, temporary


def _runtime(fd: int) -> tuple[str, str, int, int]:
    runtime = _text(fd, "runtime.path")
    socket_path = _text(fd, "socket.path")
    runtime_path, temporary = _runtime_spec(runtime, socket_path)
    runtime_fd = _dir(runtime)
    parent = os.open(str(pathlib.Path(runtime).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        current = os.stat(pathlib.Path(runtime).name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(runtime_fd)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise RuntimeError_("runtime path changed")
    except Exception:
        os.close(parent)
        os.close(runtime_fd)
        raise
    return runtime, socket_path, runtime_fd, parent


def _inventory(runtime_fd: int, live: bool) -> None:
    expected = {"server.sock", "server.sock.ctrl"} if live else set()
    if set(os.listdir(runtime_fd)) != expected:
        raise RuntimeError_("unexpected runtime inventory")
    if live:
        for name in expected:
            info = os.stat(name, dir_fd=runtime_fd, follow_symlinks=False)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or
                    stat.S_IMODE(info.st_mode) != 0o600):
                raise RuntimeError_("invalid runtime socket")


def _live(identity: dict, signal_process: bool = True) -> None:
    pid = identity["pid"]
    descriptor = os.pidfd_open(pid)
    try:
        root = pathlib.Path(f"/proc/{pid}")
        if root.stat().st_uid != os.getuid() or _start(pid) != identity["start"]:
            raise RuntimeError_("process identity mismatch")
        if (root / "exe").resolve(strict=True) != pathlib.Path(identity["executable"]):
            raise RuntimeError_("process executable mismatch")
        arguments = [x for x in (root / "cmdline").read_bytes().split(b"\0") if x]
        if identity["state"].encode() not in arguments:
            raise RuntimeError_("process state argument mismatch")
        if not signal_process:
            return
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        if not poller.poll(5000):
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            if not poller.poll(1000):
                raise RuntimeError_("swtpm did not terminate")
    finally:
        os.close(descriptor)


def _gone(identity: dict) -> None:
    root = pathlib.Path(f"/proc/{identity['pid']}")
    if not root.exists():
        return
    # A reused PID is only compared by start identity: never inspect exe/cmdline or signal it.
    if _start(identity["pid"]) != identity["start"]:
        raise RuntimeError_("recorded PID has been reused")
    raise RuntimeError_("recorded swtpm process is still live")


def _intent(identity: dict, runtime: str, socket_path: str, runtime_fd: int, quarantine: str) -> bytes:
    information = os.fstat(runtime_fd)
    return (json.dumps({"version": 1, "identity": identity, "runtime": runtime,
                        "socket": socket_path, "device": information.st_dev,
                        "inode": information.st_ino, "quarantine": quarantine},
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def _read_intent(fd: int, state: str) -> tuple[dict, str, str, int, int, str] | None:
    raw = _file(fd, "pause.intent", required=False)
    if raw is None:
        return None
    try:
        item = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError_("invalid pause intent") from error
    if not isinstance(item, dict) or set(item) != {"version", "identity", "runtime", "socket", "device", "inode", "quarantine"} or item["version"] != 1:
        raise RuntimeError_("invalid pause intent schema")
    identity = _identity(json.dumps(item["identity"], separators=(",", ":")).encode(), state)
    if (not isinstance(item["runtime"], str) or item["socket"] != item["runtime"] + "/server.sock" or
            not isinstance(item["device"], int) or item["device"] < 0 or
            not isinstance(item["inode"], int) or item["inode"] <= 0 or
            not isinstance(item["quarantine"], str) or
            re.fullmatch(r"\.pbns-swtpm-quarantine\.[A-Za-z0-9]{16}", item["quarantine"]) is None):
        raise RuntimeError_("invalid pause intent runtime")
    _runtime_spec(item["runtime"], item["socket"])
    return identity, item["runtime"], item["socket"], item["device"], item["inode"], item["quarantine"]


def _crash(step: str) -> None:
    if os.environ.get("PBNS_SWTPM_TEST_CRASH_STEP") == step:
        os._exit(97)


def _mark_paused(fd: int) -> None:
    if os.environ.get("PBNS_SWTPM_TEST_FAIL_MARKER") == "1":
        raise RuntimeError_("injected paused marker failure")
    temporary = f".paused.{os.getpid()}"
    output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.write(output, b"PBNS_SWTPM_PAUSED_V2\n")
        os.fsync(output)
    finally:
        os.close(output)
    try:
        os.link(temporary, "paused", src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        _unlink(fd, temporary)
    os.fsync(fd)


def record(state: str, pid: int, executable: str) -> None:
    fd = _dir(state)
    try:
        expected = pathlib.Path(shutil.which("swtpm") or "").resolve()
        actual = pathlib.Path(executable).resolve(strict=True)
        root = pathlib.Path(f"/proc/{pid}")
        arguments = [x for x in (root / "cmdline").read_bytes().split(b"\0") if x]
        if actual != expected or (root / "exe").resolve(strict=True) != expected or f"dir={state}/tpm,mode=0600".encode() not in arguments:
            raise RuntimeError_("cannot record unverified swtpm")
        value = json.dumps({"version": 1, "pid": pid, "start": _start(pid),
                            "executable": str(expected), "state": f"dir={state}/tpm,mode=0600"},
                           sort_keys=True, separators=(",", ":")).encode() + b"\n"
        if os.environ.get("PBNS_SWTPM_TEST_RECORD_FAIL") == "1":
            raise RuntimeError_("injected identity publication failure")
        _write(fd, IDENTITY, value)
    finally:
        os.close(fd)


def terminate_unrecorded(state: str, pid: int, executable: str) -> None:
    expected = pathlib.Path(shutil.which("swtpm") or "").resolve()
    actual = pathlib.Path(executable).resolve(strict=True)
    if actual != expected:
        raise RuntimeError_("unexpected unrecorded executable")
    identity = {"pid": pid, "start": _start(pid), "executable": str(expected),
                "state": f"dir={state}/tpm,mode=0600"}
    _live(identity)


def verify_live(state: str) -> str:
    fd = _dir(state)
    try:
        if _text(fd, "managed") != "PBNS_SWTPM_STATE_V1":
            raise RuntimeError_("invalid managed marker")
        identity = _identity(_file(fd, IDENTITY), state)
        if _text(fd, "owner.pid") is None or not _text(fd, "owner.pid").isdecimal():
            raise RuntimeError_("invalid owner metadata")
        if _text(fd, "swtpm.pid") != str(identity["pid"]):
            raise RuntimeError_("swtpm PID differs from identity")
        runtime, socket_path, runtime_fd, parent_fd = _runtime(fd)
        try:
            _inventory(runtime_fd, True)
            _live(identity, signal_process=False)
        finally:
            os.close(runtime_fd)
            os.close(parent_fd)
        return socket_path
    finally:
        os.close(fd)


def terminate(state: str) -> None:
    fd = _dir(state)
    try:
        identity = _identity(_file(fd, IDENTITY), state)
        pid = _text(fd, "swtpm.pid")
        if pid != str(identity["pid"]):
            raise RuntimeError_("swtpm PID differs from identity")
        _live(identity)
    finally:
        os.close(fd)


def pause(state: str) -> None:
    fd = _dir(state)
    try:
        if _text(fd, "managed") != "PBNS_SWTPM_STATE_V1":
            raise RuntimeError_("invalid managed marker")
        paused = _file(fd, "paused", required=False)
        saved = _read_intent(fd, state)
        if paused is not None:
            if paused != b"PBNS_SWTPM_PAUSED_V2\n":
                raise RuntimeError_("invalid paused marker")
            if saved is not None:
                _unlink(fd, "pause.intent")
                os.fsync(fd)
            return
        if saved is None:
            for name in ACTIVE:
                _file(fd, name, required=(name != "swtpm.pid"))
            identity = _identity(_file(fd, IDENTITY), state)
            if _text(fd, "owner.pid") is None or not _text(fd, "owner.pid").isdecimal():
                raise RuntimeError_("invalid owner metadata")
            runtime, socket_path, runtime_fd, parent_fd = _runtime(fd)
            try:
                pid = _text(fd, "swtpm.pid", required=False)
                if pid is not None:
                    if pid != str(identity["pid"]):
                        raise RuntimeError_("swtpm PID differs from identity")
                    _inventory(runtime_fd, True)
                else:
                    _inventory(runtime_fd, False)
                    _gone(identity)
                parent_names = set(os.listdir(parent_fd))
                quarantine = ".pbns-swtpm-quarantine." + secrets.token_hex(8)
                while quarantine in parent_names:
                    quarantine = ".pbns-swtpm-quarantine." + secrets.token_hex(8)
                _write(fd, "pause.intent", _intent(identity, runtime, socket_path, runtime_fd, quarantine))
            finally:
                os.close(runtime_fd)
                os.close(parent_fd)
            _crash("after-intent")
            saved = _read_intent(fd, state)
        identity, runtime, socket_path, expected_device, expected_inode, quarantine = saved
        retained_identity = _file(fd, IDENTITY, required=False)
        if retained_identity is not None and _identity(retained_identity, state) != identity:
            raise RuntimeError_("retained identity differs from pause intent")
        retained_runtime = _text(fd, "runtime.path", required=False)
        retained_socket = _text(fd, "socket.path", required=False)
        if ((retained_runtime is not None and retained_runtime != runtime) or
                (retained_socket is not None and retained_socket != socket_path)):
            raise RuntimeError_("retained runtime differs from pause intent")
        runtime_path, parent_path = _runtime_spec(runtime, socket_path)
        transition_parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                original = os.stat(runtime_path.name, dir_fd=transition_parent, follow_symlinks=False)
            except FileNotFoundError:
                original = None
            try:
                quarantined = os.stat(quarantine, dir_fd=transition_parent, follow_symlinks=False)
            except FileNotFoundError:
                quarantined = None
            if original is not None and quarantined is not None:
                raise RuntimeError_("mixed original and quarantine runtime state")
            if quarantined is not None:
                if (quarantined.st_dev, quarantined.st_ino) != (expected_device, expected_inode):
                    raise RuntimeError_("runtime quarantine identity mismatch")
                stale = _text(fd, "swtpm.pid", required=False)
                if stale is not None:
                    if stale != str(identity["pid"]):
                        raise RuntimeError_("swtpm PID differs from intent")
                    _gone(identity)
                    _unlink(fd, "swtpm.pid")
                else:
                    _gone(identity)
                os.rmdir(quarantine, dir_fd=transition_parent)
                os.fsync(transition_parent)
            elif original is None:
                if _text(fd, "swtpm.pid", required=False) is not None:
                    raise RuntimeError_("runtime disappeared while swtpm PID remains")
                _gone(identity)
        finally:
            os.close(transition_parent)
        try:
            runtime_fd = _dir(runtime)
        except FileNotFoundError:
            # A crash after rmdir retains the intent; verify it cannot name a live PID.
            if _text(fd, "swtpm.pid", required=False) is not None:
                raise RuntimeError_("runtime disappeared while swtpm PID remains")
            _gone(identity)
        else:
            parent_fd = os.open(str(pathlib.Path(runtime).parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                current = os.stat(pathlib.Path(runtime).name, dir_fd=parent_fd, follow_symlinks=False)
                opened = os.fstat(runtime_fd)
                if ((current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino) or
                        (opened.st_dev, opened.st_ino) != (expected_device, expected_inode)):
                    raise RuntimeError_("runtime path changed")
                pid = _text(fd, "swtpm.pid", required=False)
                if pid is not None:
                    if pid != str(identity["pid"]):
                        raise RuntimeError_("swtpm PID differs from intent")
                    try:
                        _inventory(runtime_fd, True)
                    except RuntimeError_:
                        # A swtpm control shutdown can leave only its stale PID file.
                        _inventory(runtime_fd, False)
                        _gone(identity)
                        _unlink(fd, "swtpm.pid")
                    else:
                        _live(identity)
                else:
                    _inventory(runtime_fd, False)
                    _gone(identity)
                for name in ("server.sock", "server.sock.ctrl"):
                    _unlink(runtime_fd, name)
                if os.listdir(runtime_fd):
                    raise RuntimeError_("runtime did not become empty")
                if quarantine in os.listdir(parent_fd):
                    raise RuntimeError_("runtime quarantine already exists")
                os.rename(pathlib.Path(runtime).name, quarantine, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
                if (moved.st_dev, moved.st_ino) != (expected_device, expected_inode):
                    raise RuntimeError_("runtime quarantine identity mismatch")
                _crash("after-quarantine")
                os.rmdir(quarantine, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(runtime_fd)
                os.close(parent_fd)
        _crash("after-runtime")
        for name in REMOVABLE:
            _unlink(fd, name)
        os.fsync(fd)
        _crash("after-metadata")
        _mark_paused(fd)
        _unlink(fd, "pause.intent")
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pause", action="store_true")
    group.add_argument("--terminate", action="store_true")
    group.add_argument("--verify-live", action="store_true")
    group.add_argument("--terminate-unrecorded", nargs=2, metavar=("PID", "EXECUTABLE"))
    group.add_argument("--record", nargs=2, metavar=("PID", "EXECUTABLE"))
    parser.add_argument("state")
    args = parser.parse_args()
    try:
        if args.pause:
            pause(args.state)
        elif args.terminate:
            terminate(args.state)
        elif args.verify_live:
            print(verify_live(args.state))
        elif args.terminate_unrecorded:
            terminate_unrecorded(args.state, int(args.terminate_unrecorded[0]), args.terminate_unrecorded[1])
        else:
            record(args.state, int(args.record[0]), args.record[1])
    except (OSError, RuntimeError_, ValueError, UnicodeError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
