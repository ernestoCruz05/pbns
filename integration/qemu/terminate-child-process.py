#!/usr/bin/env python3
import argparse
import math
import os
import pathlib
import select
import signal


class ProcessError(Exception):
    pass


def _start_time(pid: int) -> str:
    encoded = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
    try:
        value = encoded.rsplit(b") ", 1)[1].split()[19].decode("ascii")
    except (IndexError, UnicodeDecodeError) as error:
        raise ProcessError("invalid process stat") from error
    if not value.isdecimal():
        raise ProcessError("invalid process start identity")
    return value


def terminate(
    pid: int,
    executable: pathlib.Path,
    start_time: str,
    *,
    term_timeout: float = 5.0,
    kill_timeout: float = 1.0,
) -> None:
    if pid <= 1 or not start_time.isdecimal():
        raise ProcessError("invalid process identity")
    expected_executable = executable.resolve(strict=True)
    descriptor = os.pidfd_open(pid)
    try:
        process_root = pathlib.Path(f"/proc/{pid}")
        if process_root.stat().st_uid != os.getuid():
            raise ProcessError("process owner mismatch")
        if (process_root / "exe").resolve(strict=True) != expected_executable:
            raise ProcessError("process executable mismatch")
        if _start_time(pid) != start_time:
            raise ProcessError("process start identity mismatch")
        signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        if not poller.poll(max(1, int(term_timeout * 1000))):
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            if not poller.poll(max(1, int(kill_timeout * 1000))):
                raise ProcessError("process did not terminate")
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int)
    parser.add_argument("executable", type=pathlib.Path)
    parser.add_argument("start_time")
    parser.add_argument("--term-timeout", type=float, default=5.0)
    parser.add_argument("--kill-timeout", type=float, default=1.0)
    arguments = parser.parse_args()
    if (not math.isfinite(arguments.term_timeout) or arguments.term_timeout <= 0 or
            not math.isfinite(arguments.kill_timeout) or arguments.kill_timeout <= 0):
        return 2
    try:
        terminate(
            arguments.pid, arguments.executable, arguments.start_time,
            term_timeout=arguments.term_timeout, kill_timeout=arguments.kill_timeout,
        )
    except (OSError, ProcessError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
