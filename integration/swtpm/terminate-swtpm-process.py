#!/usr/bin/env python3
"""Compatibility entrypoint for descriptor-bound swtpm termination."""
import pathlib
import subprocess
import sys


class ProcessError(Exception):
    pass


def terminate(state: pathlib.Path) -> None:
    completed = subprocess.run(
        [str(pathlib.Path(__file__).with_name("quiesce-swtpm-runtime.py")), "--terminate", str(state)],
        check=False,
    )
    if completed.returncode:
        raise ProcessError("owned swtpm termination failed")


def main() -> int:
    if len(sys.argv) != 2:
        return 2
    try:
        terminate(pathlib.Path(sys.argv[1]))
    except (OSError, ProcessError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
