#!/usr/bin/env python3
import argparse
import filecmp
import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import time


NV_INDEX = "0x01c0000a"
NV_ATTRIBUTES = "platformcreate|authread|ownerread|ppread|ppwrite|noda|writedefine"
DEFINE_ATTRIBUTES = "platformcreate|authread|ownerread|ppread|ppwrite|no_da|writedefine"
PBNS_EK_ATTRIBUTES = "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt"
MAX_CERTIFICATE_SIZE = 16384
COMMAND_OUTPUT_CAP = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 60
EXPECTED_ATTRIBUTE_NAMES = frozenset(
    ("platformcreate", "authread", "ownerread", "ppread", "ppwrite", "no_da", "written", "writedefine")
)
EXPECTED_ATTRIBUTE_VALUE = 0x62072001


def private_directory(value: str) -> pathlib.Path:
    path = pathlib.Path(value)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise argparse.ArgumentTypeError("private directory must be an absolute directory")
    metadata = path.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o777 != 0o700:
        raise argparse.ArgumentTypeError("private directory must be owned mode 0700")
    if next(path.iterdir(), None) is not None:
        raise argparse.ArgumentTypeError("private directory must be empty")
    return path


def tcti_value(value: str) -> str:
    prefix = "swtpm:path="
    if not value.startswith(prefix):
        raise argparse.ArgumentTypeError("TCTI must use swtpm:path=ABSOLUTE_SOCKET")
    socket = pathlib.Path(value[len(prefix) :])
    if not socket.is_absolute():
        raise argparse.ArgumentTypeError("swtpm socket must be absolute")
    return value


class CommandError(RuntimeError):
    def __init__(self, command: list[str], output: str, reason: str) -> None:
        super().__init__(reason)
        self.command = command
        self.output = output


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    assert process.stdout is not None
    output = bytearray()
    failure = ""
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "command deadline expired"
                break
            readable, _, _ = select.select([process.stdout], [], [], 0.2)
            if not readable:
                continue
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            if len(output) + len(chunk) > COMMAND_OUTPUT_CAP:
                failure = "command output exceeded the bound"
                break
            output.extend(chunk)
        while process.poll() is not None:
            readable, _, _ = select.select([process.stdout], [], [], 0)
            if not readable:
                break
            chunk = os.read(process.stdout.fileno(), 4096)
            if not chunk:
                break
            if len(output) + len(chunk) > COMMAND_OUTPUT_CAP:
                failure = "command output exceeded the bound"
                break
            output.extend(chunk)
    finally:
        if failure:
            stop_process(process)
        process.stdout.close()
    encoded = output.decode("utf-8", errors="replace")
    if failure:
        raise CommandError(command, encoded, failure)
    try:
        returncode = process.wait(timeout=1)
    except subprocess.TimeoutExpired as error:
        stop_process(process)
        raise CommandError(command, encoded, "command did not exit") from error
    if returncode != 0:
        raise CommandError(command, encoded, f"command exited with status {returncode}")
    return subprocess.CompletedProcess(command, returncode, encoded, None)


def validate_ek_public(description: str) -> None:
    attributes = re.search(
        r"attributes:\s+value:\s*([^\r\n]+)\s+raw:\s*(0x[0-9a-f]+)",
        description,
        flags=re.IGNORECASE,
    )
    expected = frozenset(PBNS_EK_ATTRIBUTES.split("|"))
    names = (
        frozenset(item.strip().lower() for item in attributes.group(1).split("|"))
        if attributes is not None
        else frozenset()
    )
    required = (
        r"type:\s+value:\s*ecc.*curve-id:\s+value:\s*NIST p256.*"
        r"kdfa-alg:\s+value:\s*null.*scheme:\s+value:\s*null.*"
        r"sym-alg:\s+value:\s*aes.*sym-mode:\s+value:\s*cfb.*sym-keybits:\s*128"
    )
    if (
        attributes is None
        or names != expected
        or int(attributes.group(2), 16) != 0x30472
        or re.search(required, description, flags=re.IGNORECASE | re.DOTALL) is None
        or "authorization policy:" in description.lower()
    ):
        raise SystemExit("swtpm PBNS EK public profile mismatch")


def validate_nv_public(public: str, certificate_size: int) -> None:
    if certificate_size <= 0 or certificate_size > MAX_CERTIFICATE_SIZE:
        raise SystemExit("invalid expected NV size")
    lines = [line.strip() for line in public.splitlines() if line.strip()]
    index = re.fullmatch(r"(0x[0-9a-fA-F]+):", lines[0]) if lines else None
    if index is None or int(index.group(1), 16) != int(NV_INDEX, 16):
        raise SystemExit("NV public metadata has the wrong index")
    if not re.search(
        r"hash algorithm:\s+friendly:\s*sha256\s+value:\s*0x0*b(?:\s|$)",
        public,
        flags=re.IGNORECASE,
    ):
        raise SystemExit("NV public metadata has the wrong name algorithm")
    attributes = re.search(
        r"attributes:\s+friendly:\s*([^\r\n]+)\s+value:\s*(0x[0-9a-f]+)",
        public,
        flags=re.IGNORECASE,
    )
    if attributes is None:
        raise SystemExit("NV public metadata lacks attributes")
    names = frozenset(item.strip().lower() for item in attributes.group(1).split("|"))
    if names != EXPECTED_ATTRIBUTE_NAMES or int(attributes.group(2), 16) != EXPECTED_ATTRIBUTE_VALUE:
        raise SystemExit("NV public metadata has the wrong attributes")
    size = re.search(r"(?:^|\n)\s*size:\s*(\d+)\s*(?:\n|$)", public, flags=re.IGNORECASE)
    if size is None or int(size.group(1), 10) != certificate_size:
        raise SystemExit("NV public metadata has the wrong size")


def require_tools(names: tuple[str, ...]) -> None:
    for name in names:
        if not any(
            (pathlib.Path(directory) / name).is_file()
            for directory in os.environ.get("PATH", "").split(os.pathsep)
            if directory
        ):
            raise SystemExit(f"missing required tool: {name}")


def main() -> None:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--tcti", type=tcti_value, required=True)
    parser.add_argument("--private-dir", type=private_directory, required=True)
    arguments = parser.parse_args()
    require_tools(
        (
            "openssl",
            "tpm2_createprimary",
            "tpm2_readpublic",
            "tpm2_print",
            "tpm2_nvdefine",
            "tpm2_nvwrite",
            "tpm2_nvreadpublic",
            "tpm2_nvread",
        )
    )
    environment = os.environ.copy()
    environment["TPM2TOOLS_TCTI"] = arguments.tcti
    root = arguments.private_dir
    paths = {
        name: root / name
        for name in (
            "manufacturer-root-key.pem",
            "manufacturer-root-cert.pem",
            "ek.ctx",
            "ek-public.tss",
            "ek-public.pem",
            "ek-public.txt",
            "ek-leaf.pem",
            "ek-leaf.der",
            "ek-leaf-readback.der",
            "ek-extensions.cnf",
            "nv-public.txt",
            "provision.log",
        )
    }
    transcript: list[str] = []

    def checked(command: list[str]) -> subprocess.CompletedProcess[str]:
        transcript.append(" ".join(command))
        result = run(command, environment)
        if result.stdout:
            transcript.append(result.stdout.rstrip())
        return result

    checked(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            str(paths["manufacturer-root-key.pem"]),
        ]
    )
    checked(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            str(paths["manufacturer-root-key.pem"]),
            "-subj",
            "/CN=PBNS private swtpm manufacturer root",
            "-days",
            "3650",
            "-sha256",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-out",
            str(paths["manufacturer-root-cert.pem"]),
        ]
    )
    checked(
        [
            "tpm2_createprimary",
            "-C",
            "e",
            "-g",
            "sha256",
            "-G",
            "ecc:null:aes128cfb",
            "-a",
            PBNS_EK_ATTRIBUTES,
            "-o",
            str(paths["ek-public.tss"]),
            "-c",
            str(paths["ek.ctx"]),
        ]
    )
    public_description = checked(
        ["tpm2_print", "-t", "TPM2B_PUBLIC", str(paths["ek-public.tss"])]
    ).stdout
    paths["ek-public.txt"].write_text(public_description, encoding="utf-8")
    validate_ek_public(public_description)
    checked(
        [
            "tpm2_readpublic",
            "-c",
            str(paths["ek.ctx"]),
            "-f",
            "pem",
            "-o",
            str(paths["ek-public.pem"]),
        ]
    )
    paths["ek-extensions.cnf"].write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,keyAgreement\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid:always\n",
        encoding="ascii",
    )
    checked(
        [
            "openssl",
            "x509",
            "-new",
            "-force_pubkey",
            str(paths["ek-public.pem"]),
            "-CA",
            str(paths["manufacturer-root-cert.pem"]),
            "-CAkey",
            str(paths["manufacturer-root-key.pem"]),
            "-set_serial",
            "1",
            "-subj",
            "/CN=PBNS private swtpm P-256 EK",
            "-days",
            "3650",
            "-sha256",
            "-extfile",
            str(paths["ek-extensions.cnf"]),
            "-out",
            str(paths["ek-leaf.pem"]),
        ]
    )
    checked(
        [
            "openssl",
            "x509",
            "-in",
            str(paths["ek-leaf.pem"]),
            "-outform",
            "DER",
            "-out",
            str(paths["ek-leaf.der"]),
        ]
    )
    ek_description = checked(
        [
            "openssl",
            "pkey",
            "-pubin",
            "-in",
            str(paths["ek-public.pem"]),
            "-text",
            "-noout",
        ]
    ).stdout
    if "prime256v1" not in ek_description and "P-256" not in ek_description:
        raise SystemExit("swtpm EK is not P-256")
    certificate_public = checked(
        [
            "openssl",
            "x509",
            "-in",
            str(paths["ek-leaf.pem"]),
            "-pubkey",
            "-noout",
        ]
    ).stdout.strip()
    if certificate_public != paths["ek-public.pem"].read_text(encoding="ascii").strip():
        raise SystemExit("EK certificate public key mismatch")
    certificate_size = paths["ek-leaf.der"].stat().st_size
    if certificate_size <= 0 or certificate_size > MAX_CERTIFICATE_SIZE:
        raise SystemExit("generated EK certificate size is out of bounds")
    checked(
        [
            "tpm2_nvdefine",
            NV_INDEX,
            "-C",
            "p",
            "-s",
            str(certificate_size),
            "-g",
            "sha256",
            "-a",
            DEFINE_ATTRIBUTES,
        ]
    )
    checked(
        [
            "tpm2_nvwrite",
            NV_INDEX,
            "-C",
            "p",
            "-i",
            str(paths["ek-leaf.der"]),
        ]
    )
    public = checked(["tpm2_nvreadpublic", NV_INDEX]).stdout
    paths["nv-public.txt"].write_text(public, encoding="utf-8")
    validate_nv_public(public, certificate_size)
    checked(
        [
            "tpm2_nvread",
            NV_INDEX,
            "-C",
            "o",
            "-s",
            str(certificate_size),
            "-o",
            str(paths["ek-leaf-readback.der"]),
        ]
    )
    if not filecmp.cmp(paths["ek-leaf.der"], paths["ek-leaf-readback.der"], shallow=False):
        raise SystemExit("EK certificate NV readback mismatch")
    for path in paths.values():
        if path.exists():
            path.chmod(0o600)
    paths["provision.log"].write_text("\n".join(transcript) + "\n", encoding="utf-8")
    paths["provision.log"].chmod(0o600)
    print(f"SWTPM EK CERTIFICATE PASS index={NV_INDEX} size={certificate_size}")


if __name__ == "__main__":
    try:
        main()
    except CommandError as error:
        if error.output:
            print(error.output, file=sys.stderr, end="")
        raise SystemExit(f"command failed: {error.command[0]}: {error}") from error
