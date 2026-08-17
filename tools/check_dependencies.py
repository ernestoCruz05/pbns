#!/usr/bin/env python3

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterable


APPROVED_LICENSES = frozenset(
    {
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-2-Clause-Patent",
        "BSD-3-Clause",
        "MIT",
        "Unlicense",
    }
)
SUBMODULE_PATHS = {
    "qcbor": pathlib.Path("vendor/QCBOR"),
    "t_cose": pathlib.Path("vendor/t_cose"),
    "cose_c": pathlib.Path("vendor/COSE-C"),
    "cn_cbor": pathlib.Path("vendor/cn-cbor"),
    "cose_examples": pathlib.Path("vendor/cose-examples"),
}
EXTERNAL_PATHS = {
    "edk2": pathlib.Path(".deps/edk2"),
    "pico_sdk": pathlib.Path(".deps/pico_sdk"),
    "mbedtls": pathlib.Path(".deps/pico_sdk/lib/mbedtls"),
    "tinyusb": pathlib.Path(".deps/pico_sdk/lib/tinyusb"),
    "picotool": pathlib.Path(".deps/picotool"),
    "tpm2_tss": pathlib.Path(".deps/tpm2-tss"),
}
LICENSE_FILES = {
    "qcbor": "LICENSE",
    "t_cose": "LICENSE",
    "cose_c": "LICENSE",
    "cn_cbor": "LICENSE",
    "cose_examples": "LICENSE",
    "edk2": "License.txt",
    "pico_sdk": "LICENSE.TXT",
    "mbedtls": "LICENSE",
    "tinyusb": "LICENSE",
    "picotool": "LICENSE.TXT",
    "tpm2_tss": "LICENSE",
}
GO_LICENSE_DIGESTS = {
    "go_bbolt.txt": (
        "c15d721c37e277a11584547de6d618541501f7aa10c4e32a945a4f9ff36cb0f6"
    ),
    "go_fxamacker_cbor.txt": (
        "78cad457d5ea7318230f3d969d4cdf29cef45524a1fc8ca3a97646da1ad7a841"
    ),
    "go_google_attestation.txt": (
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    ),
    "go_google_tpm.txt": (
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    ),
    "go_veraison_cose.txt": (
        "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"
    ),
    "go_x448_float16.txt": (
        "a555f1194fdac34da70fb416968f7e2217b02352c26c1eac2fa45fcb4290ae8d"
    ),
    "go_x_sys.txt": (
        "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
    ),
}
COSE_C_REMOVED_LINE = "EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);"
COSE_C_ADDED_LINE = "const EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);"
COSE_C_GETTER_ADDED_LINES = (
    "byte *COSE_Enveloped_GetContent(HCOSE_ENVELOPED h,",
    "size_t *pcbContent,",
    "cose_errback *perror)",
    "{",
    "COSE_Enveloped *cose = (COSE_Enveloped *)h;",
    "if (!IsValidEnvelopedHandle(h) || (pcbContent == nullptr)) {",
    "if (perror != nullptr) {",
    "perror->err = COSE_ERR_INVALID_PARAMETER;",
    "}",
    "return nullptr;",
    "}",
    "*pcbContent = cose->cbContent;",
    "return const_cast<byte *>(cose->pbContent);",
    "}",
)
COSE_C_GCM_LENGTH_REMOVED_LINES = (
    "EVP_DecryptFinal(ctx, rgbOut + cbOut, &cbOut), COSE_ERR_DECRYPT_FAILED);",
    "pcose->cbContent = cbOut;",
)
COSE_C_GCM_LENGTH_ADDED_LINES = (
    "int cbFinal = 0;",
    "EVP_DecryptFinal(ctx, rgbOut + cbOut, &cbFinal), COSE_ERR_DECRYPT_FAILED);",
    "pcose->cbContent = (size_t)cbOut + (size_t)cbFinal;",
)
COSE_C_OPENSSL_LIFECYCLE_DIFF_SHA256 = (
    "bdd70e846a64f74c204e11d2915bbba1c52959f9a2503a51521e4063a580e39c"
)
COSE_C_PATCHES = (
    pathlib.Path("patches/COSE-C/0001-openssl3-const-public-key.patch"),
    pathlib.Path("patches/COSE-C/0002-implement-enveloped-content-getter.patch"),
    pathlib.Path("patches/COSE-C/0003-fix-gcm-plaintext-length.patch"),
    pathlib.Path("patches/COSE-C/0004-free-openssl-key-resources.patch"),
)
T_COSE_OPENSSL_CLEANUP_DIFF_SHA256 = (
    "7f1da8a0d41a3a519dc079b793991204ee1c3ea20c7990d94cc20977bb4ef857"
)
T_COSE_TRANSIENT_ZERO_PATCH_SHA256 = (
    "97ff280a1a66e17afa6de8ca5500c3c2035ca9833820c40b41c59d400a4b370c"
)
T_COSE_PATCHES = (
    pathlib.Path("patches/t_cose/0001-free-openssl-ec-temporaries.patch"),
    pathlib.Path("patches/t_cose/0002-zero-transient-encryption-material.patch"),
)
CN_CBOR_PATCHES = (
    pathlib.Path("patches/cn-cbor/0001-guard-zero-length-copy.patch"),
)


class LockError(ValueError):
    pass


@dataclasses.dataclass(frozen=True, slots=True)
class Dependency:
    name: str
    repository: str
    commit: str
    license: str
    license_sha256: str


def load_lock(path: pathlib.Path) -> dict[str, Dependency]:
    dependencies: dict[str, Dependency] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LockError(f"cannot read dependency lock {path}: {error}") from error

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 5:
            raise LockError(f"line {line_number}: expected five pipe-separated fields")
        name, repository, commit, license_id, license_sha256 = fields
        if not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise LockError(f"line {line_number}: invalid dependency name")
        if name in dependencies:
            raise LockError(f"line {line_number}: duplicate dependency {name}")
        if not repository.startswith("https://") or not repository.endswith(".git"):
            raise LockError(f"line {line_number}: repository must be an HTTPS Git URL")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise LockError(f"line {line_number}: commit must be 40 lowercase hexadecimal characters")
        if license_id not in APPROVED_LICENSES:
            raise LockError(f"line {line_number}: unapproved license {license_id}")
        if not re.fullmatch(r"[0-9a-f]{64}", license_sha256):
            raise LockError(f"line {line_number}: license digest must be SHA-256")
        dependencies[name] = Dependency(name, repository, commit, license_id, license_sha256)

    if not dependencies:
        raise LockError("dependency lock is empty")
    return dependencies


def validate_cose_c_patch(path: pathlib.Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LockError(f"cannot read COSE-C patch {path}: {error}") from error

    removed = [
        line[1:].strip()
        for line in lines
        if line.startswith("-") and not line.startswith(("---", "-- "))
    ]
    added = [
        line[1:].strip()
        for line in lines
        if line.startswith("+") and not line.startswith("+++")
    ]
    changed_paths = [line for line in lines if line.startswith("diff --git ")]
    const_correctness = (
        changed_paths == ["diff --git a/src/openssl.cpp b/src/openssl.cpp"]
        and removed == [COSE_C_REMOVED_LINE]
        and added == [COSE_C_ADDED_LINE]
    )
    content_getter = (
        changed_paths == ["diff --git a/src/Encrypt.cpp b/src/Encrypt.cpp"]
        and removed == []
        and tuple(added) == COSE_C_GETTER_ADDED_LINES
    )
    gcm_plaintext_length = (
        changed_paths == ["diff --git a/src/openssl.cpp b/src/openssl.cpp"]
        and tuple(removed) == COSE_C_GCM_LENGTH_REMOVED_LINES
        and tuple(added) == COSE_C_GCM_LENGTH_ADDED_LINES
    )
    openssl_lifecycle = False
    expected_lifecycle_paths = [
        "diff --git a/src/CoseKey.cpp b/src/CoseKey.cpp",
        "diff --git a/src/openssl.cpp b/src/openssl.cpp",
    ]
    if changed_paths == expected_lifecycle_paths:
        try:
            diff_start = lines.index(expected_lifecycle_paths[0])
            trailer = lines.index("-- ", diff_start)
        except ValueError:
            pass
        else:
            if trailer + 2 == len(lines) and re.fullmatch(
                r"[0-9]+(?:\.[0-9]+)+", lines[-1]
            ):
                diff = "\n".join(lines[diff_start:trailer]) + "\n"
                openssl_lifecycle = (
                    hashlib.sha256(diff.encode("utf-8")).hexdigest()
                    == COSE_C_OPENSSL_LIFECYCLE_DIFF_SHA256
                )
    if not (
        const_correctness
        or content_getter
        or gcm_plaintext_length
        or openssl_lifecycle
    ):
        raise LockError("COSE-C compatibility patch contains an unapproved source change")


def validate_cn_cbor_patch(path: pathlib.Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LockError(f"cannot read cn-cbor patch {path}: {error}") from error

    changed_paths = [line for line in lines if line.startswith("diff --git ")]
    removed = [
        line[1:].strip()
        for line in lines
        if line.startswith("-") and not line.startswith(("---", "-- "))
    ]
    added = [
        line[1:].strip()
        for line in lines
        if line.startswith("+") and not line.startswith("+++")
    ]
    if (
        changed_paths != ["diff --git a/src/cn-encoder.c b/src/cn-encoder.c"]
        or removed != ["if (ws->buf) {"]
        or added != ["if (ws->buf && cb->length > 0) {"]
    ):
        raise LockError("cn-cbor compatibility patch contains an unapproved source change")


def validate_t_cose_patch(path: pathlib.Path) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise LockError(f"cannot read t_cose patch {path}: {error}") from error

    changed_paths = [line for line in lines if line.startswith("diff --git ")]
    if path.name == "0002-zero-transient-encryption-material.patch":
        expected_paths = [
            f"diff --git a/src/{name} b/src/{name}"
            for name in (
                "t_cose_crypto.h",
                "t_cose_encrypt_dec.c",
                "t_cose_encrypt_enc.c",
                "t_cose_recipient_dec_esdh.c",
                "t_cose_recipient_enc_esdh.c",
                "t_cose_util.c",
            )
        ]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if (
            changed_paths != expected_paths
            or digest != T_COSE_TRANSIENT_ZERO_PATCH_SHA256
        ):
            raise LockError(
                "t_cose transient-zero patch contains an unapproved source change"
            )
        return

    expected_path = (
        "diff --git a/crypto_adapters/t_cose_openssl_crypto.c "
        "b/crypto_adapters/t_cose_openssl_crypto.c"
    )
    if path.name != "0001-free-openssl-ec-temporaries.patch" or changed_paths != [
        expected_path
    ]:
        raise LockError("t_cose compatibility patch contains an unapproved source change")

    try:
        diff_start = lines.index(expected_path)
        trailer = lines.index("-- ", diff_start)
    except ValueError as error:
        raise LockError("t_cose compatibility patch has malformed metadata") from error
    if trailer + 2 != len(lines) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", lines[-1]):
        raise LockError("t_cose compatibility patch contains an unapproved source change")

    diff = "\n".join(lines[diff_start:trailer]) + "\n"
    if (
        hashlib.sha256(diff.encode("utf-8")).hexdigest()
        != T_COSE_OPENSSL_CLEANUP_DIFF_SHA256
    ):
        raise LockError("t_cose compatibility patch contains an unapproved source change")


def verify_patch_applies(checkout: pathlib.Path, patch: pathlib.Path) -> None:
    result = subprocess.run(
        ["git", "-C", str(checkout), "apply", "--check", str(patch.resolve())],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise LockError(f"compatibility patch does not apply: {detail}")


def verify_patch_series_applies(checkout: pathlib.Path, patches: Iterable[pathlib.Path]) -> None:
    with tempfile.TemporaryDirectory() as directory:
        temporary_checkout = pathlib.Path(directory) / "source"
        clone = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--no-hardlinks",
                str(checkout),
                str(temporary_checkout),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if clone.returncode != 0:
            raise LockError(f"cannot prepare compatibility-patch check: {clone.stderr.strip()}")
        for patch in patches:
            verify_patch_applies(temporary_checkout, patch)
            apply = subprocess.run(
                ["git", "-C", str(temporary_checkout), "apply", str(patch.resolve())],
                check=False,
                capture_output=True,
                text=True,
            )
            if apply.returncode != 0:
                detail = apply.stderr.strip() or apply.stdout.strip()
                raise LockError(f"compatibility patch does not apply in series: {detail}")


def checkout_commit(path: pathlib.Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise LockError(f"cannot inspect Git checkout {path}: {result.stderr.strip()}")
    return result.stdout.strip()


def verify_checkouts(
    root: pathlib.Path,
    dependencies: dict[str, Dependency],
    paths: dict[str, pathlib.Path],
) -> None:
    for name, relative_path in paths.items():
        dependency = dependencies[name]
        path = root / relative_path
        if not path.is_dir():
            raise LockError(f"missing checkout for {name}: {path}")
        actual = checkout_commit(path)
        if actual != dependency.commit:
            raise LockError(f"{name}: expected {dependency.commit}, found {actual}")
        print(f"[PASS] {name} {actual}")


def verify_licenses(root: pathlib.Path, dependencies: Iterable[Dependency]) -> None:
    for dependency in dependencies:
        path = root / "LICENSES" / f"{dependency.name}.txt"
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise LockError(f"cannot read retained license {path}: {error}") from error
        if digest != dependency.license_sha256:
            raise LockError(
                f"{dependency.name}: license digest {digest} does not match {dependency.license_sha256}"
            )
        print(f"[PASS] {dependency.name} license {digest}")


def verify_go_licenses(root: pathlib.Path) -> None:
    for filename, expected_digest in GO_LICENSE_DIGESTS.items():
        path = root / "LICENSES" / filename
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise LockError(f"cannot read retained Go license {path}: {error}") from error
        if digest != expected_digest:
            raise LockError(
                f"{filename}: license digest {digest} does not match {expected_digest}"
            )
        print(f"[PASS] {filename} license {digest}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate pinned PBNS dependencies")
    parser.add_argument("--root", type=pathlib.Path)
    parser.add_argument("--verify-submodules", action="store_true")
    parser.add_argument("--verify-external", action="store_true")
    parser.add_argument("--verify-licenses", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve() if args.root else pathlib.Path(__file__).resolve().parents[1]
    try:
        dependencies = load_lock(root / "dependencies.lock")
        for relative_patch in COSE_C_PATCHES:
            validate_cose_c_patch(root / relative_patch)
        for relative_patch in T_COSE_PATCHES:
            validate_t_cose_patch(root / relative_patch)
        for relative_patch in CN_CBOR_PATCHES:
            validate_cn_cbor_patch(root / relative_patch)
        print(f"[PASS] dependency lock ({len(dependencies)} entries)")
        if args.verify_submodules:
            verify_checkouts(root, dependencies, SUBMODULE_PATHS)
            verify_patch_series_applies(
                root / SUBMODULE_PATHS["cose_c"],
                (root / relative_patch for relative_patch in COSE_C_PATCHES),
            )
            print(f"[PASS] {len(COSE_C_PATCHES)} COSE-C compatibility patches apply cleanly")
            for relative_patch in T_COSE_PATCHES:
                verify_patch_applies(
                    root / SUBMODULE_PATHS["t_cose"],
                    root / relative_patch,
                )
            print(f"[PASS] {len(T_COSE_PATCHES)} t_cose compatibility patch applies cleanly")
            for relative_patch in CN_CBOR_PATCHES:
                verify_patch_applies(
                    root / SUBMODULE_PATHS["cn_cbor"],
                    root / relative_patch,
                )
            print(f"[PASS] {len(CN_CBOR_PATCHES)} cn-cbor compatibility patch applies cleanly")
        if args.verify_external:
            verify_checkouts(root, dependencies, EXTERNAL_PATHS)
        if args.verify_licenses:
            verify_licenses(root, dependencies.values())
            verify_go_licenses(root)
    except LockError as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("DEPENDENCY CHECK PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
