import pathlib
import shutil
import sys
import tempfile
import unittest

TOOLS_DIR = pathlib.Path(__file__).parents[1]
sys.path.insert(0, str(TOOLS_DIR))

from check_dependencies import (
    GO_LICENSE_DIGESTS,
    LockError,
    load_lock,
    validate_cn_cbor_patch,
    validate_cose_c_patch,
    validate_t_cose_patch,
    verify_go_licenses,
    verify_patch_applies,
)


EXPECTED_COMMITS = {
    "qcbor": "930708bb86481e88879eb1d87fd4d664f1d69503",
    "t_cose": "ff4c5f7c6fbbe27bb582214ff1878bf58ebc6c43",
    "cose_c": "97d1805e71b7a6770093c5e6790d46611680d563",
    "cn_cbor": "f713bf67bcf3e076d47e474ce060252ef8be48c7",
    "cose_examples": "53c9d634333bb4f529d78f5980fffa2667ee2c12",
    "edk2": "b03a21a63e3bd001f52c527e5a57feddb53a690b",
    "pico_sdk": "98a542c1a62fb549ffb5d66a3e5892b06276b670",
    "mbedtls": "0bebf8b8c7f07abe3571ded48a11aa907a1ffb20",
    "tinyusb": "86ad6e56c1700e85f1c5678607a762cfe3aa2f47",
    "picotool": "6f6458d792b93685a11423b244a585eaa99eafcf",
    "tpm2_tss": "30e6057722058cb85c292dcb7b77760ad6410d4e",
}


class DependencyLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = pathlib.Path(__file__).parents[2]

    def test_required_revisions_are_exact(self) -> None:
        lock = load_lock(self.root / "dependencies.lock")
        self.assertEqual(set(lock), set(EXPECTED_COMMITS))
        for name, expected_commit in EXPECTED_COMMITS.items():
            self.assertEqual(lock[name].commit, expected_commit)

    def test_every_license_digest_is_sha256(self) -> None:
        lock = load_lock(self.root / "dependencies.lock")
        for dependency in lock.values():
            self.assertRegex(dependency.license_sha256, r"^[0-9a-f]{64}$")

    def test_tpm2_tss_is_permissive_external_input(self) -> None:
        lock = load_lock(self.root / "dependencies.lock")
        dependency = lock["tpm2_tss"]
        self.assertEqual(
            dependency.repository,
            "https://github.com/tpm2-software/tpm2-tss.git",
        )
        self.assertEqual(dependency.license, "BSD-2-Clause")
        self.assertEqual(
            dependency.license_sha256,
            "18c1bf4b1ba1fb2c4ffa7398c234d83c0d55475298e470ae1e5e3a8a8bd2e448",
        )
        bootstrap = (self.root / "tools" / "bootstrap.sh").read_text(
            encoding="utf-8"
        )
        for marker in (
            'tpm2_tss) destination="$PBNS_ROOT/.deps/tpm2-tss"',
            "edk2|pico_sdk|picotool|tpm2_tss",
            "tpm2_tss) printf '%s\\n' \"$PBNS_ROOT/.deps/tpm2-tss/LICENSE\"",
        ):
            self.assertIn(marker, bootstrap)
        self.assertNotIn("wolfTPM", bootstrap)

    def test_rejects_duplicate_dependency(self) -> None:
        row = self._valid_row("same")
        path = self._write_lock(f"{row}\n{row}\n")
        with self.assertRaisesRegex(LockError, "duplicate dependency"):
            load_lock(path)

    def test_rejects_non_commit_revision(self) -> None:
        path = self._write_lock(
            "qcbor|https://example.invalid/qcbor.git|v1.6.1|BSD-3-Clause|"
            + "0" * 64
            + "\n"
        )
        with self.assertRaisesRegex(LockError, "40 lowercase hexadecimal"):
            load_lock(path)

    def test_rejects_unapproved_license(self) -> None:
        fields = self._valid_row("dep").split("|")
        fields[3] = "UNKNOWN"
        path = self._write_lock("|".join(fields) + "\n")
        with self.assertRaisesRegex(LockError, "unapproved license"):
            load_lock(path)

    def test_rejects_bad_license_digest(self) -> None:
        fields = self._valid_row("dep").split("|")
        fields[4] = "not-a-digest"
        path = self._write_lock("|".join(fields) + "\n")
        with self.assertRaisesRegex(LockError, "license digest"):
            load_lock(path)

    def test_rejects_malformed_row(self) -> None:
        path = self._write_lock("only|four|fields|here\n")
        with self.assertRaisesRegex(LockError, "five pipe-separated fields"):
            load_lock(path)

    def test_accepts_only_const_correctness_patch(self) -> None:
        path = self._write_lock(
            "diff --git a/src/openssl.cpp b/src/openssl.cpp\n"
            "--- a/src/openssl.cpp\n"
            "+++ b/src/openssl.cpp\n"
            "@@ -1 +1 @@\n"
            "-\t\t\t\tEC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);\n"
            "+\t\t\t\tconst EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);\n"
            "-- \n"
            "2.51.0\n"
        )
        validate_cose_c_patch(path)

    def test_accepts_plaintext_getter_patch(self) -> None:
        path = self._write_lock(
            "diff --git a/src/Encrypt.cpp b/src/Encrypt.cpp\n"
            "--- a/src/Encrypt.cpp\n"
            "+++ b/src/Encrypt.cpp\n"
            "@@ -1 +1,17 @@\n"
            "+byte *COSE_Enveloped_GetContent(HCOSE_ENVELOPED h,\n"
            "+\tsize_t *pcbContent,\n"
            "+\tcose_errback *perror)\n"
            "+{\n"
            "+\tCOSE_Enveloped *cose = (COSE_Enveloped *)h;\n"
            "+\tif (!IsValidEnvelopedHandle(h) || (pcbContent == nullptr)) {\n"
            "+\t\tif (perror != nullptr) {\n"
            "+\t\t\tperror->err = COSE_ERR_INVALID_PARAMETER;\n"
            "+\t\t}\n"
            "+\t\treturn nullptr;\n"
            "+\t}\n"
            "+\t*pcbContent = cose->cbContent;\n"
            "+\treturn const_cast<byte *>(cose->pbContent);\n"
            "+}\n"
        )
        validate_cose_c_patch(path)

    def test_accepts_gcm_plaintext_length_patch(self) -> None:
        path = self._write_lock(
            "diff --git a/src/openssl.cpp b/src/openssl.cpp\n"
            "--- a/src/openssl.cpp\n"
            "+++ b/src/openssl.cpp\n"
            "@@ -1,3 +1,4 @@\n"
            "+\tint cbFinal = 0;\n"
            "-\t\tEVP_DecryptFinal(ctx, rgbOut + cbOut, &cbOut), COSE_ERR_DECRYPT_FAILED);\n"
            "+\t\tEVP_DecryptFinal(ctx, rgbOut + cbOut, &cbFinal), COSE_ERR_DECRYPT_FAILED);\n"
            "-\tpcose->cbContent = cbOut;\n"
            "+\tpcose->cbContent = (size_t)cbOut + (size_t)cbFinal;\n"
        )
        validate_cose_c_patch(path)

    def test_accepts_only_cn_cbor_zero_length_copy_patch(self) -> None:
        validate_cn_cbor_patch(
            self.root / "patches/cn-cbor/0001-guard-zero-length-copy.patch"
        )

    def test_accepts_cose_c_openssl_lifecycle_patch(self) -> None:
        validate_cose_c_patch(
            self.root / "patches/COSE-C/0004-free-openssl-key-resources.patch"
        )

    def test_accepts_only_reviewed_t_cose_patches(self) -> None:
        for name in (
            "0001-free-openssl-ec-temporaries.patch",
            "0002-zero-transient-encryption-material.patch",
        ):
            with self.subTest(name=name):
                validate_t_cose_patch(self.root / "patches" / "t_cose" / name)

    def test_rejects_additional_t_cose_patch_change(self) -> None:
        approved = self.root / "patches/t_cose/0001-free-openssl-ec-temporaries.patch"
        path = self._write_lock(
            approved.read_text(encoding="utf-8")
            + "\ndiff --git a/src/t_cose_util.c b/src/t_cose_util.c\n"
            + "--- a/src/t_cose_util.c\n"
            + "+++ b/src/t_cose_util.c\n"
            + "@@ -1 +1 @@\n-old\n+new\n"
        )
        with self.assertRaisesRegex(LockError, "unapproved source change"):
            validate_t_cose_patch(path)

    def test_go_module_license_copies_are_exact(self) -> None:
        self.assertEqual(
            set(GO_LICENSE_DIGESTS),
            {
                "go_bbolt.txt",
                "go_fxamacker_cbor.txt",
                "go_google_attestation.txt",
                "go_google_tpm.txt",
                "go_veraison_cose.txt",
                "go_x448_float16.txt",
                "go_x_sys.txt",
            },
        )
        verify_go_licenses(self.root)

    def test_rejects_modified_go_module_license(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            shutil.copytree(self.root / "LICENSES", root / "LICENSES")
            modified = root / "LICENSES" / "go_x448_float16.txt"
            modified.chmod(0o644)
            modified.write_text("modified\n", encoding="utf-8")
            with self.assertRaisesRegex(LockError, "go_x448_float16.txt"):
                verify_go_licenses(root)

    def test_rejects_patch_against_changed_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            checkout = pathlib.Path(directory)
            (checkout / "src").mkdir()
            (checkout / "src" / "openssl.cpp").write_text("different source\n", encoding="utf-8")
            patch = self._write_lock(
                "diff --git a/src/openssl.cpp b/src/openssl.cpp\n"
                "--- a/src/openssl.cpp\n"
                "+++ b/src/openssl.cpp\n"
                "@@ -1 +1 @@\n"
                "-EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);\n"
                "+const EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);\n"
            )
            with self.assertRaisesRegex(LockError, "does not apply"):
                verify_patch_applies(checkout, patch)

    def test_rejects_additional_patch_hunk(self) -> None:
        path = self._write_lock(
            "diff --git a/src/openssl.cpp b/src/openssl.cpp\n"
            "--- a/src/openssl.cpp\n"
            "+++ b/src/openssl.cpp\n"
            "@@ -1 +1 @@\n"
            "-EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);\n"
            "+const EC_KEY *peckeyPublic = EVP_PKEY_get0_EC_KEY(evpPublic);\n"
            "@@ -2 +2 @@\n-old\n+new\n"
        )
        with self.assertRaisesRegex(LockError, "unapproved source change"):
            validate_cose_c_patch(path)

    def _valid_row(self, name: str) -> str:
        return "|".join(
            (
                name,
                f"https://example.invalid/{name}.git",
                "a" * 40,
                "MIT",
                "b" * 64,
            )
        )

    def _write_lock(self, contents: str) -> pathlib.Path:
        temporary = tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8")
        self.addCleanup(pathlib.Path(temporary.name).unlink, missing_ok=True)
        with temporary:
            temporary.write(contents)
        return pathlib.Path(temporary.name)


if __name__ == "__main__":
    unittest.main()
