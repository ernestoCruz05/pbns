import importlib.util
import pathlib
import tempfile
import unittest


class SecureBootStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        helper = root / "integration" / "qemu" / "verify-secureboot-store.py"
        spec = importlib.util.spec_from_file_location("pbns_secureboot_store", helper)
        assert spec is not None and spec.loader is not None
        self.store = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.store)

    def report(self, *, secure_guid: str = "guid:EfiSecureBootEnableDisable", extra: str = "") -> str:
        blocks = [
            f"name=SecureBootEnable guid={secure_guid} size=1\n  bool: ON\n",
        ]
        for name, guid in self.store.DATABASE_GUIDS.items():
            blocks.append(
                f"name={name} guid={guid} size=865 time=2026-08-02 11:26:10+00:00\n"
                "  siglist type=guid:EfiCertX509 count=1\n"
                "    subject CN=PBNS TEST ONLY Recovery Image\n"
                "    issuer CN=PBNS TEST ONLY Recovery Image\n"
                f"{extra}"
            )
        return "\n".join(blocks) + "\n"

    def test_accepts_exact_shapes(self) -> None:
        self.store.validate_decoded(self.report())

    def test_rejects_wrong_guids_and_extra_signature_material(self) -> None:
        with self.assertRaises(ValueError):
            self.store.validate_decoded(self.report(secure_guid="guid:EfiGlobalVariable"))
        with self.assertRaises(ValueError):
            self.store.validate_decoded(self.report(extra="  siglist type=guid:EfiCertSha256 count=1\n"))
        with self.assertRaises(ValueError):
            self.store.validate_decoded(self.report(extra="  hash: deadbeef\n"))
        broken_db = self.report().replace(
            "name=db guid=guid:EfiImageSecurityDatabase", "name=db guid=guid:EfiGlobalVariable"
        )
        with self.assertRaises(ValueError):
            self.store.validate_decoded(broken_db)

    def test_extraction_inventory_rejects_unexpected_and_nonregular_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            extract = pathlib.Path(directory)
            for name in self.store.expected_certificate_names():
                (extract / name).write_text("fixture", encoding="utf-8")
            self.assertEqual(len(self.store.validate_extraction_inventory(extract)), 3)
            (extract / "unexpected.der").write_text("extra", encoding="utf-8")
            with self.assertRaises(ValueError):
                self.store.validate_extraction_inventory(extract)
            (extract / "unexpected.der").unlink()
            (extract / "directory").mkdir()
            with self.assertRaises(ValueError):
                self.store.validate_extraction_inventory(extract)

    def test_scratch_parent_requires_owned_mode_0700_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            parent.chmod(0o700)
            self.store.validate_scratch_parent(parent)
            parent.chmod(0o755)
            with self.assertRaises(ValueError):
                self.store.validate_scratch_parent(parent)


if __name__ == "__main__":
    unittest.main()
