import hashlib
import json
import pathlib
import struct
import unittest


class LoaderFixturesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pbns_root = pathlib.Path(__file__).parents[2]
        self.fixture_root = (
            self.pbns_root / "integration" / "state" / "fixtures" / "loader-v1"
        )
        self.manifest_path = self.fixture_root / "manifest.json"

    def _require_generated(self) -> None:
        if not self.manifest_path.is_file():
            self.skipTest("run integration/qemu/make-loader-fixtures.sh first")

    @staticmethod
    def _pe_metadata(path: pathlib.Path) -> dict[str, object]:
        encoded = path.read_bytes()
        if len(encoded) < 64 or encoded[:2] != b"MZ":
            raise AssertionError(f"{path} has no DOS header")
        pe_offset = struct.unpack_from("<I", encoded, 0x3C)[0]
        if (
            pe_offset + 24 > len(encoded)
            or encoded[pe_offset : pe_offset + 4] != b"PE\0\0"
        ):
            raise AssertionError(f"{path} has no complete PE signature")
        section_count = struct.unpack_from("<H", encoded, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", encoded, pe_offset + 20)[0]
        optional_offset = pe_offset + 24
        section_offset = optional_offset + optional_size
        if section_count == 0 or section_offset + (section_count * 40) > len(encoded):
            raise AssertionError(f"{path} has no complete section table")
        magic = struct.unpack_from("<H", encoded, optional_offset)[0]
        if magic != 0x20B:
            raise AssertionError(f"{path} is not PE32+")
        data_directory_offset = optional_offset + 112
        certificate_offset, certificate_size = struct.unpack_from(
            "<II", encoded, data_directory_offset + (4 * 8)
        )
        section_ends = []
        for index in range(section_count):
            entry = section_offset + (index * 40)
            raw_size, raw_offset = struct.unpack_from("<II", encoded, entry + 16)
            section_ends.append(raw_offset + raw_size)
        return {
            "length": len(encoded),
            "section_end": max(section_ends),
            "certificate_offset": certificate_offset,
            "certificate_size": certificate_size,
        }

    def test_manifest_contains_only_disposable_fixture_paths(self) -> None:
        self._require_generated()
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "pbns-loader-fixtures-v1")
        expected = {
            "missing",
            "truncated",
            "untrusted",
            "return-error",
            "return-success",
        }
        self.assertEqual(set(manifest["fixtures"]), expected)
        self.assertEqual(
            {path.name for path in self.fixture_root.iterdir() if path.is_dir()},
            expected,
        )
        root = self.fixture_root.resolve(strict=True)
        for name, fixture in manifest["fixtures"].items():
            with self.subTest(name=name):
                self.assertEqual(fixture["directory"], name)
                directory = (self.fixture_root / fixture["directory"]).resolve(
                    strict=True
                )
                self.assertEqual(directory.parent, root)
                image = fixture["image"]
                if name == "missing":
                    self.assertIsNone(image)
                    self.assertEqual(list(directory.iterdir()), [])
                    continue
                self.assertEqual(image, f"{name}/loader.efi")
                image_path = (self.fixture_root / image).resolve(strict=True)
                self.assertEqual(image_path.parent, directory)
                self.assertNotIn("EFI/Microsoft", image_path.as_posix())
                self.assertNotIn("/boot/", image_path.as_posix())

    def test_every_present_image_has_an_exact_sha256(self) -> None:
        self._require_generated()
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        present = {
            fixture["image"]: fixture["sha256"]
            for fixture in manifest["fixtures"].values()
            if fixture["image"] is not None
        }
        self.assertEqual(len(present), 4)
        for relative, expected_digest in present.items():
            with self.subTest(image=relative):
                encoded = (self.fixture_root / relative).read_bytes()
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected_digest)

    def test_pe_images_have_the_intended_distinctions(self) -> None:
        self._require_generated()
        paths = {
            name: self.fixture_root / name / "loader.efi"
            for name in ("truncated", "untrusted", "return-error", "return-success")
        }
        metadata = {name: self._pe_metadata(path) for name, path in paths.items()}
        self.assertLess(
            metadata["truncated"]["length"], metadata["truncated"]["section_end"]
        )
        for name in ("untrusted", "return-error", "return-success"):
            with self.subTest(name=name):
                self.assertGreaterEqual(
                    metadata[name]["length"], metadata[name]["section_end"]
                )
        self.assertGreater(metadata["untrusted"]["certificate_size"], 0)
        self.assertGreater(metadata["untrusted"]["certificate_offset"], 0)
        self.assertLessEqual(
            metadata["untrusted"]["certificate_offset"]
            + metadata["untrusted"]["certificate_size"],
            metadata["untrusted"]["length"],
        )
        self.assertEqual(metadata["return-success"]["certificate_size"], 0)
        self.assertNotEqual(
            paths["return-error"].read_bytes(), paths["return-success"].read_bytes()
        )

    def test_error_fixture_accepts_only_enumerated_statuses(self) -> None:
        source = (
            self.pbns_root
            / "uefi"
            / "Tests"
            / "Fixtures"
            / "ReturnError"
            / "ReturnError.c"
        ).read_text(encoding="utf-8")
        for marker in (
            "EFI_LOAD_ERROR",
            "EFI_DEVICE_ERROR",
            "EFI_ABORTED",
            "LoadOptions",
        ):
            self.assertIn(marker, source)
        for forbidden in (
            "EFI_SIMPLE_FILE_SYSTEM_PROTOCOL",
            "SetVariable",
            "GetVariable",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
