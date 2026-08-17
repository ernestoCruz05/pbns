import contextlib
import importlib.util
import io
import pathlib
import struct
import tempfile
import types
import unittest


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = PBNS_ROOT / "tools" / "verify_uf2_range.py"


def load_module() -> types.ModuleType:
    specification = importlib.util.spec_from_file_location("verify_uf2_range", SCRIPT)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


UF2 = load_module()


def block(
    *,
    target: int,
    number: int,
    count: int,
    payload: bytes = b"A" * 256,
    magic0: int = 0x0A324655,
    magic1: int = 0x9E5D5157,
    end_magic: int = 0x0AB16F30,
) -> bytes:
    output = bytearray(512)
    struct.pack_into(
        "<8I", output, 0, magic0, magic1, 0x2000, target, len(payload), number, count, 0xE48BFF56
    )
    if len(payload) <= 476:
        output[32 : 32 + len(payload)] = payload
    struct.pack_into("<I", output, 508, end_magic)
    return bytes(output)


class VerifyUf2RangeTests(unittest.TestCase):
    def write(self, encoded: bytes) -> pathlib.Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = pathlib.Path(directory.name) / "image.uf2"
        path.write_bytes(encoded)
        return path

    def test_accepts_reordered_complete_nonoverlapping_blocks(self) -> None:
        path = self.write(
            block(target=0x10000100, number=1, count=2)
            + block(target=0x10000000, number=0, count=2)
        )
        summary = UF2.verify_uf2_range(path)
        self.assertEqual(summary.block_count, 2)
        self.assertEqual(summary.target_start, 0x10000000)
        self.assertEqual(summary.target_end, 0x10000200)

    def test_rejects_bad_magic_and_invalid_file_lengths(self) -> None:
        for encoded in (
            b"",
            b"x" * 511,
            block(target=0x10000000, number=0, count=1, magic0=0),
            block(target=0x10000000, number=0, count=1, magic1=0),
            block(target=0x10000000, number=0, count=1, end_magic=0),
        ):
            with self.subTest(length=len(encoded)), self.assertRaises(UF2.Uf2Error):
                UF2.verify_uf2_range(self.write(encoded))

    def test_rejects_zero_and_oversized_payloads(self) -> None:
        zero = block(target=0x10000000, number=0, count=1, payload=b"")
        oversized = bytearray(block(target=0x10000000, number=0, count=1))
        struct.pack_into("<I", oversized, 16, 477)
        for encoded in (zero, bytes(oversized)):
            with self.assertRaises(UF2.Uf2Error):
                UF2.verify_uf2_range(self.write(encoded))

    def test_rejects_invalid_counts_and_numbers(self) -> None:
        cases = (
            block(target=0x10000000, number=0, count=0),
            block(target=0x10000000, number=0, count=2),
            block(target=0x10000000, number=1, count=1),
            block(target=0x10000000, number=0, count=2)
            + block(target=0x10000100, number=0, count=2),
            block(target=0x10000000, number=0, count=2)
            + block(target=0x10000100, number=1, count=3),
        )
        for encoded in cases:
            with self.subTest(), self.assertRaises(UF2.Uf2Error):
                UF2.verify_uf2_range(self.write(encoded))

    def test_rejects_targets_outside_flash_or_overlapping(self) -> None:
        cases = (
            block(target=0x0FFFFFFF, number=0, count=1),
            block(target=0x101FDF80, number=0, count=1),
            block(target=0xFFFFFF80, number=0, count=1),
            block(target=0x10000000, number=0, count=2)
            + block(target=0x10000080, number=1, count=2),
        )
        for encoded in cases:
            with self.subTest(), self.assertRaises(UF2.Uf2Error):
                UF2.verify_uf2_range(self.write(encoded))

    def test_rejects_invalid_allowed_range(self) -> None:
        path = self.write(block(target=0x10000000, number=0, count=1))
        for start, end in ((1, 1), (-1, 2), (0, 1 << 33)):
            with self.subTest(), self.assertRaises(UF2.Uf2Error):
                UF2.verify_uf2_range(path, allowed_start=start, allowed_end=end)

    def test_cli_accepts_planned_flash_range_names(self) -> None:
        path = self.write(block(target=0x10000000, number=0, count=1))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                UF2.main(
                    [
                        str(path),
                        "--flash-start",
                        "0x10000000",
                        "--flash-end",
                        "0x101fe000",
                    ]
                ),
                0,
            )

    def test_cli_output_is_generic_and_contains_no_payload(self) -> None:
        path = self.write(
            block(target=0x10000000, number=0, count=1, payload=b"SECRET" * 20)
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(UF2.main([str(path)]), 0)
        self.assertIn("UF2 RANGE PASS", output.getvalue())
        self.assertNotIn("SECRET", output.getvalue())


if __name__ == "__main__":
    unittest.main()
