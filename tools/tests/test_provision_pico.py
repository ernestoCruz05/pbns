import base64
import contextlib
import hashlib
import importlib.util
import io
import pathlib
import unittest


TOOLS_DIR = pathlib.Path(__file__).parents[1]
MODULE_PATH = TOOLS_DIR / "provision-pico.py"
SPEC = importlib.util.spec_from_file_location("provision_pico", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load provisioning tool")
provision_pico = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provision_pico)


class FakeSerial:
    def __init__(
        self,
        record: bytes,
        *,
        ready=None,
        fingerprint=None,
        rejection=None,
        max_write=None,
    ):
        self.record = record
        self.ready = (
            ready if ready is not None else b"PBNS-PROVISION-v1 READY\n"
        )
        self.fingerprint = fingerprint
        self.rejection = rejection
        self.max_write = max_write
        self.writes = []
        self.pending = bytearray()
        self.responses = [self.ready]

    def write(self, data: bytes) -> int:
        length = len(data) if self.max_write is None else min(len(data), self.max_write)
        chunk = data[:length]
        self.writes.append(chunk)
        self.pending.extend(chunk)
        while b"\n" in self.pending:
            command, _, remainder = self.pending.partition(b"\n")
            self.pending = bytearray(remainder)
            if command.startswith(b"SET "):
                expected = b"SET " + base64.b64encode(self.record)
                if command != expected:
                    self.responses.append(b"ERROR malformed request\n")
                elif self.rejection is not None:
                    self.responses.append(self.rejection)
                else:
                    digest = self.fingerprint or hashlib.sha256(self.record).hexdigest()
                    self.responses.append(f"OK {digest}\n".encode("ascii"))
        return length

    def flush(self) -> None:
        return None

    def readline(self, size: int = -1) -> bytes:
        if not self.responses:
            return b""
        response = self.responses.pop(0)
        return response if size < 0 else response[:size]


class FakeSerialFactory:
    def __init__(self, *ports):
        self.ports = list(ports)
        self.opened = []
        self.closed = []

    @contextlib.contextmanager
    def __call__(self):
        port = self.ports[len(self.opened)]
        self.opened.append(port)
        try:
            yield port
        finally:
            self.closed.append(port)


class ProvisionPicoTest(unittest.TestCase):
    def setUp(self) -> None:
        self.psk = b"prototype-wifi-secret"
        self.record = b"\xa2\x01\x01\x02X" + bytes((len(self.psk),)) + self.psk

    def test_physical_provisioning_transcript(self) -> None:
        serial = FakeSerial(self.record)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            fingerprint = provision_pico.provision(serial, self.record)

        expected = hashlib.sha256(self.record).hexdigest()
        self.assertEqual(fingerprint, expected)
        self.assertEqual(
            serial.writes,
            [b"SET " + base64.b64encode(self.record) + b"\n", b"REBOOT\n"],
        )
        self.assertNotIn(self.psk.decode("ascii"), output.getvalue())

    def test_reopens_once_after_silent_stale_session(self) -> None:
        stale = FakeSerial(self.record, ready=b"")
        fresh = FakeSerial(self.record)
        factory = FakeSerialFactory(stale, fresh)
        waits = []

        fingerprint = provision_pico.provision_with_reconnect(
            factory, self.record, waits.append
        )

        self.assertEqual(fingerprint, hashlib.sha256(self.record).hexdigest())
        self.assertEqual(stale.writes, [])
        self.assertEqual(
            fresh.writes,
            [b"SET " + base64.b64encode(self.record) + b"\n", b"REBOOT\n"],
        )
        self.assertEqual(factory.opened, [stale, fresh])
        self.assertEqual(factory.closed, [stale, fresh])
        self.assertEqual(waits, [provision_pico.RECONNECT_DELAY_SECONDS])

    def test_two_silent_sessions_fail_without_writes(self) -> None:
        first = FakeSerial(self.record, ready=b"")
        second = FakeSerial(self.record, ready=b"")
        factory = FakeSerialFactory(first, second)

        with self.assertRaisesRegex(
            provision_pico.ProvisioningError,
            "device is not in physical provisioning mode",
        ):
            provision_pico.provision_with_reconnect(
                factory, self.record, lambda _: None
            )

        self.assertEqual(first.writes, [])
        self.assertEqual(second.writes, [])
        self.assertEqual(factory.closed, [first, second])

    def test_wrong_nonempty_banner_is_not_retried(self) -> None:
        wrong = FakeSerial(self.record, ready=b"unexpected banner\n")
        unused = FakeSerial(self.record)
        factory = FakeSerialFactory(wrong, unused)

        with self.assertRaisesRegex(
            provision_pico.ProvisioningError, "unexpected provisioning banner"
        ):
            provision_pico.provision_with_reconnect(
                factory, self.record, lambda _: None
            )

        self.assertEqual(factory.opened, [wrong])
        self.assertEqual(factory.closed, [wrong])
        self.assertEqual(wrong.writes, [])
        self.assertEqual(unused.writes, [])

    def test_ready_first_session_does_not_wait_or_reopen(self) -> None:
        ready = FakeSerial(self.record)
        unused = FakeSerial(self.record)
        factory = FakeSerialFactory(ready, unused)
        waits = []

        provision_pico.provision_with_reconnect(
            factory, self.record, waits.append
        )

        self.assertEqual(factory.opened, [ready])
        self.assertEqual(factory.closed, [ready])
        self.assertEqual(waits, [])

    def test_handles_partial_serial_writes(self) -> None:
        serial = FakeSerial(self.record, max_write=3)
        fingerprint = provision_pico.provision(serial, self.record)
        self.assertEqual(fingerprint, hashlib.sha256(self.record).hexdigest())
        self.assertEqual(
            b"".join(serial.writes),
            b"SET " + base64.b64encode(self.record) + b"\nREBOOT\n",
        )

    def test_rejects_wrong_ready_banner_without_leaking_record(self) -> None:
        serial = FakeSerial(self.record, ready=b"unexpected secret banner\n")
        with self.assertRaises(provision_pico.ProvisioningError) as caught:
            provision_pico.provision(serial, self.record)
        self.assertNotIn(self.psk.decode("ascii"), str(caught.exception))
        self.assertEqual(serial.writes, [])

    def test_rejects_wrong_fingerprint(self) -> None:
        serial = FakeSerial(self.record, fingerprint="0" * 64)
        with self.assertRaises(provision_pico.ProvisioningError) as caught:
            provision_pico.provision(serial, self.record)
        self.assertNotIn(self.psk.decode("ascii"), str(caught.exception))
        self.assertNotIn(b"REBOOT\n", serial.writes)

    def test_sanitizes_device_rejection(self) -> None:
        serial = FakeSerial(
            self.record,
            rejection=b"ERROR prototype-wifi-secret was rejected\n",
        )
        with self.assertRaises(provision_pico.ProvisioningError) as caught:
            provision_pico.provision(serial, self.record)
        self.assertEqual(str(caught.exception), "device rejected provisioning")
        self.assertNotIn(self.psk.decode("ascii"), str(caught.exception))

    def test_cli_requires_exclusive_serial_open(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("exclusive=True", source)

    def test_rejects_empty_or_oversized_record_before_serial_io(self) -> None:
        for record in (b"", b"x" * (provision_pico.MAX_RECORD_SIZE + 1)):
            with self.subTest(size=len(record)):
                serial = FakeSerial(record)
                with self.assertRaises(provision_pico.ProvisioningError):
                    provision_pico.provision(serial, record)
                self.assertEqual(serial.writes, [])


if __name__ == "__main__":
    unittest.main()
