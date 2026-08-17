import hashlib
import hmac
import ipaddress
import pathlib
import re
import stat
import subprocess


PBNS_ROOT = pathlib.Path(__file__).resolve().parents[2]
TLS_FIXTURES = PBNS_ROOT / "tests" / "fixtures" / "keys"
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class TLSIdentityError(Exception):
    pass


def _validated_san(server_name: str) -> str:
    try:
        address = ipaddress.ip_address(server_name)
    except ValueError:
        labels = server_name.split(".")
        if (
            not server_name
            or len(server_name) > 253
            or any(DNS_LABEL.fullmatch(label) is None for label in labels)
        ):
            raise TLSIdentityError("invalid TLS test server name") from None
        return f"DNS:{server_name}"
    return f"IP:{address.compressed}"


def _require_private_directory(directory: pathlib.Path) -> None:
    try:
        information = directory.lstat()
    except OSError as error:
        raise TLSIdentityError("cannot inspect TLS test directory") from error
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(information.st_mode)
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        raise TLSIdentityError("TLS test directory must have mode 0700")


def certificate_spki_sha256(certificate: pathlib.Path) -> str:
    try:
        public_pem = subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"],
            check=True,
            capture_output=True,
        ).stdout
        public_der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=public_pem,
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise TLSIdentityError("cannot derive TLS test certificate SPKI") from error
    return hashlib.sha256(public_der).hexdigest()


def make_matching_certificate(
    directory: pathlib.Path, *, server_name: str
) -> pathlib.Path:
    san = _validated_san(server_name)
    _require_private_directory(directory)
    extension = directory / "server.ext"
    request = directory / "gateway.csr"
    certificate = directory / "gateway-cert.pem"
    key = TLS_FIXTURES / "tls-gateway-test-key.pem"
    expected_pin_path = TLS_FIXTURES / "tls-gateway-test-spki.sha256"
    try:
        expected_pin = expected_pin_path.read_text(encoding="ascii").strip()
        if SHA256_HEX.fullmatch(expected_pin) is None:
            raise TLSIdentityError("invalid committed TLS test SPKI pin")
        extension.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName={san}\n",
            encoding="ascii",
        )
        extension.chmod(0o600)
        subprocess.run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(key),
                "-subj",
                "/CN=pbns-gateway.test",
                "-out",
                str(request),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        request.chmod(0o600)
        subprocess.run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(request),
                "-signkey",
                str(key),
                "-sha256",
                "-days",
                "1",
                "-set_serial",
                "0x50424e5305",
                "-extfile",
                str(extension),
                "-out",
                str(certificate),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        certificate.chmod(0o600)
    except TLSIdentityError:
        raise
    except (OSError, subprocess.CalledProcessError) as error:
        raise TLSIdentityError("cannot create TLS test identity") from error
    if not hmac.compare_digest(certificate_spki_sha256(certificate), expected_pin):
        raise TLSIdentityError("TLS test identity has the wrong SPKI")
    return certificate
