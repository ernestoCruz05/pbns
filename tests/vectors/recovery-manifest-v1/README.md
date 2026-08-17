# Recovery manifest v1 vectors

These public test vectors use `service-signing-test-private.pem`, an intentionally public test-only P-256 key.

- `payload.cbor` is the canonical recovery-manifest payload for the fixed values in the C and Go manifest tests.
- `signed.cbor` is a COSE_Sign1 ES256 envelope over that payload with protected key ID `recovery-key-2026` and external AAD `PBNS-RECOVERY-MANIFEST-AAD-v1 || request_id || host_binding || nonce || key_id`.

The C test independently encodes the payload byte-for-byte and verifies the Go-produced envelope. The Go test independently decodes, re-encodes, and verifies both files. These vectors authenticate artifact selection and digest; they do not authorize UEFI execution of the artifact.
