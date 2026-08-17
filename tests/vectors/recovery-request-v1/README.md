# PBNS recovery request v1 vectors

These vectors fix the canonical CBOR payload shared by the C firmware client and Go gateway. They are unsigned so signature randomness cannot hide payload incompatibility.

- `manifest-request.json` uses operation 1 and the required all-zero artifact digest.
- `artifact-request.json` uses operation 2 and a nonzero digest.

The request identifier, host fingerprint, nonce, and artifact digest use visible byte patterns. They are public test data and are not deployment identities, nonces, or digests.
