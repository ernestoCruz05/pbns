# Recovery policy v1 vectors

These canonical CBOR objects use the intentionally public, test-only `recovery-policy-test-*` P-256 fixture. They contain public TPM policy material only and no TPM verification ticket.

- `initialize-4.cbor` authorizes the one-time exact write of big-endian version 4 through `PolicyNVWritten(false)` and `PolicyCpHash`.
- `advance-4-to-5.cbor` authorizes the exact write of big-endian version 5 after `PolicyNV(unsignedLT, operandB=5)` and `PolicyCpHash`.

Both objects bind NV index `0x01801000`, the complete policy-write-only NV public area and Name, the policy-key TPM public area and Name, `PBNS-RECOVERY-POLICY-REF-v1`, the approved policy, the final `PolicyAuthorize` digest, and a TPM-formatted ECDSA/SHA-256 signature over `SHA-256(approvedPolicy || policyRef)`.

ECDSA signing is randomized. Tests reproduce every non-signature field independently, verify the checked-in signatures, reject trailing TPM encodings, and use these files as the C/UEFI decoder vectors.

SHA-256:

```text
098efd02772a6d7e9d12d42e644d9f8c0adbed74809cf2fbf5344f702075dc40  initialize-4.cbor
8fcc6c497551c55d0d7068fcc99af502465ac9471bd965db662a00112f11d910  advance-4-to-5.cbor
```
