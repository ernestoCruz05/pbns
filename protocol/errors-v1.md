# PBNS v1 Error Registry

Wire error objects use deterministic CBOR with this integer-keyed map:

```cddl
pbns-error = {
  1: 1..22,  ; absolute status magnitude
  2: 1..4,   ; failed service identifier
  3: tstr .size (0..256)
}
```

The detail text is non-sensitive UTF-8 capped at 256 encoded bytes. Generic internal handler errors are replaced with `service failure`; only an explicitly typed protocol error may supply another non-sensitive detail. Local C APIs use the negative values below.

| Local value | Stable name |
|---:|---|
| 0 | `OK` |
| -1 | `ARGUMENT` |
| -2 | `LIMIT` |
| -3 | `FORMAT` |
| -4 | `CRC` |
| -5 | `VERSION` |
| -6 | `SERVICE` |
| -7 | `MESSAGE_TYPE` |
| -8 | `SEQUENCE` |
| -9 | `STATE` |
| -10 | `WOULD_BLOCK` |
| -11 | `TIMEOUT` |
| -12 | `TRANSPORT` |
| -13 | `CRYPTO` |
| -14 | `AUTHENTICATION` |
| -15 | `REPLAY` |
| -16 | `UNSUPPORTED` |
| -17 | `UNIMPLEMENTED` |
| -18 | `ENTROPY` |
| -19 | `AMBIGUOUS` |
| -20 | `RESOURCE` |
| -21 | `IO` |
| -22 | `BUSY` |

Unknown wire values are rejected rather than mapped to a generic success/failure state.
