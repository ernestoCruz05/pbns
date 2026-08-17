# PBNS Frame v1

PBNS records are binary. A complete raw record is COBS-encoded and followed by one zero delimiter on USB CDC/ACM and TLS byte streams. COBS and CRC32C detect framing damage; neither provides security authenticity.

## Raw record

All multibyte integers use network byte order.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII magic `PBNS` |
| 4 | 1 | protocol version `1` |
| 5 | 1 | service identifier |
| 6 | 1 | message type |
| 7 | 1 | flags; must be zero in v1 |
| 8 | 16 | request identifier |
| 24 | 4 | sequence number |
| 28 | 4 | payload length |
| 32 | 4 | CRC32C over bytes 0 through 31 |
| 36 | variable | payload |
| 36 + payload length | 4 | CRC32C over header, header CRC, and payload |

The fixed header is 36 bytes and the record trailer is 4 bytes. Decoders verify the header CRC before using payload length for bounds or size calculations.

## Service identifiers

| Value | Name |
|---:|---|
| 1 | `TRUSTED_TIME` |
| 2 | `RECOVERY_ARTIFACT` |
| 3 | `PLATFORM_ATTESTATION` |
| 4 | `ENROLLMENT` |

## Message types

| Value | Name | Payload rule |
|---:|---|---|
| 1 | `REQUEST` | deterministic service object, at most 65,536 bytes |
| 2 | `RESPONSE` | deterministic service object, at most 65,536 bytes |
| 3 | `DATA` | raw stream bytes, at most 16,384 bytes |
| 4 | `ACK` | exactly two non-zero network-order `uint32_t` values: next sequence and window |
| 5 | `ERROR` | deterministic error object, at most 65,536 bytes |
| 6 | `CANCEL` | empty |
| 7 | `COMPLETE` | empty |

Sequence numbers start at zero for each request stream. An ACK therefore names a non-zero next sequence. Sequence wrap is rejected before `UINT32_MAX` is incremented.

## Limits

The protocol maximum raw record is 65,576 bytes. Its maximum COBS representation under the PBNS encoder is 65,835 bytes; including the delimiter, the maximum wire record is 65,836 bytes. Deployments may configure smaller limits but never larger ones.

The decoder receives a COBS record without its trailing delimiter. The `encoded_record_max` limit counts that delimiter even though it is not passed to the decoder. The encoder always emits exactly one trailing zero delimiter.
