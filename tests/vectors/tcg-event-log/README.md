# Synthetic TCG2 event-log vectors

These fixtures are synthetic parser vectors and contain no platform-derived data.

- `valid-sha256.bin` is a 122-byte crypto-agile log with a `Spec ID Event03`
  header, SHA-1 and SHA-256 algorithm declarations, and one Event2 record in
  PCR 7. SHA-256:
  `d0c9ea08ae98d2ebcb1d592d680ffa774d65bcce021b4ddc3be414eadf3c5fc8`.
- `truncated.bin` removes the final byte from the valid vector and must be
  rejected. SHA-256:
  `883e23fd0db876e6eb8bab87f882e5a80fb30c12c5978bada12bd8bcbbd2a194`.
- `valid-final-events.bin` is a 71-byte version-1
  `EFI_TCG2_FINAL_EVENTS_TABLE` containing one SHA-256 Event2 record. Its
  16-byte table header is metadata: capture appends the 55 record bytes to the
  base log, preserving normal crypto-agile parser replay. SHA-256:
  `02a38ee60a43a799d120d38dd7b196403a4c60d12589db5c103b87294a340cd0`.
- `unsupported-bank.bin` is a structurally valid 134-byte log declaring only
  SHA-384. The evaluated SHA-256 capture rejects it with
  `PBNS_ERR_UNSUPPORTED`. SHA-256:
  `de872554aa5a51ba3b5d91143a7ccae0f2b414179500072ae82f3edf0002f07e`.

The captured event-log byte string is the exact base crypto-agile log followed
by every final Event2 record when the provider marks the final table `APPEND`,
with no final-table header or separator. The core never suppresses records by
byte equality. A provider may mark `ALREADY_INCLUDED_EXACT` only when the parsed
final event range is physically the same range as the final complete-record
suffix of the bounded base log; `NONE` requires no final table. Any other
provenance/disposition combination is rejected. The event-log digest is SHA-256
of that complete byte string.

All source ranges, including the final-table header, must be disjoint from the
entire writable caller arena. The portable core rejects overlap rather than
staging firmware bytes.
Canonical selection bytes are three bytes per tuple in ascending tuple order:
big-endian TPM algorithm identifier followed by the PCR index. The selection
digest is SHA-256 of those bytes.

They test bounded TCG EFI Protocol Specification event-log decoding. They are
not evidence from a TPM, OVMF, or a hardware platform.
