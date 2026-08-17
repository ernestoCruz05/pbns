#ifndef PBNS_ENROLLMENT_BASELINE_LIB_H
#define PBNS_ENROLLMENT_BASELINE_LIB_H

#include <Uefi.h>

#include "pbns/buffer.h"

typedef struct PBNS_ENROLLMENT_BASELINE_TIMINGS {
  UINT64 EventLogCaptureMs;
  UINT64 HashingMs;
  UINT64 PcrReadMs;
  UINT64 EncodingMs;
} PBNS_ENROLLMENT_BASELINE_TIMINGS;

EFI_STATUS EFIAPI PbnsEnrollmentBaselineCapture(
    EFI_SYSTEM_TABLE *SystemTable, pbns_view host_fingerprint,
    pbns_buffer event_log_buffer, pbns_buffer variable_scratch,
    pbns_buffer encoded_baseline, size_t *EncodedSize,
    uint8_t BaselineDigest[32], size_t *EventCount, uint32_t *PcrUpdateCounter,
    PBNS_ENROLLMENT_BASELINE_TIMINGS *Timings);

#endif
