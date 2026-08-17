#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsEnrollmentBaselineLib.h>
#include <Library/PbnsMeasuredBootLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiLib.h>

#include <stddef.h>
#include <stdint.h>

#include "pbns/measured_boot.h"

#define PBNS_BASELINE_ENCODED_MAX_SIZE                                         \
  (PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE + 4096U)

EFI_STATUS EFIAPI UefiMain(IN EFI_HANDLE ImageHandle,
                           IN EFI_SYSTEM_TABLE *SystemTable) {
  (void)ImageHandle;
  const UINTN event_pages =
      EFI_SIZE_TO_PAGES(PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE);
  const UINTN scratch_pages =
      EFI_SIZE_TO_PAGES(PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE);
  const UINTN encoded_pages = EFI_SIZE_TO_PAGES(PBNS_BASELINE_ENCODED_MAX_SIZE);
  uint8_t *event_log = AllocatePages(event_pages);
  uint8_t *scratch = AllocatePages(scratch_pages);
  uint8_t *encoded = AllocatePages(encoded_pages);
  if (event_log == NULL || scratch == NULL || encoded == NULL) {
    if (encoded != NULL) {
      FreePages(encoded, encoded_pages);
    }
    if (scratch != NULL) {
      FreePages(scratch, scratch_pages);
    }
    if (event_log != NULL) {
      FreePages(event_log, event_pages);
    }
    Print(L"PBNS BASELINE PROBE FAIL allocation\r\n");
    return EFI_OUT_OF_RESOURCES;
  }
  UINT64 start_ms = 0U;
  UINT64 end_ms = 0U;
  size_t encoded_size = 0U;
  size_t event_count = 0U;
  uint32_t update_counter = 0U;
  uint8_t baseline_digest[32] = {0};
  uint8_t host_fingerprint[32] = {0};
  PBNS_ENROLLMENT_BASELINE_TIMINGS timings = {0};
  EFI_STATUS status = PbnsUefiMonotonicMs(SystemTable->BootServices, &start_ms);
  if (!EFI_ERROR(status)) {
    status = PbnsEnrollmentBaselineCapture(
        SystemTable, (pbns_view){host_fingerprint, sizeof(host_fingerprint)},
        (pbns_buffer){event_log, 0U, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE},
        (pbns_buffer){scratch, 0U, PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE},
        (pbns_buffer){encoded, 0U, PBNS_BASELINE_ENCODED_MAX_SIZE},
        &encoded_size, baseline_digest, &event_count, &update_counter,
        &timings);
  }
  if (!EFI_ERROR(status)) {
    status = PbnsUefiMonotonicMs(SystemTable->BootServices, &end_ms);
  }
  if (!EFI_ERROR(status) && end_ms >= start_ms && encoded_size > 0U &&
      event_count > 0U) {
    Print(L"PBNS BASELINE EVENTS %u\r\n", (UINT32)event_count);
    Print(L"PBNS BASELINE ENCODED BYTES %u\r\n", (UINT32)encoded_size);
    Print(L"PBNS BASELINE PCR UPDATE COUNTER %u\r\n", update_counter);
    Print(L"PBNS BASELINE CAPTURE MS %Lu\r\n", end_ms - start_ms);
    Print(L"PBNS BASELINE EVENT LOG MS %Lu\r\n", timings.EventLogCaptureMs);
    Print(L"PBNS BASELINE HASHING MS %Lu\r\n", timings.HashingMs);
    Print(L"PBNS BASELINE PCR READ MS %Lu\r\n", timings.PcrReadMs);
    Print(L"PBNS BASELINE ENCODING MS %Lu\r\n", timings.EncodingMs);
    Print(L"PBNS BASELINE CAPTURE PASS\r\n");
    Print(L"PBNS BASELINE SOFTWARE CHECKPOINT PASS\r\n");
  } else {
    Print(L"PBNS BASELINE PROBE FAIL status %r\r\n", status);
    status = EFI_SECURITY_VIOLATION;
  }
  ZeroMem(host_fingerprint, sizeof(host_fingerprint));
  ZeroMem(baseline_digest, sizeof(baseline_digest));
  ZeroMem(encoded, PBNS_BASELINE_ENCODED_MAX_SIZE);
  ZeroMem(scratch, PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE);
  ZeroMem(event_log, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE);
  FreePages(encoded, encoded_pages);
  FreePages(scratch, scratch_pages);
  FreePages(event_log, event_pages);
  return status;
}
