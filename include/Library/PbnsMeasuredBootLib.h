#ifndef PBNS_MEASURED_BOOT_LIB_H
#define PBNS_MEASURED_BOOT_LIB_H

#include <Uefi.h>

#include "pbns/buffer.h"
#include "pbns/enrollment_baseline.h"
#include "pbns/inventory.h"
#include "pbns/measured_boot.h"

#define PBNS_BASELINE_VARIABLE_SCRATCH_MAX_SIZE                                \
  PBNS_INVENTORY_VARIABLE_MAX_SIZE

typedef struct pbns_measured_boot_capture {
  pbns_baseline_pcr pcrs[PBNS_BASELINE_PCR_COUNT];
  size_t event_log_size;
  size_t event_count;
  uint32_t pcr_update_counter;
  UINT64 EventLogCaptureMs;
  UINT64 PcrReadMs;
} pbns_measured_boot_capture;

EFI_STATUS EFIAPI PbnsMeasuredBootCaptureSelection(
    EFI_SYSTEM_TABLE *SystemTable, pbns_measured_boot_selection Selection,
    pbns_measured_boot_policy_fn PolicyAllows, VOID *PolicyContext,
    pbns_buffer EventLogArena, pbns_measured_boot_evidence *Evidence);

EFI_STATUS EFIAPI PbnsMeasuredBootCapture(EFI_BOOT_SERVICES *BootServices,
                                          pbns_buffer event_log_buffer,
                                          pbns_measured_boot_capture *Capture);

#endif
