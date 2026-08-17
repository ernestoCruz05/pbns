#ifndef PBNS_MEASURED_BOOT_UEFI_ADAPTER_H
#define PBNS_MEASURED_BOOT_UEFI_ADAPTER_H

#include <Uefi.h>

#include "PbnsMeasuredBootAdapterCore.h"
#include "pbns/measured_boot.h"

EFI_STATUS PbnsMeasuredBootFindFinalEventsTable(
    EFI_SYSTEM_TABLE *SystemTable, const pbns_uefi_memory_ops *MemoryOps,
    VOID **Table);

pbns_status PbnsMeasuredBootUefiPcrReadChunk(
    VOID *Context, pbns_measured_boot_selection Selection,
    pbns_measured_boot_pcr_snapshot *Snapshot);

#endif
