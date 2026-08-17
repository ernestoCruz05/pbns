#include <Uefi.h>

#include <IndustryStandard/UefiTcgPlatform.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PbnsMeasuredBootLib.h>
#include <Library/PbnsUefiPlatformLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>

#include <mbedtls/sha256.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/measured_boot.h"

#include "PbnsMeasuredBootAdapterCore.h"
#include "PbnsMeasuredBootUefiAdapter.h"

_Static_assert(sizeof(EFI_MEMORY_DESCRIPTOR) ==
                   sizeof(pbns_uefi_memory_descriptor),
               "EFI memory descriptor layout");
_Static_assert(offsetof(EFI_MEMORY_DESCRIPTOR, Type) ==
                   offsetof(pbns_uefi_memory_descriptor, type),
               "EFI memory descriptor type");
_Static_assert(offsetof(EFI_MEMORY_DESCRIPTOR, PhysicalStart) ==
                   offsetof(pbns_uefi_memory_descriptor, physical_start),
               "EFI memory descriptor address");
_Static_assert(offsetof(EFI_MEMORY_DESCRIPTOR, NumberOfPages) ==
                   offsetof(pbns_uefi_memory_descriptor, number_of_pages),
               "EFI memory descriptor pages");
_Static_assert(offsetof(EFI_MEMORY_DESCRIPTOR, Attribute) ==
                   offsetof(pbns_uefi_memory_descriptor, attribute),
               "EFI memory descriptor attributes");
typedef struct PBNS_MEASURED_BOOT_UEFI_CONTEXT {
  EFI_SYSTEM_TABLE *SystemTable;
  EFI_STATUS LastStatus;
  UINT64 EventLogCaptureMs;
  UINT64 PcrReadMs;
} PBNS_MEASURED_BOOT_UEFI_CONTEXT;

static pbns_uefi_map_result get_memory_map(
    void *Context, uint8_t *Map, size_t *MapSize, size_t *DescriptorSize,
    uint32_t *DescriptorVersion) {
  PBNS_MEASURED_BOOT_UEFI_CONTEXT *context = Context;
  UINTN map_size = (UINTN)*MapSize;
  UINTN map_key = 0U;
  UINTN descriptor_size = 0U;
  UINT32 descriptor_version = 0U;
  const EFI_STATUS status = context->SystemTable->BootServices->GetMemoryMap(
      &map_size, (EFI_MEMORY_DESCRIPTOR *)Map, &map_key, &descriptor_size,
      &descriptor_version);
  *MapSize = (size_t)map_size;
  *DescriptorSize = (size_t)descriptor_size;
  *DescriptorVersion = descriptor_version;
  if (status == EFI_SUCCESS) {
    return PBNS_UEFI_MAP_OK;
  }
  if (status == EFI_BUFFER_TOO_SMALL) {
    return PBNS_UEFI_MAP_BUFFER_TOO_SMALL;
  }
  context->LastStatus = status;
  return PBNS_UEFI_MAP_ERROR;
}

static pbns_status allocate_memory_map(void *Context, size_t Size,
                                       uint8_t **Allocation) {
  PBNS_MEASURED_BOOT_UEFI_CONTEXT *context = Context;
  EFI_STATUS status = context->SystemTable->BootServices->AllocatePool(
      EfiBootServicesData, (UINTN)Size, (VOID **)Allocation);
  if (EFI_ERROR(status)) {
    context->LastStatus = status;
    return PBNS_ERR_RESOURCE;
  }
  return PBNS_OK;
}

static void free_memory_map(void *Context, uint8_t *Allocation, size_t Size) {
  PBNS_MEASURED_BOOT_UEFI_CONTEXT *context = Context;
  (void)Size;
  const EFI_STATUS status =
      context->SystemTable->BootServices->FreePool(Allocation);
  if (EFI_ERROR(status)) {
    context->LastStatus = status;
  }
}

static pbns_uefi_memory_ops memory_ops(
    PBNS_MEASURED_BOOT_UEFI_CONTEXT *Context) {
  return (pbns_uefi_memory_ops){get_memory_map, allocate_memory_map,
                                free_memory_map, Context};
}

static pbns_status uefi_event_log_read(
    void *Context, pbns_measured_boot_event_source *Source) {
  PBNS_MEASURED_BOOT_UEFI_CONTEXT *context = Context;
  *Source = (pbns_measured_boot_event_source){0};
  UINT64 start = 0U;
  UINT64 end = 0U;
  EFI_STATUS status =
      PbnsUefiMonotonicMs(context->SystemTable->BootServices, &start);
  if (EFI_ERROR(status)) {
    context->LastStatus = status;
    return PBNS_ERR_SERVICE;
  }
  EFI_TCG2_PROTOCOL *tcg2 = NULL;
  status = context->SystemTable->BootServices->LocateProtocol(
      &gEfiTcg2ProtocolGuid, NULL, (VOID **)&tcg2);
  if (EFI_ERROR(status) || tcg2 == NULL) {
    context->LastStatus = EFI_UNSUPPORTED;
    return PBNS_ERR_UNSUPPORTED;
  }
  EFI_PHYSICAL_ADDRESS location = 0U;
  EFI_PHYSICAL_ADDRESS last_entry = 0U;
  BOOLEAN truncated = TRUE;
  status = tcg2->GetEventLog(tcg2, EFI_TCG2_EVENT_LOG_FORMAT_TCG_2, &location,
                             &last_entry, &truncated);
  if (EFI_ERROR(status)) {
    context->LastStatus = status;
    return PBNS_ERR_SERVICE;
  }
  if (location == 0U || last_entry < location ||
      location > (EFI_PHYSICAL_ADDRESS)UINTPTR_MAX ||
      last_entry > (EFI_PHYSICAL_ADDRESS)UINTPTR_MAX) {
    return PBNS_ERR_FORMAT;
  }
  const pbns_uefi_memory_ops ops = memory_ops(context);
  size_t source_extent = 0U;
  pbns_status memory_status = pbns_uefi_memory_readable_extent(
      &ops, (uint64_t)location, PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE,
      &source_extent);
  if (memory_status != PBNS_OK ||
      last_entry - location >= (UINT64)source_extent) {
    return memory_status == PBNS_OK ? PBNS_ERR_FORMAT : memory_status;
  }
  size_t base_size = 0U;
  pbns_status core_status = pbns_measured_boot_locate_event_log_end(
      (pbns_view){(const uint8_t *)(uintptr_t)location, source_extent},
      (size_t)(last_entry - location), &base_size);
  if (core_status != PBNS_OK) {
    return core_status;
  }
  Source->base_log =
      (pbns_view){(const uint8_t *)(uintptr_t)location, base_size};
  Source->truncated = truncated;

  VOID *final_table = NULL;
  status = PbnsMeasuredBootFindFinalEventsTable(
      context->SystemTable, &ops, &final_table);
  if (status == EFI_SUCCESS) {
    const EFI_PHYSICAL_ADDRESS final_address =
        (EFI_PHYSICAL_ADDRESS)(uintptr_t)final_table;
    size_t final_extent = 0U;
    memory_status = pbns_uefi_memory_readable_extent(
        &ops, (uint64_t)final_address,
        PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE + 16U, &final_extent);
    if (memory_status != PBNS_OK) {
      return memory_status;
    }
    size_t final_size = 0U;
    core_status = pbns_measured_boot_locate_final_events_end(
        Source->base_log,
        (pbns_view){(const uint8_t *)final_table, final_extent}, &final_size);
    if (core_status != PBNS_OK) {
      return core_status;
    }
    Source->final_events_table =
        (pbns_view){(const uint8_t *)final_table, final_size};
    bool exact_suffix = false;
    core_status = pbns_measured_boot_final_events_exact_suffix(
        Source->base_log, Source->final_events_table, &exact_suffix);
    if (core_status != PBNS_OK) {
      return core_status;
    }
    Source->final_disposition =
        exact_suffix ? PBNS_MEASURED_BOOT_FINAL_ALREADY_INCLUDED_EXACT
                     : PBNS_MEASURED_BOOT_FINAL_APPEND;
  } else if (status != EFI_NOT_FOUND) {
    context->LastStatus = status;
    return PBNS_ERR_FORMAT;
  }
  status = PbnsUefiMonotonicMs(context->SystemTable->BootServices, &end);
  if (EFI_ERROR(status) || end < start) {
    context->LastStatus = status;
    return PBNS_ERR_SERVICE;
  }
  context->EventLogCaptureMs = end - start;
  return PBNS_OK;
}

static pbns_status uefi_pcr_read(
    void *Context, pbns_measured_boot_selection Selection,
    pbns_measured_boot_pcr_snapshot *Snapshot) {
  PBNS_MEASURED_BOOT_UEFI_CONTEXT *context = Context;
  UINT64 start = 0U;
  UINT64 end = 0U;
  EFI_STATUS status =
      PbnsUefiMonotonicMs(context->SystemTable->BootServices, &start);
  if (EFI_ERROR(status)) {
    context->LastStatus = status;
    return PBNS_ERR_SERVICE;
  }
  pbns_status core_status = pbns_measured_boot_read_pcr_chunks(
      Selection, PBNS_TPM_PCR_READ_CHUNK_MAX,
      PbnsMeasuredBootUefiPcrReadChunk, &context->LastStatus, Snapshot);
  status = PbnsUefiMonotonicMs(context->SystemTable->BootServices, &end);
  if (core_status != PBNS_OK || EFI_ERROR(status) || end < start) {
    if (EFI_ERROR(status)) {
      context->LastStatus = status;
    }
    ZeroMem(Snapshot, sizeof(*Snapshot));
    return core_status != PBNS_OK ? core_status : PBNS_ERR_SERVICE;
  }
  context->PcrReadMs += end - start;
  return PBNS_OK;
}

static pbns_status uefi_sha256(
    void *Context, pbns_view Input,
    uint8_t Digest[PBNS_MEASURED_BOOT_DIGEST_SIZE]) {
  (void)Context;
  return mbedtls_sha256(Input.ptr, Input.len, Digest, 0) == 0
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static EFI_STATUS status_to_efi(pbns_status Status,
                                const PBNS_MEASURED_BOOT_UEFI_CONTEXT *Context) {
  if (Status == PBNS_OK) {
    return EFI_SUCCESS;
  }
  if (Context != NULL && EFI_ERROR(Context->LastStatus)) {
    return Context->LastStatus;
  }
  switch (Status) {
  case PBNS_ERR_ARGUMENT:
    return EFI_INVALID_PARAMETER;
  case PBNS_ERR_UNSUPPORTED:
    return EFI_UNSUPPORTED;
  case PBNS_ERR_AUTHENTICATION:
    return EFI_SECURITY_VIOLATION;
  case PBNS_ERR_BUSY:
    return EFI_NOT_READY;
  case PBNS_ERR_LIMIT:
    return EFI_BAD_BUFFER_SIZE;
  case PBNS_ERR_CRYPTO:
    return EFI_DEVICE_ERROR;
  default:
    return EFI_COMPROMISED_DATA;
  }
}

EFI_STATUS EFIAPI PbnsMeasuredBootCaptureSelection(
    EFI_SYSTEM_TABLE *SystemTable, pbns_measured_boot_selection Selection,
    pbns_measured_boot_policy_fn PolicyAllows, VOID *PolicyContext,
    pbns_buffer EventLogArena, pbns_measured_boot_evidence *Evidence) {
  if (Evidence != NULL) {
    *Evidence = (pbns_measured_boot_evidence){0};
  }
  if (SystemTable == NULL || SystemTable->BootServices == NULL ||
      PolicyAllows == NULL || Evidence == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  PBNS_MEASURED_BOOT_UEFI_CONTEXT context = {
      .SystemTable = SystemTable,
      .LastStatus = EFI_SUCCESS,
  };
  const pbns_measured_boot_capture_input input = {
      .selection = Selection,
      .event_log_read = uefi_event_log_read,
      .pcr_read = uefi_pcr_read,
      .sha256 = uefi_sha256,
      .policy_allows = PolicyAllows,
      .context = &context,
      .policy_context = PolicyContext,
  };
  const pbns_status capture_status =
      pbns_measured_boot_capture_evidence(&input, EventLogArena, Evidence);
  if (capture_status != PBNS_OK) {
    const EFI_STATUS status = status_to_efi(capture_status, &context);
    ZeroMem(&context, sizeof(context));
    return status;
  }
  Evidence->event_log_capture_ms = context.EventLogCaptureMs;
  Evidence->pcr_read_ms = context.PcrReadMs;
  ZeroMem(&context, sizeof(context));
  return EFI_SUCCESS;
}

static bool default_policy(void *Context,
                           pbns_measured_boot_selection Selection) {
  (void)Context;
  static const pbns_measured_boot_selection_item expected[] = {
      {PBNS_TPM_ALG_SHA256, 0U}, {PBNS_TPM_ALG_SHA256, 2U},
      {PBNS_TPM_ALG_SHA256, 4U}, {PBNS_TPM_ALG_SHA256, 7U}};
  if (Selection.count != sizeof(expected) / sizeof(expected[0])) {
    return false;
  }
  for (size_t index = 0U; index < Selection.count; ++index) {
    if (Selection.items[index].hash_algorithm !=
            expected[index].hash_algorithm ||
        Selection.items[index].pcr_index != expected[index].pcr_index) {
      return false;
    }
  }
  return true;
}

EFI_STATUS EFIAPI PbnsMeasuredBootCapture(EFI_BOOT_SERVICES *BootServices,
                                          pbns_buffer EventLogBuffer,
                                          pbns_measured_boot_capture *Capture) {
  if (BootServices == NULL || EventLogBuffer.ptr == NULL ||
      EventLogBuffer.len != 0U ||
      EventLogBuffer.cap < PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE ||
      Capture == NULL || gST == NULL || gST->BootServices != BootServices) {
    return EFI_INVALID_PARAMETER;
  }
  *Capture = (pbns_measured_boot_capture){0};
  static const pbns_measured_boot_selection_item items[] = {
      {PBNS_TPM_ALG_SHA256, 0U}, {PBNS_TPM_ALG_SHA256, 2U},
      {PBNS_TPM_ALG_SHA256, 4U}, {PBNS_TPM_ALG_SHA256, 7U},
  };
  pbns_measured_boot_evidence evidence = {0};
  EFI_STATUS status = PbnsMeasuredBootCaptureSelection(
      gST, (pbns_measured_boot_selection){items, 4U}, default_policy, NULL,
      EventLogBuffer, &evidence);
  if (EFI_ERROR(status)) {
    ZeroMem(&evidence, sizeof(evidence));
    return status;
  }
  for (size_t index = 0U; index < PBNS_BASELINE_PCR_COUNT; ++index) {
    Capture->pcrs[index].index = evidence.pcrs[index].selection.pcr_index;
    CopyMem(Capture->pcrs[index].digest, evidence.pcrs[index].digest,
            sizeof(Capture->pcrs[index].digest));
  }
  Capture->event_log_size = evidence.event_log.len;
  Capture->event_count = evidence.event_count;
  Capture->pcr_update_counter = evidence.pcr_update_counter;
  Capture->EventLogCaptureMs = evidence.event_log_capture_ms;
  Capture->PcrReadMs = evidence.pcr_read_ms;
  ZeroMem(&evidence, sizeof(evidence));
  return EFI_SUCCESS;
}
