#include "PbnsMeasuredBootUefiAdapter.h"

#include <IndustryStandard/Tpm20.h>
#include <Library/BaseMemoryLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Protocol/Tcg2Protocol.h>

#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(((TPML_DIGEST *)0)->digests) /
                       sizeof(((TPML_DIGEST *)0)->digests[0]) <=
                   PBNS_TPM_PCR_READ_CHUNK_MAX,
               "TPM PCR read chunk capacity");

static bool guid_equal(const EFI_GUID *Left, const EFI_GUID *Right) {
  return Left->Data1 == Right->Data1 && Left->Data2 == Right->Data2 &&
         Left->Data3 == Right->Data3 &&
         CompareMem(Left->Data4, Right->Data4, sizeof(Left->Data4)) == 0;
}

EFI_STATUS PbnsMeasuredBootFindFinalEventsTable(
    EFI_SYSTEM_TABLE *SystemTable, const pbns_uefi_memory_ops *MemoryOps,
    VOID **Table) {
  if (Table == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Table = NULL;
  if (SystemTable == NULL || MemoryOps == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  EFI_CONFIGURATION_TABLE *const entries = SystemTable->ConfigurationTable;
  const UINTN count = SystemTable->NumberOfTableEntries;
  if (count == 0U) {
    return EFI_NOT_FOUND;
  }
  if (entries == NULL ||
      count > MAX_UINTN / sizeof(EFI_CONFIGURATION_TABLE)) {
    return EFI_COMPROMISED_DATA;
  }
  const size_t table_bytes = count * sizeof(EFI_CONFIGURATION_TABLE);
  if (pbns_uefi_memory_range_readable(
          MemoryOps, (uint64_t)(uintptr_t)entries, table_bytes) != PBNS_OK) {
    return EFI_COMPROMISED_DATA;
  }
  for (UINTN index = 0U; index < count; ++index) {
    if (guid_equal(&entries[index].VendorGuid,
                   &gEfiTcg2FinalEventsTableGuid)) {
      *Table = entries[index].VendorTable;
      return *Table == NULL ? EFI_COMPROMISED_DATA : EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}

pbns_status PbnsMeasuredBootUefiPcrReadChunk(
    VOID *Context, pbns_measured_boot_selection Selection,
    pbns_measured_boot_pcr_snapshot *Snapshot) {
  EFI_STATUS *last_status = Context;
  if (last_status == NULL || Snapshot == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Snapshot = (pbns_measured_boot_pcr_snapshot){0};
  if (Selection.items == NULL || Selection.count == 0U ||
      Selection.count > PBNS_TPM_PCR_READ_CHUNK_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  TPML_PCR_SELECTION input = {
      .count = 1U,
      .pcrSelections = {{.hash = TPM_ALG_SHA256, .sizeofSelect = 3U}},
  };
  for (size_t index = 0U; index < Selection.count; ++index) {
    const uint8_t pcr = Selection.items[index].pcr_index;
    input.pcrSelections[0].pcrSelect[pcr / 8U] |=
        (uint8_t)(1U << (pcr % 8U));
  }
  TPML_PCR_SELECTION output = {0};
  TPML_DIGEST values = {0};
  UINT32 update_counter = 0U;
  const EFI_STATUS status =
      Tpm2PcrRead(&input, &update_counter, &output, &values);
  if (EFI_ERROR(status)) {
    *last_status = status;
    ZeroMem(&values, sizeof(values));
    return PBNS_ERR_SERVICE;
  }
  if (output.count != 1U || output.pcrSelections[0].hash != TPM_ALG_SHA256 ||
      output.pcrSelections[0].sizeofSelect != 3U ||
      CompareMem(output.pcrSelections[0].pcrSelect,
                 input.pcrSelections[0].pcrSelect, 3U) != 0 ||
      values.count != (UINT32)Selection.count) {
    ZeroMem(&values, sizeof(values));
    return PBNS_ERR_FORMAT;
  }
  Snapshot->count = Selection.count;
  Snapshot->update_counter = update_counter;
  for (size_t index = 0U; index < Selection.count; ++index) {
    if (values.digests[index].size != PBNS_MEASURED_BOOT_DIGEST_SIZE) {
      ZeroMem(&values, sizeof(values));
      ZeroMem(Snapshot, sizeof(*Snapshot));
      return PBNS_ERR_FORMAT;
    }
    Snapshot->values[index].selection = Selection.items[index];
    Snapshot->values[index].digest_size = PBNS_MEASURED_BOOT_DIGEST_SIZE;
    CopyMem(Snapshot->values[index].digest, values.digests[index].buffer,
            PBNS_MEASURED_BOOT_DIGEST_SIZE);
  }
  ZeroMem(&values, sizeof(values));
  return PBNS_OK;
}
