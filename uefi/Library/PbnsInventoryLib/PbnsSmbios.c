#include <Uefi.h>

#include <Guid/SmBios.h>
#include <IndustryStandard/SmBios.h>
#include <Library/BaseMemoryLib.h>

#include "PbnsInventoryAdapterCore.h"
#include "PbnsInventoryLib.h"

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/sha256.h"

static pbns_status hash_sha256(void *Context, pbns_view Input,
                               uint8_t Digest[32]) {
  (void)Context;
  if (Digest == NULL || (Input.ptr == NULL && Input.len != 0U)) {
    return PBNS_ERR_ARGUMENT;
  }
  return mbedtls_sha256(Input.ptr, Input.len, Digest, 0) == 0
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static pbns_inventory_capability capability_from_core(pbns_status Status) {
  switch (Status) {
    case PBNS_OK:
      return PBNS_INVENTORY_OK;
    case PBNS_ERR_FORMAT:
      return PBNS_INVENTORY_MALFORMED;
    case PBNS_ERR_LIMIT:
      return PBNS_INVENTORY_LIMIT;
    default:
      return PBNS_INVENTORY_ERROR;
  }
}

static bool find_configuration_table(const EFI_SYSTEM_TABLE *SystemTable,
                                     const EFI_GUID *Guid,
                                     const VOID **Table) {
  *Table = NULL;
  for (UINTN index = 0U; index < SystemTable->NumberOfTableEntries; ++index) {
    if (CompareGuid(&SystemTable->ConfigurationTable[index].VendorGuid, Guid)) {
      *Table = SystemTable->ConfigurationTable[index].VendorTable;
      return true;
    }
  }
  return false;
}

EFI_STATUS EFIAPI PbnsInventorySmbios(EFI_SYSTEM_TABLE *SystemTable,
                                      pbns_inventory_inputs *Inputs) {
  if (SystemTable == NULL || Inputs == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Inputs->smbios_status = PBNS_INVENTORY_UNSUPPORTED;
  Inputs->firmware_vendor = (pbns_inventory_text){0};
  Inputs->firmware_version = (pbns_inventory_text){0};
  Inputs->cpu_class = (pbns_inventory_text){0};
  Inputs->memory_mib = 0U;
  SetMem(Inputs->board_model_digest, PBNS_INVENTORY_DIGEST_SIZE, 0U);
  if (SystemTable->NumberOfTableEntries != 0U &&
      SystemTable->ConfigurationTable == NULL) {
    Inputs->smbios_status = PBNS_INVENTORY_MALFORMED;
    return EFI_COMPROMISED_DATA;
  }

  const VOID *entry = NULL;
  bool version3 = false;
  size_t entry_capacity = 0U;
  if (find_configuration_table(SystemTable, &gEfiSmbios3TableGuid, &entry)) {
    version3 = true;
    entry_capacity = sizeof(SMBIOS_TABLE_3_0_ENTRY_POINT);
  } else if (find_configuration_table(SystemTable, &gEfiSmbiosTableGuid,
                                      &entry)) {
    entry_capacity = sizeof(SMBIOS_TABLE_ENTRY_POINT);
  } else {
    Inputs->smbios_status = PBNS_INVENTORY_ABSENT;
    return EFI_NOT_FOUND;
  }
  if (entry == NULL) {
    Inputs->smbios_status = PBNS_INVENTORY_MALFORMED;
    return EFI_COMPROMISED_DATA;
  }

  pbns_inventory_adapter_smbios_table table = {0};
  const pbns_inventory_adapter_result entry_status =
      pbns_inventory_adapter_smbios_entry(
          (pbns_view){(const uint8_t *)entry, entry_capacity}, version3,
          &table);
  if (entry_status.kind != PBNS_PLATFORM_SUCCESS) {
    Inputs->smbios_status =
        pbns_inventory_classify_platform_result(entry_status.kind);
    return PbnsInventoryEfiStatusFromAdapterResult(entry_status);
  }

  const pbns_view declared_table = {
      (const uint8_t *)(UINTN)table.address,  // NOLINT(performance-no-int-to-ptr): endereço físico validado pelo núcleo.
      table.length};
  pbns_inventory_smbios_collector collector = {0};
  const pbns_inventory_adapter_result collect_status =
      pbns_inventory_adapter_smbios_collect(
          (pbns_view){(const uint8_t *)entry, entry_capacity}, version3,
          declared_table, &collector);
  if (collect_status.kind != PBNS_PLATFORM_SUCCESS) {
    Inputs->smbios_status =
        pbns_inventory_classify_platform_result(collect_status.kind);
    return PbnsInventoryEfiStatusFromAdapterResult(collect_status);
  }
  const pbns_status finish_status = pbns_inventory_smbios_finish(
      &collector, hash_sha256, NULL, Inputs->board_model_digest);
  if (finish_status != PBNS_OK) {
    Inputs->smbios_status = capability_from_core(finish_status);
    return finish_status == PBNS_ERR_LIMIT ? EFI_BAD_BUFFER_SIZE
                                           : EFI_COMPROMISED_DATA;
  }
  Inputs->firmware_vendor = collector.firmware_vendor;
  Inputs->firmware_version = collector.firmware_version;
  Inputs->cpu_class = collector.cpu_class;
  Inputs->memory_mib = collector.memory_mib;
  Inputs->smbios_status = PBNS_INVENTORY_OK;
  return EFI_SUCCESS;
}
