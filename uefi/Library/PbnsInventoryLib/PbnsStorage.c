#include <Uefi.h>

#include "PbnsInventoryLib.h"
#include <Protocol/BlockIo.h>

#include <stddef.h>
#include <stdint.h>

#define PBNS_GIB_BYTES (UINT64_C(1024) * 1024U * 1024U)

EFI_STATUS EFIAPI PbnsInventoryStorage(EFI_BOOT_SERVICES *BootServices,
                                       pbns_inventory_inputs *Inputs) {
  if (BootServices == NULL || Inputs == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Inputs->storage_status = PBNS_INVENTORY_UNSUPPORTED;
  Inputs->block_device_count = 0U;
  Inputs->storage_capacity_gib = 0U;

  EFI_HANDLE *handles = NULL;
  UINTN handle_count = 0U;
  EFI_STATUS status = BootServices->LocateHandleBuffer(
      ByProtocol, &gEfiBlockIoProtocolGuid, NULL, &handle_count, &handles);
  if (status == EFI_NOT_FOUND) {
    Inputs->storage_status = PBNS_INVENTORY_ABSENT;
    return EFI_SUCCESS;
  }
  if (EFI_ERROR(status) || handles == NULL) {
    Inputs->storage_status = PBNS_INVENTORY_ERROR;
    return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
  }

  pbns_inventory_storage_collector collector = {0};
  EFI_STATUS result = EFI_SUCCESS;
  for (UINTN index = 0U; index < handle_count; ++index) {
    EFI_BLOCK_IO_PROTOCOL *block = NULL;
    status = BootServices->HandleProtocol(handles[index], &gEfiBlockIoProtocolGuid,
                                          (VOID **)&block);
    if (EFI_ERROR(status) || block == NULL || block->Media == NULL) {
      Inputs->storage_status = PBNS_INVENTORY_ERROR;
      result = EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
      break;
    }
    const pbns_inventory_block_device approved = {
        .last_block = block->Media->LastBlock,
        .block_size = block->Media->BlockSize,
        .removable = block->Media->RemovableMedia != FALSE,
        .logical_partition = block->Media->LogicalPartition != FALSE,
    };
    const pbns_status core_status =
        pbns_inventory_storage_add(&collector, &approved);
    if (core_status != PBNS_OK) {
      Inputs->storage_status = core_status == PBNS_ERR_LIMIT
                                   ? PBNS_INVENTORY_LIMIT
                                   : PBNS_INVENTORY_MALFORMED;
      result = core_status == PBNS_ERR_LIMIT ? EFI_BAD_BUFFER_SIZE
                                              : EFI_COMPROMISED_DATA;
      break;
    }
  }
  if (!EFI_ERROR(result)) {
    Inputs->block_device_count = collector.count;
    Inputs->storage_capacity_gib = collector.total_bytes / PBNS_GIB_BYTES;
    Inputs->storage_status = PBNS_INVENTORY_OK;
  }
  BootServices->FreePool((VOID *)handles);
  return result;
}
