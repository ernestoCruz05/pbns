#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include "PbnsInventoryLib.h"
#include <Protocol/PciIo.h>

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

EFI_STATUS EFIAPI PbnsInventoryPci(EFI_BOOT_SERVICES *BootServices,
                                   pbns_inventory_inputs *Inputs) {
  if (BootServices == NULL || Inputs == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  Inputs->pci_status = PBNS_INVENTORY_UNSUPPORTED;
  SetMem(Inputs->pci_digest, PBNS_INVENTORY_DIGEST_SIZE, 0U);

  EFI_HANDLE *handles = NULL;
  UINTN handle_count = 0U;
  EFI_STATUS status = BootServices->LocateHandleBuffer(
      ByProtocol, &gEfiPciIoProtocolGuid, NULL, &handle_count, &handles);
  if (status == EFI_NOT_FOUND) {
    Inputs->pci_status = PBNS_INVENTORY_ABSENT;
    return EFI_SUCCESS;
  }
  if (EFI_ERROR(status) || handles == NULL) {
    Inputs->pci_status = PBNS_INVENTORY_ERROR;
    return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
  }

  pbns_inventory_pci_collector *collector =
      AllocateZeroPool(sizeof(*collector));
  if (collector == NULL) {
    BootServices->FreePool((VOID *)handles);
    Inputs->pci_status = PBNS_INVENTORY_ERROR;
    return EFI_OUT_OF_RESOURCES;
  }

  EFI_STATUS result = EFI_SUCCESS;
  for (UINTN index = 0U; index < handle_count; ++index) {
    EFI_PCI_IO_PROTOCOL *pci = NULL;
    status = BootServices->HandleProtocol(handles[index], &gEfiPciIoProtocolGuid,
                                          (VOID **)&pci);
    if (EFI_ERROR(status) || pci == NULL) {
      Inputs->pci_status = PBNS_INVENTORY_ERROR;
      result = EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
      break;
    }
    UINTN segment = 0U;
    UINTN bus = 0U;
    UINTN device = 0U;
    UINTN function = 0U;
    status = pci->GetLocation(pci, &segment, &bus, &device, &function);
    if (EFI_ERROR(status) || segment > UINT16_MAX || bus > UINT8_MAX ||
        device > 31U || function > 7U) {
      Inputs->pci_status = EFI_ERROR(status) ? PBNS_INVENTORY_ERROR
                                              : PBNS_INVENTORY_MALFORMED;
      result = EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
      break;
    }
    uint8_t configuration[12] = {0};
    status = pci->Pci.Read(pci, EfiPciIoWidthUint8, 0U,
                           sizeof(configuration), configuration);
    if (EFI_ERROR(status)) {
      Inputs->pci_status = PBNS_INVENTORY_ERROR;
      result = status;
      break;
    }
    const pbns_inventory_pci_function approved = {
        .segment = (uint16_t)segment,
        .bus = (uint8_t)bus,
        .device = (uint8_t)device,
        .function = (uint8_t)function,
        .vendor_id =
            (uint16_t)((uint16_t)configuration[0U] |
                       (uint16_t)((uint16_t)configuration[1U] << 8U)),
        .device_id =
            (uint16_t)((uint16_t)configuration[2U] |
                       (uint16_t)((uint16_t)configuration[3U] << 8U)),
        .class_code = configuration[11U],
        .subclass = configuration[10U],
        .prog_if = configuration[9U],
    };
    const pbns_status core_status = pbns_inventory_pci_add(collector, &approved);
    if (core_status != PBNS_OK) {
      Inputs->pci_status = core_status == PBNS_ERR_LIMIT
                               ? PBNS_INVENTORY_LIMIT
                               : PBNS_INVENTORY_MALFORMED;
      result = core_status == PBNS_ERR_LIMIT ? EFI_BAD_BUFFER_SIZE
                                              : EFI_COMPROMISED_DATA;
      break;
    }
  }

  if (!EFI_ERROR(result)) {
    const pbns_status core_status = pbns_inventory_pci_finish(
        collector, hash_sha256, NULL, Inputs->pci_digest);
    if (core_status == PBNS_OK) {
      Inputs->pci_status = PBNS_INVENTORY_OK;
    } else {
      Inputs->pci_status = PBNS_INVENTORY_ERROR;
      result = EFI_COMPROMISED_DATA;
    }
  }
  ZeroMem(collector, sizeof(*collector));
  FreePool(collector);
  BootServices->FreePool((VOID *)handles);
  return result;
}
