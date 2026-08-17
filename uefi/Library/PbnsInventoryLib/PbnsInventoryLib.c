#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include "PbnsInventoryAdapterCore.h"
#include "PbnsInventoryLib.h"
#include <Protocol/Tcg2Protocol.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

EFI_STATUS PbnsInventoryEfiStatusFromAdapterResult(
    pbns_inventory_adapter_result Result) {
  if (Result.kind == PBNS_PLATFORM_SUCCESS) {
    return EFI_SUCCESS;
  }
  if (Result.kind == PBNS_PLATFORM_LIMIT) {
    return EFI_BAD_BUFFER_SIZE;
  }
  if (Result.native_status != 0U) {
    return Result.native_status;
  }
  switch (Result.kind) {
    case PBNS_PLATFORM_NOT_FOUND:
      return EFI_NOT_FOUND;
    case PBNS_PLATFORM_UNSUPPORTED:
      return EFI_UNSUPPORTED;
    case PBNS_PLATFORM_MALFORMED:
      return EFI_COMPROMISED_DATA;
    case PBNS_PLATFORM_ERROR:
    default:
      return EFI_DEVICE_ERROR;
  }
}

pbns_inventory_capability PbnsInventoryCapabilityFromEfiStatus(
    EFI_STATUS Status) {
  pbns_inventory_platform_result result = PBNS_PLATFORM_ERROR;
  if (Status == EFI_SUCCESS) {
    result = PBNS_PLATFORM_SUCCESS;
  } else if (Status == EFI_NOT_FOUND) {
    result = PBNS_PLATFORM_NOT_FOUND;
  } else if (Status == EFI_UNSUPPORTED) {
    result = PBNS_PLATFORM_UNSUPPORTED;
  } else if (Status == EFI_COMPROMISED_DATA) {
    result = PBNS_PLATFORM_MALFORMED;
  } else if (Status == EFI_BAD_BUFFER_SIZE || Status == EFI_BUFFER_TOO_SMALL) {
    result = PBNS_PLATFORM_LIMIT;
  }
  return pbns_inventory_classify_platform_result(result);
}

void PbnsInventoryCollectTpm(EFI_BOOT_SERVICES *BootServices,
                             pbns_inventory_inputs *Inputs,
                             uint32_t Banks[5]) {
  Inputs->tpm = (pbns_inventory_tpm_input){
      .status = PBNS_INVENTORY_UNSUPPORTED,
  };
  EFI_TCG2_PROTOCOL *tcg2 = NULL;
  EFI_STATUS status =
      BootServices->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL, (VOID **)&tcg2);
  if (EFI_ERROR(status) || tcg2 == NULL) {
    Inputs->tpm.status = EFI_ERROR(status)
                             ? PbnsInventoryCapabilityFromEfiStatus(status)
                             : PBNS_INVENTORY_ERROR;
    return;
  }
  EFI_TCG2_BOOT_SERVICE_CAPABILITY capability = {0};
  capability.Size = (UINT8)sizeof(capability);
  status = tcg2->GetCapability(tcg2, &capability);
  if (EFI_ERROR(status)) {
    Inputs->tpm.status = PbnsInventoryCapabilityFromEfiStatus(status);
    return;
  }
  if (capability.Size < sizeof(capability)) {
    Inputs->tpm.status = PBNS_INVENTORY_UNSUPPORTED;
    return;
  }
  if (capability.TPMPresentFlag == FALSE) {
    Inputs->tpm.status = PBNS_INVENTORY_ABSENT;
    return;
  }

  const pbns_inventory_adapter_tcg_capability approved = {
      .present = true,
      .manufacturer = capability.ManufacturerID,
      /* A capacidade TCG2 não expõe uma versão de firmware TPM portátil. */
      .firmware_version = 0U,
      .active_bitmap = capability.ActivePcrBanks,
      .supported_bank_count = capability.NumberOfPCRBanks,
  };
  (void)pbns_inventory_adapter_tcg(&approved, Banks, 5U, &Inputs->tpm);
}

EFI_STATUS EFIAPI PbnsInventoryCapture(
    EFI_SYSTEM_TABLE *SystemTable,
    const PBNS_INVENTORY_CONFIGURATION *Configuration,
    pbns_inventory_report *Report) {
  if (SystemTable == NULL || SystemTable->BootServices == NULL ||
      SystemTable->RuntimeServices == NULL || Configuration == NULL ||
      Configuration->HostFingerprint.ptr == NULL ||
      Configuration->HostFingerprint.len != PBNS_INVENTORY_DIGEST_SIZE ||
      Configuration->VariableScratch.ptr == NULL ||
      Configuration->VariableScratch.len != 0U ||
      Configuration->VariableScratch.cap == 0U ||
      Configuration->VariableScratch.cap > PBNS_INVENTORY_VARIABLE_MAX_SIZE ||
      Report == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Report = (pbns_inventory_report){0};
  pbns_inventory_inputs inputs = {
      .host_fingerprint = Configuration->HostFingerprint,
      .pbns_version = Configuration->PbnsVersion,
      .pico_version = Configuration->PicoVersion,
      .gateway_version = Configuration->GatewayVersion,
      .prior_loader_efi_status = Configuration->PriorLoaderEfiStatus,
      .smbios_status = PBNS_INVENTORY_UNSUPPORTED,
      .pci_status = PBNS_INVENTORY_UNSUPPORTED,
      .storage_status = PBNS_INVENTORY_UNSUPPORTED,
      .secure_boot = {.status = PBNS_INVENTORY_UNSUPPORTED},
      .tpm = {.status = PBNS_INVENTORY_UNSUPPORTED},
  };
  (void)PbnsInventorySmbios(SystemTable, &inputs);
  (void)PbnsInventoryPci(SystemTable->BootServices, &inputs);
  (void)PbnsInventoryStorage(SystemTable->BootServices, &inputs);
  (void)PbnsInventorySecureBoot(SystemTable->RuntimeServices,
                                Configuration->VariableScratch, &inputs);
  uint32_t banks[5] = {0};
  PbnsInventoryCollectTpm(SystemTable->BootServices, &inputs, banks);
  const pbns_status status = pbns_inventory_collect(&inputs, Report);
  ZeroMem(banks, sizeof(banks));
  ZeroMem(&inputs, sizeof(inputs));
  if (status != PBNS_OK) {
    *Report = (pbns_inventory_report){0};
    return EFI_COMPROMISED_DATA;
  }
  return EFI_SUCCESS;
}
