#ifndef PBNS_INVENTORY_LIB_H
#define PBNS_INVENTORY_LIB_H

#include <Uefi.h>

#include "pbns/inventory.h"
#include "PbnsInventoryAdapterCore.h"

typedef struct PBNS_INVENTORY_CONFIGURATION {
  pbns_view HostFingerprint;
  pbns_buffer VariableScratch;
  uint32_t PbnsVersion;
  uint32_t PicoVersion;
  uint32_t GatewayVersion;
  uint64_t PriorLoaderEfiStatus;
} PBNS_INVENTORY_CONFIGURATION;

EFI_STATUS EFIAPI PbnsInventoryCapture(
    EFI_SYSTEM_TABLE *SystemTable,
    const PBNS_INVENTORY_CONFIGURATION *Configuration,
    pbns_inventory_report *Report);

pbns_inventory_capability PbnsInventoryCapabilityFromEfiStatus(
    EFI_STATUS Status);
EFI_STATUS PbnsInventoryEfiStatusFromAdapterResult(
    pbns_inventory_adapter_result Result);
void PbnsInventoryCollectTpm(EFI_BOOT_SERVICES *BootServices,
                             pbns_inventory_inputs *Inputs,
                             uint32_t Banks[5]);
EFI_STATUS EFIAPI PbnsInventorySmbios(EFI_SYSTEM_TABLE *SystemTable,
                                      pbns_inventory_inputs *Inputs);
EFI_STATUS EFIAPI PbnsInventoryPci(EFI_BOOT_SERVICES *BootServices,
                                   pbns_inventory_inputs *Inputs);
EFI_STATUS EFIAPI PbnsInventoryStorage(EFI_BOOT_SERVICES *BootServices,
                                       pbns_inventory_inputs *Inputs);
EFI_STATUS EFIAPI PbnsInventorySecureBoot(
    EFI_RUNTIME_SERVICES *RuntimeServices, pbns_buffer Scratch,
    pbns_inventory_inputs *Inputs);

#endif
