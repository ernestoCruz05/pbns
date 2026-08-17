#ifndef PBNS_BOOT_CONFIG_LIB_H
#define PBNS_BOOT_CONFIG_LIB_H

#include <Uefi.h>

#include <Protocol/DevicePath.h>

#include <pbns/boot_config.h>
#include <pbns/launcher.h>

#define PBNS_BOOT_CONFIG_VARIABLE_NAME L"PbnsBootConfigV1"
#define PBNS_BOOT_FAILURE_VARIABLE_NAME L"PbnsBootFailureV1"

EFI_STATUS
PbnsBootConfigRead(IN EFI_RUNTIME_SERVICES *RuntimeServices,
                   OUT pbns_launcher_config *Config, OUT UINT8 *PathStorage,
                   IN UINTN PathStorageCapacity);

EFI_STATUS
PbnsBootConfigWrite(IN EFI_RUNTIME_SERVICES *RuntimeServices,
                    IN UINT16 NormalBootOption,
                    IN EFI_DEVICE_PATH_PROTOCOL *RecoveryDevicePath);

EFI_STATUS
PbnsBootConfigRecordFailure(IN EFI_RUNTIME_SERVICES *RuntimeServices,
                            IN pbns_launcher_stage Stage,
                            IN EFI_STATUS FailureStatus);

#endif
