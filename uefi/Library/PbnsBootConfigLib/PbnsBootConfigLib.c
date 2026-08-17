#include <Uefi.h>

#include <Guid/GlobalVariable.h>
#include <Library/DevicePathLib.h>

#include <pbns/boot_config.h>

#include "PbnsBootConfigLib.h"

static EFI_STATUS PbnsStatusToEfi(IN pbns_status Status) {
  if (Status == PBNS_ERR_ARGUMENT) {
    return EFI_INVALID_PARAMETER;
  }
  if (Status == PBNS_ERR_LIMIT) {
    return EFI_BAD_BUFFER_SIZE;
  }
  if (Status == PBNS_ERR_CRC) {
    return EFI_CRC_ERROR;
  }
  return EFI_COMPROMISED_DATA;
}

EFI_STATUS
PbnsBootConfigRead(IN EFI_RUNTIME_SERVICES *RuntimeServices,
                   OUT pbns_launcher_config *Config, OUT UINT8 *PathStorage,
                   IN UINTN PathStorageCapacity) {
  union {
    UINT64 Alignment;
    UINT8 Bytes[PBNS_BOOT_CONFIG_ENCODED_CAP];
  } Encoded = {0};
  pbns_boot_config PortableConfig = {0};
  UINTN EncodedSize = sizeof(Encoded.Bytes);
  UINT32 Attributes = 0U;
  UINT16 BootCurrent = 0U;
  UINTN BootCurrentSize;
  pbns_status DecodeStatus;
  EFI_STATUS Status;

  if ((RuntimeServices == NULL) || (Config == NULL) || (PathStorage == NULL) ||
      (PathStorageCapacity < PBNS_BOOT_CONFIG_PATH_CAP)) {
    return EFI_INVALID_PARAMETER;
  }
  *Config = (pbns_launcher_config){0};
  Status = RuntimeServices->GetVariable(PBNS_BOOT_CONFIG_VARIABLE_NAME,
                                        &gPbnsBootConfigGuid, &Attributes,
                                        &EncodedSize, Encoded.Bytes);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (Attributes !=
      (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)) {
    return EFI_COMPROMISED_DATA;
  }
  DecodeStatus = pbns_boot_config_decode(
      (pbns_view){Encoded.Bytes, (size_t)EncodedSize},
      (pbns_buffer){PathStorage, 0U, (size_t)PathStorageCapacity},
      &PortableConfig);
  if (DecodeStatus != PBNS_OK) {
    return PbnsStatusToEfi(DecodeStatus);
  }
  if (!IsDevicePathValid((EFI_DEVICE_PATH_PROTOCOL *)PathStorage,
                         (UINTN)PortableConfig.recovery_device_path.len) ||
      (GetDevicePathSize((EFI_DEVICE_PATH_PROTOCOL *)PathStorage) !=
       (UINTN)PortableConfig.recovery_device_path.len)) {
    return EFI_COMPROMISED_DATA;
  }
  Config->normal_boot_option = PortableConfig.normal_boot_option;
  Config->recovery_device_path = PortableConfig.recovery_device_path;

  BootCurrentSize = sizeof(BootCurrent);
  Status = RuntimeServices->GetVariable(L"BootCurrent", &gEfiGlobalVariableGuid,
                                        NULL, &BootCurrentSize, &BootCurrent);
  if (!EFI_ERROR(Status) && (BootCurrentSize == sizeof(BootCurrent))) {
    Config->self_reference = BootCurrent == Config->normal_boot_option;
  } else if (Status != EFI_NOT_FOUND) {
    return EFI_COMPROMISED_DATA;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
PbnsBootConfigWrite(IN EFI_RUNTIME_SERVICES *RuntimeServices,
                    IN UINT16 NormalBootOption,
                    IN EFI_DEVICE_PATH_PROTOCOL *RecoveryDevicePath) {
  union {
    UINT64 Alignment;
    UINT8 Bytes[PBNS_BOOT_CONFIG_ENCODED_CAP];
  } Encoded = {0};
  pbns_boot_config Config;
  UINTN PathSize;
  size_t Written = 0U;
  pbns_status Status;

  if ((RuntimeServices == NULL) || (RecoveryDevicePath == NULL) ||
      !IsDevicePathValid(RecoveryDevicePath, PBNS_BOOT_CONFIG_PATH_CAP)) {
    return EFI_INVALID_PARAMETER;
  }
  PathSize = GetDevicePathSize(RecoveryDevicePath);
  if ((PathSize == 0U) || (PathSize > PBNS_BOOT_CONFIG_PATH_CAP)) {
    return EFI_BAD_BUFFER_SIZE;
  }
  Config = (pbns_boot_config){
      .normal_boot_option = NormalBootOption,
      .recovery_device_path = {(CONST uint8_t *)RecoveryDevicePath,
                               (size_t)PathSize},
  };
  Status = pbns_boot_config_encode(
      &Config, (pbns_buffer){Encoded.Bytes, 0U, sizeof(Encoded.Bytes)},
      &Written);
  if (Status != PBNS_OK) {
    return PbnsStatusToEfi(Status);
  }
  return RuntimeServices->SetVariable(
      PBNS_BOOT_CONFIG_VARIABLE_NAME, &gPbnsBootConfigGuid,
      EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
      (UINTN)Written, Encoded.Bytes);
}

EFI_STATUS
PbnsBootConfigRecordFailure(IN EFI_RUNTIME_SERVICES *RuntimeServices,
                            IN pbns_launcher_stage Stage,
                            IN EFI_STATUS FailureStatus) {
  UINT8 Encoded[PBNS_BOOT_FAILURE_ENCODED_SIZE] = {0};
  size_t Written = 0U;
  pbns_status Status;
  pbns_boot_failure Failure;

  if ((RuntimeServices == NULL) || (Stage < PBNS_LAUNCHER_STAGE_LOAD_NORMAL) ||
      (Stage > PBNS_LAUNCHER_STAGE_START_NORMAL)) {
    return EFI_INVALID_PARAMETER;
  }
  Failure = (pbns_boot_failure){
      .stage = (uint8_t)Stage,
      .platform_status = (uint64_t)FailureStatus,
  };
  Status = pbns_boot_failure_encode(
      &Failure, (pbns_buffer){Encoded, 0U, sizeof(Encoded)}, &Written);
  if (Status != PBNS_OK) {
    return PbnsStatusToEfi(Status);
  }
  return RuntimeServices->SetVariable(
      PBNS_BOOT_FAILURE_VARIABLE_NAME, &gPbnsBootConfigGuid,
      EFI_VARIABLE_BOOTSERVICE_ACCESS, (UINTN)Written, Encoded);
}
