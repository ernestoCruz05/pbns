#include <Uefi.h>

#include <Guid/GlobalVariable.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>

#include <pbns/launcher.h>

#include "PbnsBootConfigLib.h"

#define PBNS_LAUNCHER_BOOT_OPTION_CAP 65536U

struct launcher_context {
  EFI_HANDLE ImageHandle;
  EFI_SYSTEM_TABLE *SystemTable;
  UINT8 *NormalOption;
  UINTN NormalOptionSize;
  pbns_launcher_config Config;
  union {
    UINT64 Alignment;
    UINT8 Bytes[PBNS_BOOT_CONFIG_PATH_CAP];
  } RecoveryPath;
};

static pbns_status StatusToPbns(IN EFI_STATUS Status) {
  if (Status == EFI_OUT_OF_RESOURCES) {
    return PBNS_ERR_RESOURCE;
  }
  if (Status == EFI_NOT_FOUND) {
    return PBNS_ERR_IO;
  }
  if ((Status == EFI_SECURITY_VIOLATION) || (Status == EFI_ACCESS_DENIED)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (Status == EFI_UNSUPPORTED) {
    return PBNS_ERR_UNSUPPORTED;
  }
  if ((Status == EFI_COMPROMISED_DATA) || (Status == EFI_CRC_ERROR) ||
      (Status == EFI_BAD_BUFFER_SIZE)) {
    return PBNS_ERR_FORMAT;
  }
  if (Status == EFI_INVALID_PARAMETER) {
    return PBNS_ERR_ARGUMENT;
  }
  return PBNS_ERR_IO;
}

static pbns_status LauncherReadConfig(IN VOID *Context,
                                      OUT pbns_launcher_config *Config,
                                      OUT uint64_t *PlatformStatus) {
  struct launcher_context *Launcher = Context;
  EFI_STATUS Status;

  if ((Launcher == NULL) || (Config == NULL) || (PlatformStatus == NULL)) {
    return PBNS_ERR_ARGUMENT;
  }
  Status = PbnsBootConfigRead(Launcher->SystemTable->RuntimeServices,
                              &Launcher->Config, Launcher->RecoveryPath.Bytes,
                              sizeof(Launcher->RecoveryPath.Bytes));
  *PlatformStatus = (UINT64)Status;
  if (EFI_ERROR(Status)) {
    return StatusToPbns(Status);
  }
  *Config = Launcher->Config;
  return PBNS_OK;
}

static EFI_STATUS
ReadNormalBootOption(IN OUT struct launcher_context *Launcher) {
  CHAR16 VariableName[9];
  UINTN VariableSize = 0U;
  UINT32 VariableAttributes;
  EFI_STATUS Status;
  UINTN Printed;

  Printed = UnicodeSPrint(VariableName, sizeof(VariableName), L"Boot%04x",
                          (UINT32)Launcher->Config.normal_boot_option);
  if ((Printed != 8) || (VariableName[8] != L'\0')) {
    return EFI_COMPROMISED_DATA;
  }
  Status = Launcher->SystemTable->RuntimeServices->GetVariable(
      VariableName, &gEfiGlobalVariableGuid, NULL, &VariableSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }
  if ((VariableSize < 8U) || (VariableSize > PBNS_LAUNCHER_BOOT_OPTION_CAP)) {
    return EFI_BAD_BUFFER_SIZE;
  }
  Launcher->NormalOption = AllocatePool(VariableSize);
  if (Launcher->NormalOption == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  Launcher->NormalOptionSize = VariableSize;
  VariableAttributes = 0U;
  Status = Launcher->SystemTable->RuntimeServices->GetVariable(
      VariableName, &gEfiGlobalVariableGuid, &VariableAttributes, &VariableSize,
      Launcher->NormalOption);
  if (EFI_ERROR(Status)) {
    FreePool(Launcher->NormalOption);
    Launcher->NormalOption = NULL;
    Launcher->NormalOptionSize = 0U;
    return Status;
  }
  if ((VariableSize != Launcher->NormalOptionSize) ||
      (VariableAttributes !=
       (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS))) {
    FreePool(Launcher->NormalOption);
    Launcher->NormalOption = NULL;
    Launcher->NormalOptionSize = 0U;
    return EFI_COMPROMISED_DATA;
  }
  return EFI_SUCCESS;
}

static EFI_STATUS
ParseNormalBootOption(IN struct launcher_context *Launcher,
                      OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath,
                      OUT VOID **OptionalData, OUT UINT32 *OptionalDataSize) {
  UINT8 *Encoded;
  UINTN EncodedSize;
  UINT16 FilePathSize;
  UINTN DescriptionOffset;
  UINTN PathOffset;

  if ((Launcher == NULL) || (Launcher->NormalOption == NULL) ||
      (DevicePath == NULL) || (OptionalData == NULL) ||
      (OptionalDataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }
  Encoded = Launcher->NormalOption;
  EncodedSize = Launcher->NormalOptionSize;
  FilePathSize = (UINT16)(((UINT16)Encoded[4]) | ((UINT16)Encoded[5] << 8U));
  DescriptionOffset = 6U;
  while ((DescriptionOffset + sizeof(CHAR16)) <= EncodedSize) {
    if ((Encoded[DescriptionOffset] == 0U) &&
        (Encoded[DescriptionOffset + 1U] == 0U)) {
      break;
    }
    DescriptionOffset += sizeof(CHAR16);
  }
  if ((DescriptionOffset + sizeof(CHAR16)) > EncodedSize) {
    return EFI_COMPROMISED_DATA;
  }
  PathOffset = DescriptionOffset + sizeof(CHAR16);
  if ((FilePathSize == 0U) || (PathOffset > EncodedSize) ||
      ((UINTN)FilePathSize > EncodedSize - PathOffset)) {
    return EFI_COMPROMISED_DATA;
  }
  *DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)(Encoded + PathOffset);
  if (!IsDevicePathValid(*DevicePath, FilePathSize) ||
      (GetDevicePathSize(*DevicePath) != FilePathSize)) {
    return EFI_COMPROMISED_DATA;
  }
  PathOffset += FilePathSize;
  if ((EncodedSize - PathOffset) > MAX_UINT32) {
    return EFI_BAD_BUFFER_SIZE;
  }
  *OptionalData = Encoded + PathOffset;
  *OptionalDataSize = (UINT32)(EncodedSize - PathOffset);
  return EFI_SUCCESS;
}

static VOID ReleaseNormalOption(IN OUT struct launcher_context *Launcher) {
  if ((Launcher != NULL) && (Launcher->NormalOption != NULL)) {
    FreePool(Launcher->NormalOption);
    Launcher->NormalOption = NULL;
    Launcher->NormalOptionSize = 0U;
  }
}

static pbns_status LauncherLoad(IN VOID *Context,
                                IN pbns_launcher_target Target,
                                IN CONST pbns_launcher_config *Config,
                                OUT VOID **Image,
                                OUT uint64_t *PlatformStatus) {
  struct launcher_context *Launcher = Context;
  EFI_DEVICE_PATH_PROTOCOL *DevicePath;
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
  VOID *OptionalData = NULL;
  UINT32 OptionalDataSize = 0U;
  EFI_STATUS Status;

  if ((Launcher == NULL) || (Config == NULL) || (Image == NULL) ||
      (PlatformStatus == NULL)) {
    return PBNS_ERR_ARGUMENT;
  }
  *Image = NULL;
  *PlatformStatus = (UINT64)EFI_INVALID_PARAMETER;
  if (Target == PBNS_LAUNCHER_TARGET_NORMAL) {
    Status = ReadNormalBootOption(Launcher);
    if (!EFI_ERROR(Status)) {
      Status = ParseNormalBootOption(Launcher, &DevicePath, &OptionalData,
                                     &OptionalDataSize);
    }
  } else if (Target == PBNS_LAUNCHER_TARGET_RECOVERY) {
    DevicePath = (EFI_DEVICE_PATH_PROTOCOL *)Launcher->RecoveryPath.Bytes;
    Status = EFI_SUCCESS;
  } else {
    return PBNS_ERR_ARGUMENT;
  }
  if (EFI_ERROR(Status)) {
    ReleaseNormalOption(Launcher);
    *PlatformStatus = (UINT64)Status;
    return StatusToPbns(Status);
  }

  Print(L"PBNS LAUNCHER: [1/3] Loading normal target OS (Boot%04x)...\r\n",
        (UINT32)Launcher->Config.normal_boot_option);
  Status = Launcher->SystemTable->BootServices->LoadImage(
      FALSE, Launcher->ImageHandle, DevicePath, NULL, 0U, (EFI_HANDLE *)Image);
  if (EFI_ERROR(Status)) {
    Print(L"PBNS LAUNCHER: LoadImage failed: status=0x%lx (%r)\r\n", (UINT64)Status, Status);
    ReleaseNormalOption(Launcher);
    *PlatformStatus = (UINT64)Status;
    return StatusToPbns(Status);
  }
  Print(L"PBNS LAUNCHER: [2/3] OS Image loaded successfully.\r\n");
  if (Target == PBNS_LAUNCHER_TARGET_NORMAL) {
    LoadedImage = NULL;
    Status = Launcher->SystemTable->BootServices->HandleProtocol(
        (EFI_HANDLE)*Image, &gEfiLoadedImageProtocolGuid,
        (VOID **)&LoadedImage);
    if (EFI_ERROR(Status) || (LoadedImage == NULL)) {
      Print(L"PBNS LAUNCHER: LoadedImage protocol failed: status=0x%lx\r\n", (UINT64)Status);
      Launcher->SystemTable->BootServices->UnloadImage((EFI_HANDLE)*Image);
      *Image = NULL;
      ReleaseNormalOption(Launcher);
      *PlatformStatus =
          (UINT64)(EFI_ERROR(Status) ? Status : EFI_COMPROMISED_DATA);
      return StatusToPbns((EFI_STATUS)*PlatformStatus);
    }
    LoadedImage->LoadOptions = OptionalData;
    LoadedImage->LoadOptionsSize = OptionalDataSize;
  }
  *PlatformStatus = (UINT64)EFI_SUCCESS;
  return PBNS_OK;
}

static pbns_status LauncherStart(IN VOID *Context,
                                 IN pbns_launcher_target Target, IN VOID *Image,
                                 OUT bool *Returned,
                                 OUT uint64_t *PlatformStatus) {
  struct launcher_context *Launcher = Context;
  EFI_STATUS Status;

  (void)Target;
  if ((Launcher == NULL) || (Image == NULL) || (Returned == NULL) ||
      (PlatformStatus == NULL)) {
    return PBNS_ERR_ARGUMENT;
  }
  Print(L"PBNS LAUNCHER: [3/3] Starting OS execution...\r\n");
  Status = Launcher->SystemTable->BootServices->StartImage((EFI_HANDLE)Image,
                                                           NULL, NULL);
  Print(L"PBNS LAUNCHER: StartImage returned status=0x%lx (%r)\r\n", (UINT64)Status, Status);
  *Returned = true;
  *PlatformStatus = (UINT64)Status;
  return EFI_ERROR(Status) ? StatusToPbns(Status) : PBNS_OK;
}

static VOID LauncherRecordFailure(IN VOID *Context,
                                  IN pbns_launcher_stage Stage,
                                  IN uint64_t PlatformStatus) {
  struct launcher_context *Launcher = Context;

  Print(L"PBNS LAUNCHER: Recorded failure stage=%u status=0x%lx\r\n", (UINT32)Stage, PlatformStatus);
  if (Launcher != NULL) {
    (void)PbnsBootConfigRecordFailure(Launcher->SystemTable->RuntimeServices,
                                      Stage, (EFI_STATUS)PlatformStatus);
  }
}

static VOID LauncherUnload(IN VOID *Context, IN pbns_launcher_target Target,
                           IN VOID *Image) {
  struct launcher_context *Launcher = Context;

  if ((Launcher != NULL) && (Image != NULL)) {
    (void)Launcher->SystemTable->BootServices->UnloadImage((EFI_HANDLE)Image);
  }
  if (Target == PBNS_LAUNCHER_TARGET_NORMAL) {
    ReleaseNormalOption(Launcher);
  }
}

static CONST pbns_launcher_ops mLauncherOps = {
    .read_config = LauncherReadConfig,
    .load = LauncherLoad,
    .start = LauncherStart,
    .record_failure = LauncherRecordFailure,
    .unload = LauncherUnload,
};

EFI_STATUS
EFIAPI
UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
  struct launcher_context Launcher = {
      .ImageHandle = ImageHandle,
      .SystemTable = SystemTable,
  };
  pbns_launcher_result Result = {0};
  pbns_status Status;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) ||
      (SystemTable->RuntimeServices == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Print(L"\r\n=================================================\r\n");
  Print(L"PBNS LAUNCHER (Automated Secure Boot Orchestrator)\r\n");
  Print(L"=================================================\r\n");

  Status =
      pbns_launcher_run(&mLauncherOps, &Launcher, (UINT64)EFI_ABORTED, &Result);
  ReleaseNormalOption(&Launcher);
  Print(L"PBNS LAUNCHER: result outcome=%u stage=%u status=%d (platform_status=0x%lx)\r\n",
        (UINT32)Result.outcome, (UINT32)Result.stage, Status, Result.original_platform_status);
  if ((Status == PBNS_OK) || (Result.original_platform_status == 0U)) {
    return EFI_ABORTED;
  }
  return (EFI_STATUS)Result.original_platform_status;
}
