#include <Uefi.h>

#include <Library/BaseMemoryLib.h>

#include <Protocol/LoadedImage.h>

static EFI_STATUS FixtureSelectedStatus(IN EFI_HANDLE ImageHandle,
                                        IN EFI_SYSTEM_TABLE *SystemTable) {
  static const CHAR16 LoadErrorOption[] = L"load-error";
  static const CHAR16 DeviceErrorOption[] = L"device-error";
  static const CHAR16 AbortedOption[] = L"aborted";
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
  EFI_STATUS Status;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL)) {
    return EFI_ABORTED;
  }
  Status = SystemTable->BootServices->HandleProtocol(
      ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
  if (EFI_ERROR(Status) || (LoadedImage == NULL) ||
      (LoadedImage->LoadOptions == NULL)) {
    return EFI_ABORTED;
  }
  if ((LoadedImage->LoadOptionsSize == sizeof(LoadErrorOption)) &&
      (CompareMem(LoadedImage->LoadOptions, LoadErrorOption,
                  sizeof(LoadErrorOption)) == 0)) {
    return EFI_LOAD_ERROR;
  }
  if ((LoadedImage->LoadOptionsSize == sizeof(DeviceErrorOption)) &&
      (CompareMem(LoadedImage->LoadOptions, DeviceErrorOption,
                  sizeof(DeviceErrorOption)) == 0)) {
    return EFI_DEVICE_ERROR;
  }
  if ((LoadedImage->LoadOptionsSize == sizeof(AbortedOption)) &&
      (CompareMem(LoadedImage->LoadOptions, AbortedOption,
                  sizeof(AbortedOption)) == 0)) {
    return EFI_ABORTED;
  }
  return EFI_ABORTED;
}

EFI_STATUS
EFIAPI
UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
  return FixtureSelectedStatus(ImageHandle, SystemTable);
}
