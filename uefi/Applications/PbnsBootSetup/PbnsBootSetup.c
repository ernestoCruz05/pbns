#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootManagerLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>

#include "PbnsBootConfigLib.h"

static BOOLEAN DevicePathsEqual(IN CONST EFI_DEVICE_PATH_PROTOCOL *Left,
                                IN CONST EFI_DEVICE_PATH_PROTOCOL *Right) {
  UINTN LeftSize;
  UINTN RightSize;

  if ((Left == NULL) || (Right == NULL) ||
      !IsDevicePathValid(Left, PBNS_BOOT_CONFIG_PATH_CAP) ||
      !IsDevicePathValid(Right, PBNS_BOOT_CONFIG_PATH_CAP)) {
    return FALSE;
  }
  LeftSize = GetDevicePathSize(Left);
  RightSize = GetDevicePathSize(Right);
  return (LeftSize == RightSize) && (CompareMem(Left, Right, LeftSize) == 0);
}

static BOOLEAN
OptionForbidden(IN CONST EFI_BOOT_MANAGER_LOAD_OPTION *Option,
                IN CONST EFI_DEVICE_PATH_PROTOCOL *CurrentPath,
                IN CONST EFI_DEVICE_PATH_PROTOCOL *RecoveryPath) {
  if ((Option == NULL) || (Option->Description == NULL) ||
      (Option->FilePath == NULL)) {
    return TRUE;
  }
  if ((StrCmp(Option->Description, L"PBNS Launcher") == 0) ||
      (StrCmp(Option->Description, L"PBNS Recovery") == 0)) {
    return TRUE;
  }
  if (DevicePathsEqual(Option->FilePath, CurrentPath) ||
      DevicePathsEqual(Option->FilePath, RecoveryPath)) {
    return TRUE;
  }
  return FALSE;
}

static EFI_STATUS ReadOptionIndex(
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN CONST EFI_BOOT_MANAGER_LOAD_OPTION *Options, IN UINTN OptionCount,
    IN CONST EFI_DEVICE_PATH_PROTOCOL *CurrentPath,
    IN CONST EFI_DEVICE_PATH_PROTOCOL *RecoveryPath, OUT UINTN *SelectedIndex) {
  EFI_INPUT_KEY Key;
  UINTN Value = 0U;
  UINTN Digits = 0U;
  UINTN EventIndex;
  UINTN Index;
  EFI_STATUS Status;

  if ((SystemTable == NULL) || (SystemTable->ConIn == NULL) ||
      (Options == NULL) || (OptionCount == 0U) || (SelectedIndex == NULL)) {
    return EFI_INVALID_PARAMETER;
  }
  Print(L"Select the existing normal boot option:\n");
  for (Index = 0U; Index < OptionCount; ++Index) {
    if (!OptionForbidden(&Options[Index], CurrentPath, RecoveryPath)) {
      Print(L"  [%u] Boot%04x %s\n", (UINT32)Index,
            (UINT32)Options[Index].OptionNumber, Options[Index].Description);
    }
  }
  Print(L"> ");
  for (;;) {
    Status = SystemTable->BootServices->WaitForEvent(
        1U, &SystemTable->ConIn->WaitForKey, &EventIndex);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    Status = SystemTable->ConIn->ReadKeyStroke(SystemTable->ConIn, &Key);
    if (Status == EFI_NOT_READY) {
      continue;
    }
    if (EFI_ERROR(Status)) {
      return Status;
    }
    if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      if ((Digits == 0U) || (Value >= OptionCount) ||
          OptionForbidden(&Options[Value], CurrentPath, RecoveryPath)) {
        return EFI_INVALID_PARAMETER;
      }
      *SelectedIndex = Value;
      Print(L"\n");
      return EFI_SUCCESS;
    }
    if (Key.UnicodeChar == CHAR_BACKSPACE) {
      if (Digits > 0U) {
        Value /= 10U;
        Digits -= 1U;
        Print(L"\b \b");
      }
      continue;
    }
    if ((Key.UnicodeChar < L'0') || (Key.UnicodeChar > L'9')) {
      continue;
    }
    if ((Digits >= 5U) ||
        (Value > ((MAX_UINTN - (UINTN)(Key.UnicodeChar - L'0')) / 10U))) {
      return EFI_BAD_BUFFER_SIZE;
    }
    Value = (Value * 10U) + (UINTN)(Key.UnicodeChar - L'0');
    Digits += 1U;
    Print(L"%c", Key.UnicodeChar);
  }
}

EFI_STATUS
EFIAPI
UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable) {
  static CHAR16 RecoveryDescription[] = L"PBNS Recovery";
  EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
  EFI_BOOT_MANAGER_LOAD_OPTION *BootOptions = NULL;
  EFI_BOOT_MANAGER_LOAD_OPTION RecoveryOption = {0};
  EFI_DEVICE_PATH_PROTOCOL *RecoveryPath = NULL;
  UINTN BootOptionCount = 0U;
  UINTN SelectedIndex = 0U;
  BOOLEAN RecoveryAdded = FALSE;
  EFI_STATUS Status;

  if ((SystemTable == NULL) || (SystemTable->BootServices == NULL) ||
      (SystemTable->RuntimeServices == NULL)) {
    return EFI_INVALID_PARAMETER;
  }
  Status = SystemTable->BootServices->HandleProtocol(
      ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
  if (EFI_ERROR(Status) || (LoadedImage == NULL)) {
    return EFI_ERROR(Status) ? Status : EFI_COMPROMISED_DATA;
  }
  RecoveryPath = FileDevicePath(LoadedImage->DeviceHandle,
                                L"\\EFI\\PBNS\\PBNSRecovery.efi");
  if (RecoveryPath == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  BootOptions =
      EfiBootManagerGetLoadOptions(&BootOptionCount, LoadOptionTypeBoot);
  if ((BootOptions == NULL) || (BootOptionCount == 0U)) {
    Status = EFI_NOT_FOUND;
    goto Cleanup;
  }
  Status = ReadOptionIndex(SystemTable, BootOptions, BootOptionCount,
                           LoadedImage->FilePath, RecoveryPath, &SelectedIndex);
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }
  if (BootOptions[SelectedIndex].OptionNumber > MAX_UINT16) {
    Status = EFI_COMPROMISED_DATA;
    goto Cleanup;
  }
  Status = EfiBootManagerInitializeLoadOption(
      &RecoveryOption, LoadOptionNumberUnassigned, LoadOptionTypeBoot,
      LOAD_OPTION_ACTIVE, RecoveryDescription, RecoveryPath, NULL, 0U);
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }
  Status = EfiBootManagerAddLoadOptionVariable(&RecoveryOption, MAX_UINTN);
  if (EFI_ERROR(Status)) {
    goto Cleanup;
  }
  RecoveryAdded = TRUE;
  Status = PbnsBootConfigWrite(SystemTable->RuntimeServices,
                               (UINT16)BootOptions[SelectedIndex].OptionNumber,
                               RecoveryPath);
  if (EFI_ERROR(Status)) {
    (void)EfiBootManagerDeleteLoadOptionVariable(RecoveryOption.OptionNumber,
                                                 LoadOptionTypeBoot);
    RecoveryAdded = FALSE;
    goto Cleanup;
  }
  Print(L"PBNS BOOT SETUP PASS normal=Boot%04x recovery=Boot%04x\n",
        (UINT32)BootOptions[SelectedIndex].OptionNumber,
        (UINT32)RecoveryOption.OptionNumber);

Cleanup:
  if (RecoveryOption.Description != NULL) {
    (void)EfiBootManagerFreeLoadOption(&RecoveryOption);
  } else if (RecoveryAdded) {
    (void)EfiBootManagerDeleteLoadOptionVariable(RecoveryOption.OptionNumber,
                                                 LoadOptionTypeBoot);
  }
  if (BootOptions != NULL) {
    (void)EfiBootManagerFreeLoadOptions(BootOptions, BootOptionCount);
  }
  if (RecoveryPath != NULL) {
    FreePool(RecoveryPath);
  }
  return Status;
}
