#include "PbnsTpmIdentityUefi.h"

#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "PbnsTpmStorage.h"

_Static_assert(PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES ==
                   (EFI_VARIABLE_NON_VOLATILE |
                    EFI_VARIABLE_BOOTSERVICE_ACCESS),
               "TPM variable attributes must remain boot-service-only");

static CHAR16 mVariableName[] = L"PbnsTpmIdentity";

EFI_STATUS PbnsTpmStorageUefiRead(UINT8 *Buffer, UINTN Capacity,
                                  UINTN *Length) {
  if (Buffer == NULL || Length == NULL || Capacity == 0U) {
    return EFI_INVALID_PARAMETER;
  }
  *Length = 0U;
  UINT32 attributes = 0U;
  UINTN size = Capacity;
  EFI_STATUS status = gRT->GetVariable(
      mVariableName, &gPbnsTpmIdentityVariableGuid, &attributes, &size, Buffer);
  if (EFI_ERROR(status)) {
    ZeroMem(Buffer, Capacity);
    return status;
  }
  if (attributes != PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES || size == 0U ||
      size > Capacity) {
    ZeroMem(Buffer, Capacity);
    return EFI_COMPROMISED_DATA;
  }
  *Length = size;
  return EFI_SUCCESS;
}

EFI_STATUS PbnsTpmStorageUefiWrite(UINT8 *Buffer, UINTN Length) {
  if (Buffer == NULL || Length == 0U || Length > PBNS_TPM_STORAGE_MAX_SIZE) {
    return EFI_INVALID_PARAMETER;
  }
  EFI_STATUS status =
      gRT->SetVariable(mVariableName, &gPbnsTpmIdentityVariableGuid,
                       PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES, Length, Buffer);
  if (EFI_ERROR(status)) {
    return status;
  }
  UINT8 readback[PBNS_TPM_STORAGE_MAX_SIZE] = {0};
  UINTN readback_size = 0U;
  status = PbnsTpmStorageUefiRead(readback, sizeof(readback), &readback_size);
  if (EFI_ERROR(status) || readback_size != Length ||
      CompareMem(readback, Buffer, Length) != 0) {
    ZeroMem(readback, sizeof(readback));
    return EFI_DEVICE_ERROR;
  }
  ZeroMem(readback, sizeof(readback));
  return EFI_SUCCESS;
}

EFI_STATUS PbnsTpmStorageUefiDelete(void) {
  return gRT->SetVariable(mVariableName, &gPbnsTpmIdentityVariableGuid, 0U, 0U,
                          NULL);
}
