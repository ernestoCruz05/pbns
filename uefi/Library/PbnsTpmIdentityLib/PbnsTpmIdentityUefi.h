#ifndef PBNS_TPM_IDENTITY_UEFI_H
#define PBNS_TPM_IDENTITY_UEFI_H

#include <Uefi.h>

EFI_STATUS PbnsTpmStorageUefiRead(UINT8 *Buffer, UINTN Capacity, UINTN *Length);
EFI_STATUS PbnsTpmStorageUefiWrite(UINT8 *Buffer, UINTN Length);
EFI_STATUS PbnsTpmStorageUefiDelete(void);

#endif
