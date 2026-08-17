#ifndef PBNS_UEFI_PLATFORM_LIB_H
#define PBNS_UEFI_PLATFORM_LIB_H

#include <Uefi.h>

#include <pbns/frame.h>

VOID *
EFIAPI
PbnsUefiAllocatePool (
  IN UINTN  Size
  );

VOID
EFIAPI
PbnsUefiFreePool (
  IN VOID  *Allocation
  );

EFI_STATUS
EFIAPI
PbnsUefiRandomRequestId (
  OUT pbns_request_id  *RequestId
  );

EFI_STATUS
EFIAPI
PbnsUefiMonotonicMs (
  IN EFI_BOOT_SERVICES  *BootServices,
  OUT UINT64            *Milliseconds
  );

#endif
