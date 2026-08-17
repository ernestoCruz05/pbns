#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include <stdlib.h>
#include <string.h>

EFI_GUID gEfiGlobalVariableGuid = {.Data1 = 1U};
EFI_GUID gEfiImageSecurityDatabaseGuid = {.Data1 = 2U};
EFI_GUID gEfiSmbiosTableGuid = {.Data1 = 3U};
EFI_GUID gEfiSmbios3TableGuid = {.Data1 = 4U};
EFI_GUID gEfiPciIoProtocolGuid = {.Data1 = 5U};
EFI_GUID gEfiBlockIoProtocolGuid = {.Data1 = 6U};
EFI_GUID gEfiTcg2ProtocolGuid = {.Data1 = 7U};

VOID *SetMem(VOID *Buffer, UINTN Size, UINT8 Value) {
  return memset(Buffer, Value, Size);
}

VOID *ZeroMem(VOID *Buffer, UINTN Size) { return memset(Buffer, 0, Size); }

VOID *CopyMem(VOID *Destination, const VOID *Source, UINTN Size) {
  return memcpy(Destination, Source, Size);
}

INTN CompareMem(const VOID *First, const VOID *Second, UINTN Size) {
  return memcmp(First, Second, Size);
}

BOOLEAN CompareGuid(const EFI_GUID *First, const EFI_GUID *Second) {
  return memcmp(First, Second, sizeof(*First)) == 0 ? TRUE : FALSE;
}

VOID *AllocateZeroPool(UINTN Size) { return calloc(1U, Size); }

VOID FreePool(VOID *Buffer) { free(Buffer); }
