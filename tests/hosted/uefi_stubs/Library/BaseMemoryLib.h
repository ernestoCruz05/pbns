#ifndef PBNS_TEST_BASE_MEMORY_LIB_H
#define PBNS_TEST_BASE_MEMORY_LIB_H
#include <Uefi.h>
VOID *SetMem(VOID *Buffer, UINTN Size, UINT8 Value);
VOID *ZeroMem(VOID *Buffer, UINTN Size);
VOID *CopyMem(VOID *Destination, const VOID *Source, UINTN Size);
INTN CompareMem(const VOID *First, const VOID *Second, UINTN Size);
BOOLEAN CompareGuid(const EFI_GUID *First, const EFI_GUID *Second);
#endif
