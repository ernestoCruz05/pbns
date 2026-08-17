#ifndef PBNS_TEST_MEMORY_ALLOCATION_LIB_H
#define PBNS_TEST_MEMORY_ALLOCATION_LIB_H
#include <Uefi.h>
VOID *AllocateZeroPool(UINTN Size);
VOID FreePool(VOID *Buffer);
#endif
