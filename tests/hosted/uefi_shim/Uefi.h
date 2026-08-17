#ifndef PBNS_TEST_UEFI_H
#define PBNS_TEST_UEFI_H

#include <stddef.h>
#include <stdint.h>

#define EFIAPI

typedef intptr_t EFI_STATUS;
typedef size_t UINTN;
typedef uint32_t UINT32;
typedef uint8_t UINT8;
typedef void VOID;
typedef struct EFI_BOOT_SERVICES {
  uint32_t unused;
} EFI_BOOT_SERVICES;

#define EFI_SUCCESS ((EFI_STATUS)0)
#define EFI_INVALID_PARAMETER ((EFI_STATUS)2)
#define EFI_SECURITY_VIOLATION ((EFI_STATUS)26)
#define EFI_ERROR(Status) ((Status) != EFI_SUCCESS)

#endif
