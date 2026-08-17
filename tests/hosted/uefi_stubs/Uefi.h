#ifndef PBNS_TEST_UEFI_H
#define PBNS_TEST_UEFI_H

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#define EFIAPI
#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define FALSE 0U
#define TRUE 1U
#define MAX_UINTN SIZE_MAX

typedef void VOID;
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef size_t UINTN;
typedef ptrdiff_t INTN;
typedef wchar_t CHAR16;
typedef uint8_t BOOLEAN;
typedef uint64_t EFI_STATUS;
typedef VOID *EFI_HANDLE;

typedef struct EFI_GUID {
  UINT32 Data1;
  UINT16 Data2;
  UINT16 Data3;
  UINT8 Data4[8];
} EFI_GUID;

#define EFI_STATUS_ERROR_BIT (UINT64_C(1) << 63U)
#define EFI_SUCCESS UINT64_C(0)
#define EFI_INVALID_PARAMETER (EFI_STATUS_ERROR_BIT | UINT64_C(2))
#define EFI_UNSUPPORTED (EFI_STATUS_ERROR_BIT | UINT64_C(3))
#define EFI_BAD_BUFFER_SIZE (EFI_STATUS_ERROR_BIT | UINT64_C(4))
#define EFI_BUFFER_TOO_SMALL (EFI_STATUS_ERROR_BIT | UINT64_C(5))
#define EFI_DEVICE_ERROR (EFI_STATUS_ERROR_BIT | UINT64_C(7))
#define EFI_OUT_OF_RESOURCES (EFI_STATUS_ERROR_BIT | UINT64_C(9))
#define EFI_NOT_FOUND (EFI_STATUS_ERROR_BIT | UINT64_C(14))
#define EFI_SECURITY_VIOLATION (EFI_STATUS_ERROR_BIT | UINT64_C(26))
#define EFI_COMPROMISED_DATA (EFI_STATUS_ERROR_BIT | UINT64_C(33))
#define EFI_ERROR(status) (((status) & EFI_STATUS_ERROR_BIT) != 0U)

typedef EFI_STATUS(EFIAPI *EFI_GET_VARIABLE)(CHAR16 *Name, EFI_GUID *Guid,
                                              UINT32 *Attributes, UINTN *Size,
                                              VOID *Data);

typedef struct EFI_RUNTIME_SERVICES {
  EFI_GET_VARIABLE GetVariable;
} EFI_RUNTIME_SERVICES;

typedef enum EFI_LOCATE_SEARCH_TYPE { ByProtocol = 2 } EFI_LOCATE_SEARCH_TYPE;

typedef EFI_STATUS(EFIAPI *EFI_LOCATE_PROTOCOL)(EFI_GUID *Protocol,
                                                 VOID *Registration,
                                                 VOID **Interface);
typedef EFI_STATUS(EFIAPI *EFI_LOCATE_HANDLE_BUFFER)(
    EFI_LOCATE_SEARCH_TYPE SearchType, EFI_GUID *Protocol, VOID *SearchKey,
    UINTN *Count, EFI_HANDLE **Handles);
typedef EFI_STATUS(EFIAPI *EFI_HANDLE_PROTOCOL)(EFI_HANDLE Handle,
                                                 EFI_GUID *Protocol,
                                                 VOID **Interface);
typedef EFI_STATUS(EFIAPI *EFI_FREE_POOL)(VOID *Buffer);

typedef struct EFI_BOOT_SERVICES {
  EFI_LOCATE_PROTOCOL LocateProtocol;
  EFI_LOCATE_HANDLE_BUFFER LocateHandleBuffer;
  EFI_HANDLE_PROTOCOL HandleProtocol;
  EFI_FREE_POOL FreePool;
} EFI_BOOT_SERVICES;

typedef struct EFI_CONFIGURATION_TABLE {
  EFI_GUID VendorGuid;
  VOID *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct EFI_SYSTEM_TABLE {
  EFI_RUNTIME_SERVICES *RuntimeServices;
  EFI_BOOT_SERVICES *BootServices;
  UINTN NumberOfTableEntries;
  EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;

#endif
