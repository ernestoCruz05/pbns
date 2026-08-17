#ifndef PBNS_TEST_TCG2_H
#define PBNS_TEST_TCG2_H
#include <Uefi.h>
extern EFI_GUID gEfiTcg2ProtocolGuid;
extern EFI_GUID gEfiTcg2FinalEventsTableGuid;
typedef struct {
  UINT8 Size; UINT8 StructureVersion[2]; UINT8 ProtocolVersion[2];
  UINT32 HashAlgorithmBitmap; UINT32 SupportedEventLogs;
  BOOLEAN TPMPresentFlag; UINT16 MaxCommandSize; UINT16 MaxResponseSize;
  UINT32 ManufacturerID; UINT32 NumberOfPCRBanks; UINT32 ActivePcrBanks;
} EFI_TCG2_BOOT_SERVICE_CAPABILITY;
typedef struct EFI_TCG2_PROTOCOL EFI_TCG2_PROTOCOL;
typedef EFI_STATUS(EFIAPI *EFI_TCG2_GET_CAPABILITY)(EFI_TCG2_PROTOCOL *This,
  EFI_TCG2_BOOT_SERVICE_CAPABILITY *Capability);
struct EFI_TCG2_PROTOCOL { EFI_TCG2_GET_CAPABILITY GetCapability; };
#endif
