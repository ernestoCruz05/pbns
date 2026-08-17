#ifndef PBNS_TEST_SMBIOS_STANDARD_H
#define PBNS_TEST_SMBIOS_STANDARD_H
#include <Uefi.h>
#pragma pack(push, 1)
typedef struct {
  UINT8 AnchorString[4]; UINT8 Checksum; UINT8 EntryPointLength;
  UINT8 MajorVersion; UINT8 MinorVersion; UINT16 MaxStructureSize;
  UINT8 EntryPointRevision; UINT8 FormattedArea[5];
  UINT8 IntermediateAnchorString[5]; UINT8 IntermediateChecksum;
  UINT16 TableLength; UINT32 TableAddress; UINT16 NumberOfSmbiosStructures;
  UINT8 SmbiosBcdRevision;
} SMBIOS_TABLE_ENTRY_POINT;
typedef struct {
  UINT8 AnchorString[5]; UINT8 Checksum; UINT8 EntryPointLength;
  UINT8 MajorVersion; UINT8 MinorVersion; UINT8 DocRev;
  UINT8 EntryPointRevision; UINT8 Reserved; UINT32 TableMaximumSize;
  UINT64 TableAddress;
} SMBIOS_TABLE_3_0_ENTRY_POINT;
#pragma pack(pop)
#endif
