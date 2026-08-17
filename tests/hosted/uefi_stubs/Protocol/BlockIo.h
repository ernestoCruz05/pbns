#ifndef PBNS_TEST_BLOCK_IO_H
#define PBNS_TEST_BLOCK_IO_H
#include <Uefi.h>
extern EFI_GUID gEfiBlockIoProtocolGuid;
typedef struct EFI_BLOCK_IO_MEDIA {
  BOOLEAN RemovableMedia; BOOLEAN LogicalPartition; UINT32 BlockSize;
  UINT64 LastBlock;
} EFI_BLOCK_IO_MEDIA;
typedef struct EFI_BLOCK_IO_PROTOCOL { EFI_BLOCK_IO_MEDIA *Media; } EFI_BLOCK_IO_PROTOCOL;
#endif
