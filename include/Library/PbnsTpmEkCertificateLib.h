#ifndef PBNS_TPM_EK_CERTIFICATE_LIB_H
#define PBNS_TPM_EK_CERTIFICATE_LIB_H

#include <Uefi.h>

#include "pbns/buffer.h"

#define PBNS_TPM_EK_CERTIFICATE_NV_INDEX 0x01c0000aU
#define PBNS_TPM_EK_CERTIFICATE_MAX_SIZE 16384U

EFI_STATUS EFIAPI PbnsTpmEkCertificateRead(pbns_buffer Output, UINTN *Written);

#endif
