#ifndef PBNS_TPM_EK_CERTIFICATE_INTERNAL_H
#define PBNS_TPM_EK_CERTIFICATE_INTERNAL_H

#include <Uefi.h>

#include <IndustryStandard/Tpm20.h>
#include <Library/PbnsTpmEkCertificateLib.h>

#include <stddef.h>

#include "pbns/status.h"

typedef EFI_STATUS(EFIAPI *PBNS_TPM_EK_NV_READ_PUBLIC)(
    void *Context, TPMI_RH_NV_INDEX NvIndex, TPM2B_NV_PUBLIC *NvPublic,
    TPM2B_NAME *NvName);
typedef EFI_STATUS(EFIAPI *PBNS_TPM_EK_NV_READ)(void *Context,
                                                TPMI_RH_NV_AUTH AuthHandle,
                                                TPMI_RH_NV_INDEX NvIndex,
                                                TPMS_AUTH_COMMAND *AuthSession,
                                                UINT16 Size, UINT16 Offset,
                                                TPM2B_MAX_BUFFER *OutData);

typedef struct PBNS_TPM_EK_CERTIFICATE_COMMANDS {
  void *Context;
  PBNS_TPM_EK_NV_READ_PUBLIC NvReadPublic;
  PBNS_TPM_EK_NV_READ NvRead;
} PBNS_TPM_EK_CERTIFICATE_COMMANDS;

pbns_status PbnsTpmEkCertificateReadWithCommands(
    const PBNS_TPM_EK_CERTIFICATE_COMMANDS *Commands, pbns_buffer Output,
    size_t *Written);

#endif
