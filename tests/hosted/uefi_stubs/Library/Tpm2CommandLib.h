#ifndef PBNS_TEST_TPM2_COMMAND_LIB_H
#define PBNS_TEST_TPM2_COMMAND_LIB_H

#include <IndustryStandard/Tpm20.h>

EFI_STATUS Tpm2PcrRead(TPML_PCR_SELECTION *PcrSelectionIn,
                       UINT32 *PcrUpdateCounter,
                       TPML_PCR_SELECTION *PcrSelectionOut,
                       TPML_DIGEST *PcrValues);
EFI_STATUS Tpm2NvReadPublic(TPMI_RH_NV_INDEX NvIndex, TPM2B_NV_PUBLIC *NvPublic,
                            TPM2B_NAME *NvName);
EFI_STATUS Tpm2NvRead(TPMI_RH_NV_AUTH AuthHandle, TPMI_RH_NV_INDEX NvIndex,
                      TPMS_AUTH_COMMAND *AuthSession, UINT16 Size,
                      UINT16 Offset, TPM2B_MAX_BUFFER *OutData);

#endif
