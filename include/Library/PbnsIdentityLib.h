#ifndef PBNS_IDENTITY_LIB_H
#define PBNS_IDENTITY_LIB_H

#include <Uefi.h>

#include "pbns/buffer.h"
#include "pbns/identity.h"
#include "pbns/status.h"

typedef EFI_STATUS(EFIAPI *PBNS_TPM_RANDOM_FILL)(void *Context, UINTN Size,
                                                 UINT8 *Output);

typedef struct {
  PBNS_TPM_RANDOM_FILL Fill;
  void *Context;
} PBNS_TPM_RANDOM_SOURCE;

pbns_status EFIAPI PbnsIdentityRandomFill(
    const PBNS_TPM_RANDOM_SOURCE *TpmSource, pbns_buffer Output);
EFI_STATUS EFIAPI PbnsSoftwareIdentityCreate(
    const PBNS_TPM_RANDOM_SOURCE *TpmSource, pbns_identity *Identity);
EFI_STATUS EFIAPI PbnsSoftwareIdentityOpen(
    const PBNS_TPM_RANDOM_SOURCE *TpmSource, pbns_identity *Identity);
EFI_STATUS EFIAPI PbnsSoftwareIdentityReset(void);

#endif
