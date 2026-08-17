#ifndef PBNS_ANTI_ROLLBACK_LIB_H
#define PBNS_ANTI_ROLLBACK_LIB_H

#include <Uefi.h>

#include <tss2/tss2_sys.h>

#include "PbnsRecoveryPolicyWire.h"
#include "pbns/anti_rollback.h"

typedef struct PBNS_ANTI_ROLLBACK_TPM_CONTEXT {
  TSS2_SYS_CONTEXT *Sys;
  pbns_buffer CanonicalScratch;
  TPM2B_PUBLIC ExpectedPolicyKey;
  TPM2B_NAME ExpectedPolicyKeyName;
  uint8_t ExpectedFinalPolicy[PBNS_RECOVERY_POLICY_DIGEST_SIZE];
} PBNS_ANTI_ROLLBACK_TPM_CONTEXT;

EFI_STATUS EFIAPI
PbnsAntiRollbackNvramController(pbns_anti_rollback *Controller);

EFI_STATUS EFIAPI PbnsAntiRollbackTpmController(
    PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context, TSS2_SYS_CONTEXT *Sys,
    pbns_buffer CanonicalScratch, const TPM2B_PUBLIC *ExpectedPolicyKey,
    pbns_anti_rollback *Controller);

EFI_STATUS EFIAPI PbnsAntiRollbackTpmInitialize(
    PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context, pbns_view Authorization,
    pbns_anti_rollback_state *State);

#endif
