#include "PbnsRecoveryRollbackUefi.h"

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>

#include "PbnsAntiRollbackLib.h"
#include "PbnsTpmSubmitUefi.h"
#include "PbnsTss2Tcti.h"
#include "../../../src/core/recovery_service_adapter.h"

#define PBNS_TPM_COMMAND_MAX 4096U
#define PBNS_TPM_RESPONSE_MAX 4096U
#define PBNS_TPM_SYS_STORAGE_MAX 16384U

_Static_assert(PBNS_TPM_COMMAND_MAX == PBNS_TPM_RESPONSE_MAX,
               "TPM command and response bounds must match");

typedef union PBNS_TPM_ALIGNED_SYS_CONTEXT {
  uint64_t Alignment;
  uint8_t Bytes[PBNS_TPM_SYS_STORAGE_MAX];
} PBNS_TPM_ALIGNED_SYS_CONTEXT;

_Static_assert(sizeof(PBNS_TPM_ALIGNED_SYS_CONTEXT) == PBNS_TPM_SYS_STORAGE_MAX,
               "SYS storage capacity changed");

struct PBNS_RECOVERY_ROLLBACK {
  pbns_recovery_service_rollback assurance;
  pbns_anti_rollback controller;
  PBNS_ANTI_ROLLBACK_TPM_CONTEXT tpm_controller;
  TSS2_SYS_CONTEXT *sys;
  PBNS_TPM_ALIGNED_SYS_CONTEXT sys_storage;
  pbns_tss2_tcti tcti;
  uint8_t submit_storage[PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE];
  uint8_t canonical_scratch[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE];
};

static const uint8_t POLICY_KEY_X[32] = {
    0x1eU, 0xb5U, 0xdcU, 0x01U, 0xeeU, 0xd6U, 0x85U, 0x63U,
    0xe2U, 0x64U, 0x3fU, 0x98U, 0xdaU, 0x59U, 0xb4U, 0xdbU,
    0x72U, 0x0fU, 0x66U, 0x54U, 0x7aU, 0xefU, 0xcbU, 0x3bU,
    0xebU, 0x69U, 0x96U, 0x71U, 0x51U, 0x31U, 0xcbU, 0x58U,
};
static const uint8_t POLICY_KEY_Y[32] = {
    0x97U, 0x9dU, 0x6bU, 0xdbU, 0x23U, 0xceU, 0xb0U, 0x65U,
    0x9cU, 0xcfU, 0xc8U, 0xf1U, 0xd5U, 0xf1U, 0x98U, 0x9bU,
    0xc3U, 0x0cU, 0x1dU, 0xcfU, 0x8fU, 0x13U, 0xe3U, 0xa5U,
    0x56U, 0xc2U, 0x74U, 0x06U, 0xe2U, 0xa6U, 0x73U, 0x35U,
};

static void build_policy_key(TPM2B_PUBLIC *key) {
  *key = (TPM2B_PUBLIC){
      .publicArea = {
          .type = TPM2_ALG_ECC,
          .nameAlg = TPM2_ALG_SHA256,
          .objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT,
          .parameters = {.eccDetail = {
                             .symmetric = {.algorithm = TPM2_ALG_NULL},
                             .scheme = {.scheme = TPM2_ALG_ECDSA,
                                        .details.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
                             .curveID = TPM2_ECC_NIST_P256,
                             .kdf = {.scheme = TPM2_ALG_NULL},
                         }},
          .unique = {.ecc = {.x = {.size = sizeof(POLICY_KEY_X)},
                             .y = {.size = sizeof(POLICY_KEY_Y)}}},
      },
  };
  CopyMem(key->publicArea.unique.ecc.x.buffer, POLICY_KEY_X,
          sizeof(POLICY_KEY_X));
  CopyMem(key->publicArea.unique.ecc.y.buffer, POLICY_KEY_Y,
          sizeof(POLICY_KEY_Y));
  uint8_t encoded[512] = {0};
  size_t size = 0U;
  if (Tss2_MU_TPMT_PUBLIC_Marshal(&key->publicArea, encoded, sizeof(encoded),
                                  &size) == TSS2_RC_SUCCESS &&
      size <= UINT16_MAX) {
    key->size = (UINT16)size;
  }
  ZeroMem(encoded, sizeof(encoded));
}

static void tpm_final(PBNS_RECOVERY_ROLLBACK *rollback) {
  if (rollback->sys != NULL) {
    Tss2_Sys_Finalize(rollback->sys);
    rollback->sys = NULL;
  }
  if (rollback->tcti.common.v1.finalize != NULL) {
    rollback->tcti.common.v1.finalize((TSS2_TCTI_CONTEXT *)(void *)&rollback->tcti);
  }
  pbns_tpm_submit_uefi_final(rollback->submit_storage);
  ZeroMem(&rollback->sys_storage, sizeof(rollback->sys_storage));
  ZeroMem(&rollback->tpm_controller, sizeof(rollback->tpm_controller));
  ZeroMem(&rollback->controller, sizeof(rollback->controller));
}

static EFI_STATUS open_tpm(PBNS_RECOVERY_ROLLBACK *rollback) {
  const size_t required = Tss2_Sys_GetContextSize(PBNS_TPM_COMMAND_MAX);
  if (required == 0U || required > PBNS_TPM_SYS_STORAGE_MAX ||
      required > (size_t)MAX_UINTN) {
    return EFI_OUT_OF_RESOURCES;
  }
  pbns_tpm_submit submit = NULL;
  void *submit_context = NULL;
  if (pbns_tpm_submit_uefi_init(rollback->submit_storage, &submit,
                                &submit_context) != PBNS_OK ||
      pbns_tss2_tcti_initialize(&rollback->tcti, submit, submit_context) !=
          PBNS_OK) {
    tpm_final(rollback);
    return EFI_DEVICE_ERROR;
  }
  rollback->sys = (TSS2_SYS_CONTEXT *)(void *)rollback->sys_storage.Bytes;
  const TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;
  if (Tss2_Sys_Initialize(rollback->sys, required,
                          (TSS2_TCTI_CONTEXT *)(void *)&rollback->tcti,
                          &abi) != TSS2_RC_SUCCESS) {
    tpm_final(rollback);
    return EFI_DEVICE_ERROR;
  }
  TPM2B_PUBLIC policy_key = {0};
  build_policy_key(&policy_key);
  if (policy_key.size == 0U ||
      EFI_ERROR(PbnsAntiRollbackTpmController(
          &rollback->tpm_controller, rollback->sys,
          (pbns_buffer){rollback->canonical_scratch, 0U,
                        sizeof(rollback->canonical_scratch)},
          &policy_key, &rollback->controller))) {
    ZeroMem(&policy_key, sizeof(policy_key));
    tpm_final(rollback);
    return EFI_SECURITY_VIOLATION;
  }
  ZeroMem(&policy_key, sizeof(policy_key));
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI PbnsRecoveryRollbackOpen(
    pbns_recovery_assurance_mode mode, PBNS_RECOVERY_ROLLBACK **out_rollback) {
  if (out_rollback != NULL) {
    *out_rollback = NULL;
  }
  if (out_rollback == NULL ||
      (mode != PBNS_RECOVERY_ASSURANCE_T && mode != PBNS_RECOVERY_ASSURANCE_S)) {
    return EFI_INVALID_PARAMETER;
  }
  PBNS_RECOVERY_ROLLBACK *rollback = AllocateZeroPool(sizeof(*rollback));
  if (rollback == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  EFI_STATUS status = EFI_SUCCESS;
  if (mode == PBNS_RECOVERY_ASSURANCE_T) {
    status = open_tpm(rollback);
  } else if (PbnsAntiRollbackNvramController(&rollback->controller) != EFI_SUCCESS) {
    status = EFI_DEVICE_ERROR;
  }
  if (EFI_ERROR(status)) {
    PbnsRecoveryRollbackDestroy(rollback);
    return status;
  }
  rollback->assurance = (pbns_recovery_service_rollback){
      .mode = mode,
      .controller = &rollback->controller,
  };
  *out_rollback = rollback;
  return EFI_SUCCESS;
}

void EFIAPI PbnsRecoveryRollbackDestroy(PBNS_RECOVERY_ROLLBACK *rollback) {
  if (rollback == NULL) {
    return;
  }
  tpm_final(rollback);
  ZeroMem(&rollback->assurance, sizeof(rollback->assurance));
  ZeroMem(rollback, sizeof(*rollback));
  FreePool(rollback);
}

pbns_status PbnsRecoveryRollbackRead(PBNS_RECOVERY_ROLLBACK *rollback,
                                     uint64_t *version) {
  return rollback == NULL ? PBNS_ERR_ARGUMENT
                          : pbns_recovery_service_rollback_read(
                                &rollback->assurance, version);
}

pbns_status PbnsRecoveryRollbackAdvance(
    PBNS_RECOVERY_ROLLBACK *rollback,
    const pbns_recovery_service_manifest_state *manifest_state,
    uint64_t current, uint64_t target, pbns_view authorization) {
  return rollback == NULL
             ? PBNS_ERR_ARGUMENT
             : pbns_recovery_service_rollback_advance(
                   &rollback->assurance, manifest_state, current, target,
                   authorization);
}
