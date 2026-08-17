#ifndef PBNS_RECOVERY_POLICY_WIRE_H
#define PBNS_RECOVERY_POLICY_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE 4096U
#define PBNS_RECOVERY_POLICY_DIGEST_SIZE 32U
#define PBNS_RECOVERY_POLICY_OPERAND_SIZE 8U
#define PBNS_RECOVERY_POLICY_REF_MAX_SIZE 64U

typedef enum pbns_recovery_policy_kind {
  PBNS_RECOVERY_POLICY_KIND_INVALID = 0,
  PBNS_RECOVERY_POLICY_KIND_INITIALIZE = 1,
  PBNS_RECOVERY_POLICY_KIND_UPDATE = 2
} pbns_recovery_policy_kind;

typedef struct pbns_recovery_policy_authorization {
  pbns_recovery_policy_kind kind;
  uint32_t nv_index;
  TPM2B_NV_PUBLIC nv_public;
  TPM2B_NAME nv_name;
  uint64_t target_version;
  uint8_t operand[PBNS_RECOVERY_POLICY_OPERAND_SIZE];
  uint16_t offset;
  uint16_t operation;
  uint8_t cp_hash[PBNS_RECOVERY_POLICY_DIGEST_SIZE];
  uint8_t approved_policy[PBNS_RECOVERY_POLICY_DIGEST_SIZE];
  uint8_t policy_ref[PBNS_RECOVERY_POLICY_REF_MAX_SIZE];
  size_t policy_ref_size;
  TPM2B_PUBLIC policy_key_public;
  TPM2B_NAME policy_key_name;
  TPMT_SIGNATURE signature;
  uint8_t final_policy[PBNS_RECOVERY_POLICY_DIGEST_SIZE];
} pbns_recovery_policy_authorization;

pbns_status pbns_recovery_policy_encode(
    const pbns_recovery_policy_authorization *authorization, pbns_buffer output,
    size_t *written);

pbns_status
pbns_recovery_policy_decode(pbns_view encoded, pbns_buffer canonical_scratch,
                            pbns_recovery_policy_authorization *authorization);

#endif
