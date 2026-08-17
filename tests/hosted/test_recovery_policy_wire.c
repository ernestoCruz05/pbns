#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "PbnsRecoveryPolicyWire.h"
#include "pbns/tpm_profile.h"

static size_t read_vector(const char *name, uint8_t *output, size_t capacity) {
  char path[256] = {0};
  const int length =
      snprintf(path, sizeof(path), "tests/vectors/recovery-policy-v1/%s", name);
  assert(length > 0);
  assert((size_t)length < sizeof(path));
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  const size_t received = fread(output, 1U, capacity, file);
  assert(ferror(file) == 0);
  assert(received > 0U);
  assert(received < capacity);
  assert(fclose(file) == 0);
  return received;
}

static void
assert_profile(const pbns_recovery_policy_authorization *authorization,
               pbns_recovery_policy_kind kind, uint64_t target) {
  static const uint8_t expected_ref[] = "PBNS-RECOVERY-POLICY-REF-v1";
  assert(authorization->kind == kind);
  assert(authorization->nv_index == PBNS_TPM_RECOVERY_NV_INDEX);
  assert(authorization->nv_public.nvPublic.nvIndex ==
         PBNS_TPM_RECOVERY_NV_INDEX);
  assert(authorization->nv_public.nvPublic.nameAlg == TPM2_ALG_SHA256);
  const TPMA_NV expected_attributes =
      TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA |
      (kind == PBNS_RECOVERY_POLICY_KIND_UPDATE ? TPMA_NV_WRITTEN : 0U);
  assert(authorization->nv_public.nvPublic.attributes == expected_attributes);
  assert(authorization->nv_public.nvPublic.dataSize == 8U);
  assert(authorization->nv_public.nvPublic.authPolicy.size == 32U);
  assert(authorization->nv_name.size == 34U);
  assert(authorization->target_version == target);
  uint8_t target_bytes[8] = {0};
  for (size_t index = 0U; index < sizeof(target_bytes); ++index) {
    target_bytes[7U - index] = (uint8_t)(target >> (index * 8U));
  }
  assert(memcmp(authorization->operand, target_bytes, sizeof(target_bytes)) ==
         0);
  assert(authorization->offset == 0U);
  assert(authorization->operation == (kind == PBNS_RECOVERY_POLICY_KIND_UPDATE
                                          ? (uint16_t)TPM2_EO_UNSIGNED_LT
                                          : 0U));
  assert(authorization->policy_ref_size == sizeof(expected_ref) - 1U);
  assert(memcmp(authorization->policy_ref, expected_ref,
                sizeof(expected_ref) - 1U) == 0);
  assert(authorization->policy_key_public.publicArea.type == TPM2_ALG_ECC);
  assert(authorization->policy_key_public.publicArea.nameAlg ==
         TPM2_ALG_SHA256);
  assert(authorization->policy_key_public.publicArea.parameters.eccDetail
             .curveID == TPM2_ECC_NIST_P256);
  assert(authorization->policy_key_name.size == 34U);
  assert(authorization->signature.sigAlg == TPM2_ALG_ECDSA);
  assert(authorization->signature.signature.ecdsa.hash == TPM2_ALG_SHA256);
}

static void test_vector(const char *name, pbns_recovery_policy_kind kind,
                        uint64_t target) {
  uint8_t encoded[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE] = {0};
  uint8_t scratch[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE] = {0};
  uint8_t canonical[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE] = {0};
  const size_t encoded_size = read_vector(name, encoded, sizeof(encoded));
  pbns_recovery_policy_authorization authorization = {0};
  assert(
      pbns_recovery_policy_decode((pbns_view){encoded, encoded_size},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &authorization) == PBNS_OK);
  assert_profile(&authorization, kind, target);
  size_t canonical_size = 0U;
  assert(pbns_recovery_policy_encode(
             &authorization, (pbns_buffer){canonical, 0U, sizeof(canonical)},
             &canonical_size) == PBNS_OK);
  assert(canonical_size == encoded_size);
  assert(memcmp(canonical, encoded, encoded_size) == 0);
}

static void test_rejects_truncated_mutated_and_overlapping_inputs(void) {
  uint8_t encoded[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE] = {0};
  uint8_t scratch[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE] = {0};
  const size_t encoded_size =
      read_vector("advance-4-to-5.cbor", encoded, sizeof(encoded));
  pbns_recovery_policy_authorization authorization = {0};
  assert(
      pbns_recovery_policy_decode((pbns_view){encoded, encoded_size - 1U},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &authorization) == PBNS_ERR_FORMAT);
  encoded[encoded_size - 1U] ^= 1U;
  assert(
      pbns_recovery_policy_decode((pbns_view){encoded, encoded_size},
                                  (pbns_buffer){scratch, 0U, sizeof(scratch)},
                                  &authorization) != PBNS_OK);
  assert(
      pbns_recovery_policy_decode((pbns_view){encoded, encoded_size},
                                  (pbns_buffer){encoded, 0U, sizeof(encoded)},
                                  &authorization) == PBNS_ERR_ARGUMENT);
}

static void test_invalid_arguments(void) {
  uint8_t output[PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE] = {0};
  size_t written = SIZE_MAX;
  assert(pbns_recovery_policy_encode(NULL,
                                     (pbns_buffer){output, 0U, sizeof(output)},
                                     &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  pbns_recovery_policy_authorization authorization = {0};
  assert(pbns_recovery_policy_decode((pbns_view){NULL, 0U},
                                     (pbns_buffer){output, 0U, sizeof(output)},
                                     &authorization) == PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_vector("initialize-4.cbor", PBNS_RECOVERY_POLICY_KIND_INITIALIZE, 4U);
  test_vector("advance-4-to-5.cbor", PBNS_RECOVERY_POLICY_KIND_UPDATE, 5U);
  test_rejects_truncated_mutated_and_overlapping_inputs();
  test_invalid_arguments();
  return 0;
}
