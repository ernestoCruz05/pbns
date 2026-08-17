#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <tss2/tss2_mu.h>

#include "pbns/tpm_profile.h"

static pbns_status openssl_sha256(void *context, pbns_view input,
                                  pbns_buffer digest) {
  (void)context;
  unsigned int written = 0U;
  if (digest.ptr == NULL || digest.len != 0U || digest.cap < 32U) {
    return PBNS_ERR_ARGUMENT;
  }
  return EVP_Digest(input.ptr, input.len, digest.ptr, &written, EVP_sha256(),
                    NULL) == 1 &&
                 written == 32U
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static size_t marshal_public(const TPM2B_PUBLIC *public_area,
                             uint8_t output[512]) {
  size_t offset = 0U;
  assert(Tss2_MU_TPM2B_PUBLIC_Marshal(public_area, output, 512U, &offset) ==
         TSS2_RC_SUCCESS);
  return offset;
}

static void assert_ecc_profile(const TPM2B_PUBLIC *value,
                               TPMA_OBJECT expected_attributes,
                               bool restricted) {
  assert(value->size > 0U);
  assert(value->publicArea.type == TPM2_ALG_ECC);
  assert(value->publicArea.nameAlg == TPM2_ALG_SHA256);
  assert(value->publicArea.objectAttributes == expected_attributes);
  assert(value->publicArea.authPolicy.size == 0U);
  const TPMS_ECC_PARMS *ecc = &value->publicArea.parameters.eccDetail;
  assert(ecc->symmetric.algorithm == TPM2_ALG_NULL);
  assert(ecc->scheme.scheme == TPM2_ALG_ECDSA);
  assert(ecc->scheme.details.ecdsa.hashAlg == TPM2_ALG_SHA256);
  assert(ecc->curveID == TPM2_ECC_NIST_P256);
  assert(ecc->kdf.scheme == TPM2_ALG_NULL);
  assert(value->publicArea.unique.ecc.x.size == 0U);
  assert(value->publicArea.unique.ecc.y.size == 0U);
  assert(((value->publicArea.objectAttributes & TPMA_OBJECT_RESTRICTED) !=
          0U) == restricted);
}

static void test_identity_and_ak_templates(void) {
  const TPMA_OBJECT common = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                             TPMA_OBJECT_SENSITIVEDATAORIGIN |
                             TPMA_OBJECT_USERWITHAUTH |
                             TPMA_OBJECT_SIGN_ENCRYPT;
  TPM2B_PUBLIC identity = {0};
  TPM2B_PUBLIC repeated = {0};
  TPM2B_PUBLIC ak = {0};
  assert(pbns_tpm_identity_template(&identity) == PBNS_OK);
  assert(pbns_tpm_identity_template(&repeated) == PBNS_OK);
  assert(pbns_tpm_ak_template(&ak) == PBNS_OK);
  assert_ecc_profile(&identity, common, false);
  assert_ecc_profile(&ak, common | TPMA_OBJECT_RESTRICTED, true);
  assert((identity.publicArea.objectAttributes & TPMA_OBJECT_DECRYPT) == 0U);
  assert((ak.publicArea.objectAttributes & TPMA_OBJECT_DECRYPT) == 0U);

  uint8_t encoded[512] = {0};
  uint8_t encoded_repeated[512] = {0};
  const size_t length = marshal_public(&identity, encoded);
  const size_t repeated_length = marshal_public(&repeated, encoded_repeated);
  assert(length == repeated_length);
  assert(memcmp(encoded, encoded_repeated, length) == 0);
  assert(identity.size + 2U == length);
}

static void test_public_name_uses_complete_marshaled_public(void) {
  TPM2B_PUBLIC identity = {0};
  assert(pbns_tpm_identity_template(&identity) == PBNS_OK);
  uint8_t name[34] = {0};
  size_t name_length = 0U;
  assert(pbns_tpm_public_name(&identity, openssl_sha256, NULL,
                              (pbns_buffer){name, 0U, sizeof(name)},
                              &name_length) == PBNS_OK);
  assert(name_length == sizeof(name));
  assert(name[0] == 0U && name[1] == 0x0bU);

  uint8_t public_bytes[512] = {0};
  size_t offset = 0U;
  assert(Tss2_MU_TPMT_PUBLIC_Marshal(&identity.publicArea, public_bytes,
                                     sizeof(public_bytes),
                                     &offset) == TSS2_RC_SUCCESS);
  uint8_t expected[32] = {0};
  unsigned int expected_length = 0U;
  assert(EVP_Digest(public_bytes, offset, expected, &expected_length,
                    EVP_sha256(), NULL) == 1);
  assert(expected_length == sizeof(expected));
  assert(memcmp(name + 2U, expected, sizeof(expected)) == 0);

  identity.publicArea.objectAttributes ^= TPMA_OBJECT_NODA;
  uint8_t changed[34] = {0};
  size_t changed_length = 0U;
  assert(pbns_tpm_public_name(&identity, openssl_sha256, NULL,
                              (pbns_buffer){changed, 0U, sizeof(changed)},
                              &changed_length) == PBNS_OK);
  assert(memcmp(name, changed, sizeof(name)) != 0);
}

static pbns_tpm_capabilities complete_capabilities(void) {
  return (pbns_tpm_capabilities){
      .manufacturer = UINT32_C(0x49465800),
      .firmware1 = 1U,
      .firmware2 = 2U,
      .tpm2 = true,
      .ecc_p256 = true,
      .sha256 = true,
      .sha256_pcr_bank = true,
      .sign = true,
      .certify = true,
      .activate_credential = true,
      .get_random = true,
  };
}

static void test_capability_validation_fails_closed(void) {
  pbns_tpm_capabilities capabilities = complete_capabilities();
  assert(pbns_tpm_capabilities_validate(&capabilities) == PBNS_OK);
  assert(pbns_tpm_capabilities_validate(NULL) == PBNS_ERR_ARGUMENT);

  bool *requirements[] = {
      &capabilities.tpm2,
      &capabilities.ecc_p256,
      &capabilities.sha256,
      &capabilities.sha256_pcr_bank,
      &capabilities.sign,
      &capabilities.certify,
      &capabilities.activate_credential,
      &capabilities.get_random,
  };
  for (size_t index = 0U;
       index < sizeof(requirements) / sizeof(requirements[0]); ++index) {
    capabilities = complete_capabilities();
    *requirements[index] = false;
    assert(pbns_tpm_capabilities_validate(&capabilities) ==
           PBNS_ERR_UNSUPPORTED);
  }
}

static void test_nv_profile(void) {
  uint8_t policy[32] = {0};
  policy[0] = 0xa5U;
  TPM2B_NV_PUBLIC value = {0};
  assert(pbns_tpm_nv_public(PBNS_TPM_RECOVERY_NV_INDEX,
                            (pbns_view){policy, sizeof(policy)},
                            &value) == PBNS_OK);
  assert(value.size > 0U);
  assert(value.nvPublic.nvIndex == PBNS_TPM_RECOVERY_NV_INDEX);
  assert(value.nvPublic.nameAlg == TPM2_ALG_SHA256);
  assert(value.nvPublic.authPolicy.size == sizeof(policy));
  assert(memcmp(value.nvPublic.authPolicy.buffer, policy, sizeof(policy)) == 0);
  assert(value.nvPublic.dataSize == 8U);
  const TPMA_NV attributes = value.nvPublic.attributes;
  assert((attributes & TPMA_NV_POLICYWRITE) != 0U);
  assert((attributes & TPMA_NV_OWNERREAD) != 0U);
  assert((attributes & TPMA_NV_NO_DA) != 0U);
  assert((attributes &
          (TPMA_NV_AUTHWRITE | TPMA_NV_OWNERWRITE | TPMA_NV_PPWRITE)) == 0U);

  assert(pbns_tpm_nv_public(PBNS_TPM_RECOVERY_NV_INDEX,
                            (pbns_view){policy, sizeof(policy) - 1U},
                            &value) == PBNS_ERR_ARGUMENT);
  assert(pbns_tpm_nv_public(UINT32_C(0x02000000),
                            (pbns_view){policy, sizeof(policy)},
                            &value) == PBNS_ERR_ARGUMENT);
  assert(pbns_tpm_nv_public(PBNS_TPM_RECOVERY_NV_INDEX,
                            (pbns_view){policy, sizeof(policy)},
                            NULL) == PBNS_ERR_ARGUMENT);
}

static void test_tpm_command_retry_policy_is_bounded(void) {
  assert(PBNS_TPM_COMMAND_RETRY_LIMIT == 3U);
  assert(pbns_tpm_command_retryable(TPM2_RC_RETRY));
  assert(pbns_tpm_command_retryable(TPM2_RC_YIELDED));
  assert(pbns_tpm_command_retryable(TPM2_RC_TESTING));
  assert(!pbns_tpm_command_retryable(TSS2_RC_SUCCESS));
  assert(!pbns_tpm_command_retryable(TPM2_RC_FAILURE));
}

static void test_argument_and_output_contracts(void) {
  TPM2B_PUBLIC value = {0};
  assert(pbns_tpm_identity_template(NULL) == PBNS_ERR_ARGUMENT);
  assert(pbns_tpm_ak_template(NULL) == PBNS_ERR_ARGUMENT);
  assert(pbns_tpm_identity_template(&value) == PBNS_OK);
  uint8_t output[34] = {0};
  size_t written = 99U;
  assert(pbns_tpm_public_name(NULL, openssl_sha256, NULL,
                              (pbns_buffer){output, 0U, sizeof(output)},
                              &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(pbns_tpm_public_name(&value, NULL, NULL,
                              (pbns_buffer){output, 0U, sizeof(output)},
                              &written) == PBNS_ERR_ARGUMENT);
  assert(pbns_tpm_public_name(&value, openssl_sha256, NULL,
                              (pbns_buffer){output, 0U, sizeof(output) - 1U},
                              &written) == PBNS_ERR_LIMIT);
}

int main(void) {
  test_identity_and_ak_templates();
  test_public_name_uses_complete_marshaled_public();
  test_capability_validation_fails_closed();
  test_nv_profile();
  test_tpm_command_retry_policy_is_bounded();
  test_argument_and_output_contracts();
  return 0;
}
