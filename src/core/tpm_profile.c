#include "pbns/tpm_profile.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#define PBNS_TPM_SHA256_SIZE 32U
#define PBNS_TPM_NAME_SIZE 34U
#define PBNS_TPM_MARSHAL_MAX 512U

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static pbns_status finish_public_size(TPM2B_PUBLIC *output) {
  uint8_t encoded[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t offset = 0U;
  const TSS2_RC result = Tss2_MU_TPMT_PUBLIC_Marshal(
      &output->publicArea, encoded, sizeof(encoded), &offset);
  secure_zero(encoded, sizeof(encoded));
  if (result != TSS2_RC_SUCCESS || offset == 0U || offset > UINT16_MAX) {
    *output = (TPM2B_PUBLIC){0};
    return PBNS_ERR_CRYPTO;
  }
  output->size = (UINT16)offset;
  return PBNS_OK;
}

static pbns_status make_signing_template(TPMA_OBJECT attributes,
                                         TPM2B_PUBLIC *output) {
  if (output == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *output = (TPM2B_PUBLIC){0};
  output->publicArea.type = TPM2_ALG_ECC;
  output->publicArea.nameAlg = TPM2_ALG_SHA256;
  output->publicArea.objectAttributes = attributes;
  output->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
  output->publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
  output->publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg =
      TPM2_ALG_SHA256;
  output->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
  output->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
  return finish_public_size(output);
}

bool pbns_tpm_command_retryable(uint32_t command_result) {
  return command_result == (uint32_t)TPM2_RC_RETRY ||
         command_result == (uint32_t)TPM2_RC_YIELDED ||
         command_result == (uint32_t)TPM2_RC_TESTING;
}

bool pbns_tpm_command_retry_delay_us(uint32_t command_result, size_t attempt,
                                     size_t *delay_us) {
  if (delay_us == NULL) {
    return false;
  }
  *delay_us = 0U;
  if (!pbns_tpm_command_retryable(command_result) ||
      attempt + 1U >= PBNS_TPM_COMMAND_RETRY_LIMIT) {
    return false;
  }
  *delay_us = (attempt + 1U) * PBNS_TPM_COMMAND_RETRY_STALL_US;
  return true;
}

pbns_status
pbns_tpm_capabilities_validate(const pbns_tpm_capabilities *capabilities) {
  if (capabilities == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!capabilities->tpm2 || !capabilities->ecc_p256 || !capabilities->sha256 ||
      !capabilities->sha256_pcr_bank || !capabilities->sign ||
      !capabilities->certify || !capabilities->activate_credential ||
      !capabilities->get_random) {
    return PBNS_ERR_UNSUPPORTED;
  }
  return PBNS_OK;
}

pbns_status pbns_tpm_identity_template(TPM2B_PUBLIC *output) {
  const TPMA_OBJECT attributes =
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
      TPMA_OBJECT_SIGN_ENCRYPT;
  return make_signing_template(attributes, output);
}

pbns_status pbns_tpm_ak_template(TPM2B_PUBLIC *output) {
  const TPMA_OBJECT attributes =
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
      TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
  return make_signing_template(attributes, output);
}

static pbns_status make_storage_template(TPM2B_PUBLIC *output) {
  if (output == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *output = (TPM2B_PUBLIC){0};
  output->publicArea.type = TPM2_ALG_ECC;
  output->publicArea.nameAlg = TPM2_ALG_SHA256;
  output->publicArea.objectAttributes =
      TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
      TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
      TPMA_OBJECT_NODA | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
  output->publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
  output->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128U;
  output->publicArea.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
  output->publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
  output->publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
  output->publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
  return finish_public_size(output);
}

pbns_status pbns_tpm_ek_template(TPM2B_PUBLIC *output) {
  return make_storage_template(output);
}

pbns_status pbns_tpm_srk_template(TPM2B_PUBLIC *output) {
  return make_storage_template(output);
}

pbns_status pbns_tpm_nv_public(TPM2_HANDLE index, pbns_view policy_digest,
                               TPM2B_NV_PUBLIC *output) {
  if (index != PBNS_TPM_RECOVERY_NV_INDEX || policy_digest.ptr == NULL ||
      policy_digest.len != PBNS_TPM_SHA256_SIZE || output == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *output = (TPM2B_NV_PUBLIC){0};
  output->nvPublic.nvIndex = index;
  output->nvPublic.nameAlg = TPM2_ALG_SHA256;
  output->nvPublic.attributes =
      TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA;
  output->nvPublic.authPolicy.size = PBNS_TPM_SHA256_SIZE;
  memcpy(output->nvPublic.authPolicy.buffer, policy_digest.ptr,
         policy_digest.len);
  output->nvPublic.dataSize = 8U;

  uint8_t encoded[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t offset = 0U;
  const TSS2_RC result = Tss2_MU_TPMS_NV_PUBLIC_Marshal(
      &output->nvPublic, encoded, sizeof(encoded), &offset);
  secure_zero(encoded, sizeof(encoded));
  if (result != TSS2_RC_SUCCESS || offset == 0U || offset > UINT16_MAX) {
    *output = (TPM2B_NV_PUBLIC){0};
    return PBNS_ERR_CRYPTO;
  }
  output->size = (UINT16)offset;
  return PBNS_OK;
}

pbns_status pbns_tpm_public_name(const TPM2B_PUBLIC *public_area,
                                 pbns_tpm_sha256 sha256, void *sha256_context,
                                 pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (public_area == NULL || sha256 == NULL || output.ptr == NULL ||
      output.len != 0U || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (output.cap < PBNS_TPM_NAME_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  if (public_area->publicArea.nameAlg != TPM2_ALG_SHA256) {
    return PBNS_ERR_UNSUPPORTED;
  }

  uint8_t encoded[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t encoded_length = 0U;
  TSS2_RC result = Tss2_MU_TPMT_PUBLIC_Marshal(
      &public_area->publicArea, encoded, sizeof(encoded), &encoded_length);
  if (result != TSS2_RC_SUCCESS || encoded_length == 0U) {
    secure_zero(encoded, sizeof(encoded));
    return PBNS_ERR_CRYPTO;
  }
  size_t name_offset = 0U;
  result = Tss2_MU_UINT16_Marshal(TPM2_ALG_SHA256, output.ptr, output.cap,
                                  &name_offset);
  if (result != TSS2_RC_SUCCESS || name_offset != 2U) {
    secure_zero(encoded, sizeof(encoded));
    return PBNS_ERR_CRYPTO;
  }
  const pbns_status status =
      sha256(sha256_context, (pbns_view){encoded, encoded_length},
             (pbns_buffer){output.ptr + name_offset, 0U, PBNS_TPM_SHA256_SIZE});
  secure_zero(encoded, sizeof(encoded));
  if (status != PBNS_OK) {
    memset(output.ptr, 0, PBNS_TPM_NAME_SIZE);
    return status;
  }
  *written = PBNS_TPM_NAME_SIZE;
  return PBNS_OK;
}

pbns_status pbns_tpm_public_encode(const TPM2B_PUBLIC *value,
                                   pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (value == NULL || output.ptr == NULL || output.len != 0U ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const TSS2_RC result =
      Tss2_MU_TPM2B_PUBLIC_Marshal(value, output.ptr, output.cap, &offset);
  if (result != TSS2_RC_SUCCESS) {
    return result == TSS2_MU_RC_INSUFFICIENT_BUFFER ? PBNS_ERR_LIMIT
                                                    : PBNS_ERR_FORMAT;
  }
  *written = offset;
  return PBNS_OK;
}

pbns_status pbns_tpm_public_decode(pbns_view encoded, TPM2B_PUBLIC *value) {
  if (encoded.ptr == NULL || encoded.len == 0U || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *value = (TPM2B_PUBLIC){0};
  size_t offset = 0U;
  const TSS2_RC result =
      Tss2_MU_TPM2B_PUBLIC_Unmarshal(encoded.ptr, encoded.len, &offset, value);
  if (result != TSS2_RC_SUCCESS || offset != encoded.len) {
    *value = (TPM2B_PUBLIC){0};
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

pbns_status pbns_tpm_private_encode(const TPM2B_PRIVATE *value,
                                    pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (value == NULL || output.ptr == NULL || output.len != 0U ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const TSS2_RC result =
      Tss2_MU_TPM2B_PRIVATE_Marshal(value, output.ptr, output.cap, &offset);
  if (result != TSS2_RC_SUCCESS) {
    return result == TSS2_MU_RC_INSUFFICIENT_BUFFER ? PBNS_ERR_LIMIT
                                                    : PBNS_ERR_FORMAT;
  }
  *written = offset;
  return PBNS_OK;
}

pbns_status pbns_tpm_signature_encode(const TPMT_SIGNATURE *value,
                                      pbns_buffer output, size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (value == NULL || output.ptr == NULL || output.len != 0U ||
      written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  const TSS2_RC result =
      Tss2_MU_TPMT_SIGNATURE_Marshal(value, output.ptr, output.cap, &offset);
  if (result != TSS2_RC_SUCCESS || offset == 0U) {
    memset(output.ptr, 0, output.cap);
    return result == TSS2_MU_RC_INSUFFICIENT_BUFFER ? PBNS_ERR_LIMIT
                                                    : PBNS_ERR_FORMAT;
  }
  *written = offset;
  return PBNS_OK;
}

pbns_status pbns_tpm_private_decode(pbns_view encoded, TPM2B_PRIVATE *value) {
  if (encoded.ptr == NULL || encoded.len == 0U || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *value = (TPM2B_PRIVATE){0};
  size_t offset = 0U;
  const TSS2_RC result =
      Tss2_MU_TPM2B_PRIVATE_Unmarshal(encoded.ptr, encoded.len, &offset, value);
  if (result != TSS2_RC_SUCCESS || offset != encoded.len) {
    *value = (TPM2B_PRIVATE){0};
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}
