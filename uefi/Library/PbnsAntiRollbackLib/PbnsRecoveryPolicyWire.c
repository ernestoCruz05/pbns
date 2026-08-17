#include "PbnsRecoveryPolicyWire.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <tss2/tss2_mu.h>

#include "pbns/tpm_profile.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define PBNS_POLICY_TPM_PUBLIC_MAX_SIZE 512U
#define PBNS_POLICY_TPM_SIGNATURE_MAX_SIZE 256U
#define PBNS_POLICY_NV_PUBLIC_MAX_SIZE 128U

static const uint8_t initialization_domain[] = "PBNS-RECOVERY-POLICY-INIT-v1";
static const uint8_t update_domain[] = "PBNS-RECOVERY-POLICY-UPDATE-v1";
static const uint8_t initialization_kind[] = "initialize";
static const uint8_t update_kind[] = "update";
static const uint8_t expected_policy_ref[] = "PBNS-RECOVERY-POLICY-REF-v1";

static bool output_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static bool view_valid(pbns_view input) {
  return input.ptr != NULL || input.len == 0U;
}

static bool ranges_overlap(pbns_view input, pbns_buffer output) {
  if (input.len == 0U || output.cap == 0U) {
    return false;
  }
  const uintptr_t input_start = (uintptr_t)input.ptr;
  const uintptr_t output_start = (uintptr_t)output.ptr;
  if (input.len > UINTPTR_MAX - input_start ||
      output.cap > UINTPTR_MAX - output_start) {
    return true;
  }
  return input_start < output_start + output.cap &&
         output_start < input_start + input.len;
}

static bool bytes_nonzero(const uint8_t *value, size_t size) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < size; ++index) {
    combined |= value[index];
  }
  return combined != 0U;
}

static bool target_matches(uint64_t target, const uint8_t operand[8]) {
  uint64_t decoded = 0U;
  for (size_t index = 0U; index < 8U; ++index) {
    decoded = (decoded << 8U) | operand[index];
  }
  return target == decoded;
}

static bool policy_public_valid(const TPM2B_PUBLIC *value) {
  const TPMT_PUBLIC *public_area = &value->publicArea;
  const TPMS_ECC_PARMS *ecc = &public_area->parameters.eccDetail;
  return value->size > 0U && public_area->type == TPM2_ALG_ECC &&
         public_area->nameAlg == TPM2_ALG_SHA256 &&
         public_area->objectAttributes == TPMA_OBJECT_SIGN_ENCRYPT &&
         public_area->authPolicy.size == 0U &&
         ecc->symmetric.algorithm == TPM2_ALG_NULL &&
         ecc->scheme.scheme == TPM2_ALG_ECDSA &&
         ecc->scheme.details.ecdsa.hashAlg == TPM2_ALG_SHA256 &&
         ecc->curveID == TPM2_ECC_NIST_P256 &&
         ecc->kdf.scheme == TPM2_ALG_NULL &&
         public_area->unique.ecc.x.size == 32U &&
         public_area->unique.ecc.y.size == 32U;
}

static bool nv_public_valid(const TPM2B_NV_PUBLIC *value, bool written) {
  const TPMS_NV_PUBLIC *public_area = &value->nvPublic;
  const TPMA_NV expected = TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD |
                           TPMA_NV_NO_DA | (written ? TPMA_NV_WRITTEN : 0U);
  return value->size > 0U &&
         public_area->nvIndex == PBNS_TPM_RECOVERY_NV_INDEX &&
         public_area->nameAlg == TPM2_ALG_SHA256 &&
         public_area->attributes == expected &&
         public_area->authPolicy.size == PBNS_RECOVERY_POLICY_DIGEST_SIZE &&
         public_area->dataSize == PBNS_RECOVERY_POLICY_OPERAND_SIZE;
}

static bool signature_valid(const TPMT_SIGNATURE *signature) {
  return signature->sigAlg == TPM2_ALG_ECDSA &&
         signature->signature.ecdsa.hash == TPM2_ALG_SHA256 &&
         signature->signature.ecdsa.signatureR.size > 0U &&
         signature->signature.ecdsa.signatureR.size <= 32U &&
         signature->signature.ecdsa.signatureS.size > 0U &&
         signature->signature.ecdsa.signatureS.size <= 32U;
}

static bool
authorization_valid(const pbns_recovery_policy_authorization *authorization) {
  if (authorization == NULL ||
      (authorization->kind != PBNS_RECOVERY_POLICY_KIND_INITIALIZE &&
       authorization->kind != PBNS_RECOVERY_POLICY_KIND_UPDATE) ||
      authorization->nv_index != PBNS_TPM_RECOVERY_NV_INDEX ||
      !nv_public_valid(&authorization->nv_public,
                       authorization->kind ==
                           PBNS_RECOVERY_POLICY_KIND_UPDATE) ||
      authorization->nv_name.size != 34U ||
      authorization->target_version == 0U ||
      !target_matches(authorization->target_version, authorization->operand) ||
      authorization->offset != 0U ||
      authorization->operation !=
          (authorization->kind == PBNS_RECOVERY_POLICY_KIND_UPDATE
               ? (uint16_t)TPM2_EO_UNSIGNED_LT
               : 0U) ||
      !bytes_nonzero(authorization->cp_hash, sizeof(authorization->cp_hash)) ||
      !bytes_nonzero(authorization->approved_policy,
                     sizeof(authorization->approved_policy)) ||
      authorization->policy_ref_size != sizeof(expected_policy_ref) - 1U ||
      memcmp(authorization->policy_ref, expected_policy_ref,
             sizeof(expected_policy_ref) - 1U) != 0 ||
      !policy_public_valid(&authorization->policy_key_public) ||
      authorization->policy_key_name.size != 34U ||
      !signature_valid(&authorization->signature) ||
      !bytes_nonzero(authorization->final_policy,
                     sizeof(authorization->final_policy))) {
    return false;
  }
  return memcmp(authorization->nv_public.nvPublic.authPolicy.buffer,
                authorization->final_policy,
                PBNS_RECOVERY_POLICY_DIGEST_SIZE) == 0;
}

static pbns_status
marshal_nv_public(const TPM2B_NV_PUBLIC *value,
                  uint8_t output[PBNS_POLICY_NV_PUBLIC_MAX_SIZE],
                  size_t *written) {
  size_t offset = 0U;
  const TSS2_RC result = Tss2_MU_TPM2B_NV_PUBLIC_Marshal(
      value, output, PBNS_POLICY_NV_PUBLIC_MAX_SIZE, &offset);
  if (result != TSS2_RC_SUCCESS || offset == 0U) {
    memset(output, 0, PBNS_POLICY_NV_PUBLIC_MAX_SIZE);
    return result == TSS2_MU_RC_INSUFFICIENT_BUFFER ? PBNS_ERR_LIMIT
                                                    : PBNS_ERR_FORMAT;
  }
  *written = offset;
  return PBNS_OK;
}

static pbns_status
marshal_public(const TPM2B_PUBLIC *value,
               uint8_t output[PBNS_POLICY_TPM_PUBLIC_MAX_SIZE],
               size_t *written) {
  size_t offset = 0U;
  const TSS2_RC result = Tss2_MU_TPM2B_PUBLIC_Marshal(
      value, output, PBNS_POLICY_TPM_PUBLIC_MAX_SIZE, &offset);
  if (result != TSS2_RC_SUCCESS || offset == 0U) {
    memset(output, 0, PBNS_POLICY_TPM_PUBLIC_MAX_SIZE);
    return result == TSS2_MU_RC_INSUFFICIENT_BUFFER ? PBNS_ERR_LIMIT
                                                    : PBNS_ERR_FORMAT;
  }
  *written = offset;
  return PBNS_OK;
}

static pbns_status
marshal_signature(const TPMT_SIGNATURE *value,
                  uint8_t output[PBNS_POLICY_TPM_SIGNATURE_MAX_SIZE],
                  size_t *written) {
  size_t offset = 0U;
  const TSS2_RC result = Tss2_MU_TPMT_SIGNATURE_Marshal(
      value, output, PBNS_POLICY_TPM_SIGNATURE_MAX_SIZE, &offset);
  if (result != TSS2_RC_SUCCESS || offset == 0U) {
    memset(output, 0, PBNS_POLICY_TPM_SIGNATURE_MAX_SIZE);
    return result == TSS2_MU_RC_INSUFFICIENT_BUFFER ? PBNS_ERR_LIMIT
                                                    : PBNS_ERR_FORMAT;
  }
  *written = offset;
  return PBNS_OK;
}

static pbns_status
encode_unchecked(const pbns_recovery_policy_authorization *authorization,
                 pbns_buffer output, size_t *written) {
  uint8_t nv_public[PBNS_POLICY_NV_PUBLIC_MAX_SIZE] = {0};
  uint8_t policy_public[PBNS_POLICY_TPM_PUBLIC_MAX_SIZE] = {0};
  uint8_t signature[PBNS_POLICY_TPM_SIGNATURE_MAX_SIZE] = {0};
  size_t nv_public_size = 0U;
  size_t policy_public_size = 0U;
  size_t signature_size = 0U;
  pbns_status status =
      marshal_nv_public(&authorization->nv_public, nv_public, &nv_public_size);
  if (status == PBNS_OK) {
    status = marshal_public(&authorization->policy_key_public, policy_public,
                            &policy_public_size);
  }
  if (status == PBNS_OK) {
    status = marshal_signature(&authorization->signature, signature,
                               &signature_size);
  }
  if (status != PBNS_OK) {
    memset(nv_public, 0, sizeof(nv_public));
    memset(policy_public, 0, sizeof(policy_public));
    memset(signature, 0, sizeof(signature));
    return status;
  }
  const uint8_t *domain =
      authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE
          ? initialization_domain
          : update_domain;
  const size_t domain_size =
      authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE
          ? sizeof(initialization_domain) - 1U
          : sizeof(update_domain) - 1U;
  const uint8_t *kind =
      authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE
          ? initialization_kind
          : update_kind;
  const size_t kind_size =
      authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE
          ? sizeof(initialization_kind) - 1U
          : sizeof(update_kind) - 1U;
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddTextToMapN(&encoder, 1, (UsefulBufC){domain, domain_size});
  QCBOREncode_AddUInt64ToMapN(&encoder, 2, 1U);
  QCBOREncode_AddTextToMapN(&encoder, 3, (UsefulBufC){kind, kind_size});
  QCBOREncode_AddUInt64ToMapN(&encoder, 4, authorization->nv_index);
  QCBOREncode_AddBytesToMapN(&encoder, 5,
                             (UsefulBufC){nv_public, nv_public_size});
  QCBOREncode_AddBytesToMapN(
      &encoder, 6,
      (UsefulBufC){authorization->nv_name.name, authorization->nv_name.size});
  QCBOREncode_AddUInt64ToMapN(&encoder, 7, authorization->target_version);
  QCBOREncode_AddBytesToMapN(
      &encoder, 8,
      (UsefulBufC){authorization->operand, sizeof(authorization->operand)});
  QCBOREncode_AddUInt64ToMapN(&encoder, 9, authorization->offset);
  QCBOREncode_AddUInt64ToMapN(&encoder, 10, authorization->operation);
  QCBOREncode_AddBytesToMapN(
      &encoder, 11,
      (UsefulBufC){authorization->cp_hash, sizeof(authorization->cp_hash)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 12,
      (UsefulBufC){authorization->approved_policy,
                   sizeof(authorization->approved_policy)});
  QCBOREncode_AddBytesToMapN(
      &encoder, 13,
      (UsefulBufC){authorization->policy_ref, authorization->policy_ref_size});
  QCBOREncode_AddBytesToMapN(&encoder, 14,
                             (UsefulBufC){policy_public, policy_public_size});
  QCBOREncode_AddBytesToMapN(&encoder, 15,
                             (UsefulBufC){authorization->policy_key_name.name,
                                          authorization->policy_key_name.size});
  QCBOREncode_AddBytesToMapN(&encoder, 16,
                             (UsefulBufC){signature, signature_size});
  QCBOREncode_AddBytesToMapN(&encoder, 17,
                             (UsefulBufC){authorization->final_policy,
                                          sizeof(authorization->final_policy)});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  memset(nv_public, 0, sizeof(nv_public));
  memset(policy_public, 0, sizeof(policy_public));
  memset(signature, 0, sizeof(signature));
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

pbns_status pbns_recovery_policy_encode(
    const pbns_recovery_policy_authorization *authorization, pbns_buffer output,
    size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  if (authorization == NULL || !output_valid(output) || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!authorization_valid(authorization)) {
    return PBNS_ERR_FORMAT;
  }
  if (output.cap > PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE) {
    output.cap = PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE;
  }
  return encode_unchecked(authorization, output, written);
}

static bool text_equal(UsefulBufC value, const uint8_t *expected,
                       size_t expected_size) {
  return value.len == expected_size &&
         memcmp(value.ptr, expected, expected_size) == 0;
}

static pbns_status
decode_tpm_values(UsefulBufC nv_public, UsefulBufC policy_public,
                  UsefulBufC signature,
                  pbns_recovery_policy_authorization *authorization) {
  size_t offset = 0U;
  TSS2_RC result = Tss2_MU_TPM2B_NV_PUBLIC_Unmarshal(
      nv_public.ptr, nv_public.len, &offset, &authorization->nv_public);
  if (result != TSS2_RC_SUCCESS || offset != nv_public.len) {
    return PBNS_ERR_FORMAT;
  }
  offset = 0U;
  result = Tss2_MU_TPM2B_PUBLIC_Unmarshal(policy_public.ptr, policy_public.len,
                                          &offset,
                                          &authorization->policy_key_public);
  if (result != TSS2_RC_SUCCESS || offset != policy_public.len) {
    return PBNS_ERR_FORMAT;
  }
  offset = 0U;
  result = Tss2_MU_TPMT_SIGNATURE_Unmarshal(signature.ptr, signature.len,
                                            &offset, &authorization->signature);
  return result == TSS2_RC_SUCCESS && offset == signature.len ? PBNS_OK
                                                              : PBNS_ERR_FORMAT;
}

static pbns_status
decode_unchecked(pbns_view encoded,
                 pbns_recovery_policy_authorization *authorization) {
  QCBORDecodeContext decoder = {0};
  UsefulBufC domain = {0};
  UsefulBufC kind = {0};
  UsefulBufC nv_public = {0};
  UsefulBufC nv_name = {0};
  UsefulBufC operand = {0};
  UsefulBufC cp_hash = {0};
  UsefulBufC approved = {0};
  UsefulBufC policy_ref = {0};
  UsefulBufC policy_public = {0};
  UsefulBufC policy_key_name = {0};
  UsefulBufC signature = {0};
  UsefulBufC final_policy = {0};
  uint64_t version = 0U;
  uint64_t nv_index = 0U;
  uint64_t offset = 0U;
  uint64_t operation = 0U;
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetTextStringInMapN(&decoder, 1, &domain);
  QCBORDecode_GetUInt64InMapN(&decoder, 2, &version);
  QCBORDecode_GetTextStringInMapN(&decoder, 3, &kind);
  QCBORDecode_GetUInt64InMapN(&decoder, 4, &nv_index);
  QCBORDecode_GetByteStringInMapN(&decoder, 5, &nv_public);
  QCBORDecode_GetByteStringInMapN(&decoder, 6, &nv_name);
  QCBORDecode_GetUInt64InMapN(&decoder, 7, &authorization->target_version);
  QCBORDecode_GetByteStringInMapN(&decoder, 8, &operand);
  QCBORDecode_GetUInt64InMapN(&decoder, 9, &offset);
  QCBORDecode_GetUInt64InMapN(&decoder, 10, &operation);
  QCBORDecode_GetByteStringInMapN(&decoder, 11, &cp_hash);
  QCBORDecode_GetByteStringInMapN(&decoder, 12, &approved);
  QCBORDecode_GetByteStringInMapN(&decoder, 13, &policy_ref);
  QCBORDecode_GetByteStringInMapN(&decoder, 14, &policy_public);
  QCBORDecode_GetByteStringInMapN(&decoder, 15, &policy_key_name);
  QCBORDecode_GetByteStringInMapN(&decoder, 16, &signature);
  QCBORDecode_GetByteStringInMapN(&decoder, 17, &final_policy);
  QCBORDecode_ExitMap(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS || version != 1U ||
      nv_index > UINT32_MAX || offset > UINT16_MAX || operation > UINT16_MAX ||
      nv_name.len != 34U || operand.len != sizeof(authorization->operand) ||
      cp_hash.len != sizeof(authorization->cp_hash) ||
      approved.len != sizeof(authorization->approved_policy) ||
      policy_ref.len == 0U ||
      policy_ref.len > sizeof(authorization->policy_ref) ||
      policy_key_name.len != 34U ||
      final_policy.len != sizeof(authorization->final_policy)) {
    return PBNS_ERR_FORMAT;
  }
  if (text_equal(domain, initialization_domain,
                 sizeof(initialization_domain) - 1U) &&
      text_equal(kind, initialization_kind, sizeof(initialization_kind) - 1U)) {
    authorization->kind = PBNS_RECOVERY_POLICY_KIND_INITIALIZE;
  } else if (text_equal(domain, update_domain, sizeof(update_domain) - 1U) &&
             text_equal(kind, update_kind, sizeof(update_kind) - 1U)) {
    authorization->kind = PBNS_RECOVERY_POLICY_KIND_UPDATE;
  } else {
    return PBNS_ERR_FORMAT;
  }
  authorization->nv_index = (uint32_t)nv_index;
  authorization->offset = (uint16_t)offset;
  authorization->operation = (uint16_t)operation;
  authorization->nv_name.size = (UINT16)nv_name.len;
  memcpy(authorization->nv_name.name, nv_name.ptr, nv_name.len);
  memcpy(authorization->operand, operand.ptr, operand.len);
  memcpy(authorization->cp_hash, cp_hash.ptr, cp_hash.len);
  memcpy(authorization->approved_policy, approved.ptr, approved.len);
  memcpy(authorization->policy_ref, policy_ref.ptr, policy_ref.len);
  authorization->policy_ref_size = policy_ref.len;
  authorization->policy_key_name.size = (UINT16)policy_key_name.len;
  memcpy(authorization->policy_key_name.name, policy_key_name.ptr,
         policy_key_name.len);
  memcpy(authorization->final_policy, final_policy.ptr, final_policy.len);
  return decode_tpm_values(nv_public, policy_public, signature, authorization);
}

pbns_status
pbns_recovery_policy_decode(pbns_view encoded, pbns_buffer canonical_scratch,
                            pbns_recovery_policy_authorization *authorization) {
  if (authorization != NULL) {
    *authorization = (pbns_recovery_policy_authorization){0};
  }
  if (!view_valid(encoded) || encoded.len == 0U ||
      encoded.len > PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE ||
      !output_valid(canonical_scratch) || canonical_scratch.cap < encoded.len ||
      authorization == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (ranges_overlap(encoded, canonical_scratch)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_recovery_policy_authorization decoded = {0};
  pbns_status status = decode_unchecked(encoded, &decoded);
  if (status != PBNS_OK || !authorization_valid(&decoded)) {
    return status != PBNS_OK ? status : PBNS_ERR_FORMAT;
  }
  size_t canonical_size = 0U;
  status = encode_unchecked(&decoded, canonical_scratch, &canonical_size);
  if (status != PBNS_OK || canonical_size != encoded.len ||
      memcmp(canonical_scratch.ptr, encoded.ptr, encoded.len) != 0) {
    return PBNS_ERR_FORMAT;
  }
  *authorization = decoded;
  return PBNS_OK;
}
