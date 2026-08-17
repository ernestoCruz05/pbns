#include "PbnsAntiRollbackLib.h"

#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <mbedtls/sha256.h>
#include <tss2/tss2_mu.h>

#include "pbns/tpm_profile.h"

#define PBNS_TPM_NAME_SIZE 34U
#define PBNS_TPM_POLICY_NONCE_SIZE 32U
#define PBNS_TPM_MARSHAL_MAX 512U
#define PBNS_TPM_TRANSPORT_MAX 4096U
#define PBNS_TPM_RETRY_LIMIT 3U
#define PBNS_TPM_RETRY_DELAY_US 10000U

static bool retry_command(TSS2_RC Result, size_t Attempt) {
  if (!pbns_tpm_command_retryable((uint32_t)Result) ||
      Attempt + 1U >= PBNS_TPM_RETRY_LIMIT || gBS == NULL) {
    return false;
  }
  gBS->Stall(((UINTN)Attempt + 1U) * PBNS_TPM_RETRY_DELAY_US);
  return true;
}

#define PBNS_TPM_EXECUTE(Result, Expression)                                   \
  do {                                                                         \
    for (size_t attempt_ = 0U; attempt_ < PBNS_TPM_RETRY_LIMIT; ++attempt_) {  \
      (Result) = (Expression);                                                 \
      if (!retry_command((Result), attempt_)) {                                \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
  } while (false)

static TSS2L_SYS_AUTH_COMMAND password_auth(void) {
  TSS2L_SYS_AUTH_COMMAND auth = {0};
  auth.count = 1U;
  auth.auths[0].sessionHandle = TPM2_RS_PW;
  return auth;
}

static TSS2L_SYS_AUTH_COMMAND policy_auth(TPMI_SH_AUTH_SESSION Session) {
  TSS2L_SYS_AUTH_COMMAND auth = {0};
  auth.count = 1U;
  auth.auths[0].sessionHandle = Session;
  auth.auths[0].sessionAttributes = TPMA_SESSION_CONTINUESESSION;
  return auth;
}

static pbns_status tss_status(TSS2_RC Result) {
  if (Result == TSS2_RC_SUCCESS) {
    return PBNS_OK;
  }
  return pbns_tpm_command_retryable((uint32_t)Result) ? PBNS_ERR_BUSY
                                                      : PBNS_ERR_CRYPTO;
}

static bool missing_handle(TSS2_RC Result) {
  return (Result & UINT32_C(0x000000bf)) == (uint32_t)TPM2_RC_HANDLE;
}

static void write_u32_be(uint8_t Output[4], uint32_t Value) {
  Output[0] = (uint8_t)(Value >> 24U);
  Output[1] = (uint8_t)(Value >> 16U);
  Output[2] = (uint8_t)(Value >> 8U);
  Output[3] = (uint8_t)Value;
}

static pbns_status sha256_parts(const pbns_view *Parts, size_t PartCount,
                                uint8_t Output[32]) {
  mbedtls_sha256_context context;
  mbedtls_sha256_init(&context);
  int result = mbedtls_sha256_starts(&context, 0);
  for (size_t index = 0U; result == 0 && index < PartCount; ++index) {
    if (Parts[index].ptr == NULL && Parts[index].len != 0U) {
      result = -1;
      break;
    }
    result =
        mbedtls_sha256_update(&context, Parts[index].ptr, Parts[index].len);
  }
  if (result == 0) {
    result = mbedtls_sha256_finish(&context, Output);
  }
  mbedtls_sha256_free(&context);
  if (result != 0) {
    ZeroMem(Output, 32U);
    return PBNS_ERR_CRYPTO;
  }
  return PBNS_OK;
}

static pbns_status public_name(const TPM2B_PUBLIC *Public, TPM2B_NAME *Name) {
  uint8_t marshaled[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t size = 0U;
  TSS2_RC result = Tss2_MU_TPMT_PUBLIC_Marshal(&Public->publicArea, marshaled,
                                               sizeof(marshaled), &size);
  if (result != TSS2_RC_SUCCESS || size == 0U) {
    ZeroMem(marshaled, sizeof(marshaled));
    return PBNS_ERR_FORMAT;
  }
  Name->size = PBNS_TPM_NAME_SIZE;
  Name->name[0] = (uint8_t)(TPM2_ALG_SHA256 >> 8U);
  Name->name[1] = (uint8_t)TPM2_ALG_SHA256;
  const pbns_view parts[] = {{marshaled, size}};
  const pbns_status status = sha256_parts(parts, 1U, Name->name + 2U);
  ZeroMem(marshaled, sizeof(marshaled));
  return status;
}

static pbns_status nv_name(const TPM2B_NV_PUBLIC *Public, TPM2B_NAME *Name) {
  uint8_t marshaled[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t size = 0U;
  TSS2_RC result = Tss2_MU_TPMS_NV_PUBLIC_Marshal(&Public->nvPublic, marshaled,
                                                  sizeof(marshaled), &size);
  if (result != TSS2_RC_SUCCESS || size == 0U) {
    ZeroMem(marshaled, sizeof(marshaled));
    return PBNS_ERR_FORMAT;
  }
  Name->size = PBNS_TPM_NAME_SIZE;
  Name->name[0] = (uint8_t)(TPM2_ALG_SHA256 >> 8U);
  Name->name[1] = (uint8_t)TPM2_ALG_SHA256;
  const pbns_view parts[] = {{marshaled, size}};
  const pbns_status status = sha256_parts(parts, 1U, Name->name + 2U);
  ZeroMem(marshaled, sizeof(marshaled));
  return status;
}

static bool names_equal(const TPM2B_NAME *Left, const TPM2B_NAME *Right) {
  return Left->size == Right->size && Left->size <= sizeof(Left->name) &&
         CompareMem(Left->name, Right->name, Left->size) == 0;
}

static pbns_status
compute_final_policy(const pbns_recovery_policy_authorization *Authorization,
                     uint8_t Output[32]) {
  uint8_t zero[32] = {0};
  uint8_t command[4] = {0};
  uint8_t first[32] = {0};
  write_u32_be(command, TPM2_CC_PolicyAuthorize);
  const pbns_view first_parts[] = {
      {zero, sizeof(zero)},
      {command, sizeof(command)},
      {Authorization->policy_key_name.name,
       Authorization->policy_key_name.size},
  };
  pbns_status status = sha256_parts(first_parts, 3U, first);
  if (status == PBNS_OK) {
    const pbns_view second_parts[] = {
        {first, sizeof(first)},
        {Authorization->policy_ref, Authorization->policy_ref_size},
    };
    status = sha256_parts(second_parts, 2U, Output);
  }
  ZeroMem(first, sizeof(first));
  return status;
}

static pbns_status
compute_approved_policy(const pbns_recovery_policy_authorization *Authorization,
                        uint8_t Output[32]) {
  uint8_t zero[32] = {0};
  uint8_t command[4] = {0};
  uint8_t first[32] = {0};
  pbns_status status = PBNS_OK;
  if (Authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE) {
    const uint8_t written = 0U;
    write_u32_be(command, TPM2_CC_PolicyNvWritten);
    const pbns_view parts[] = {
        {zero, sizeof(zero)},
        {command, sizeof(command)},
        {&written, sizeof(written)},
    };
    status = sha256_parts(parts, 3U, first);
  } else {
    uint8_t offset[2] = {(uint8_t)(Authorization->offset >> 8U),
                         (uint8_t)Authorization->offset};
    uint8_t operation[2] = {(uint8_t)(Authorization->operation >> 8U),
                            (uint8_t)Authorization->operation};
    uint8_t args[32] = {0};
    const pbns_view args_parts[] = {
        {Authorization->operand, sizeof(Authorization->operand)},
        {offset, sizeof(offset)},
        {operation, sizeof(operation)},
    };
    status = sha256_parts(args_parts, 3U, args);
    if (status == PBNS_OK) {
      write_u32_be(command, TPM2_CC_PolicyNV);
      const pbns_view parts[] = {
          {zero, sizeof(zero)},
          {command, sizeof(command)},
          {args, sizeof(args)},
          {Authorization->nv_name.name, Authorization->nv_name.size},
      };
      status = sha256_parts(parts, 4U, first);
    }
    ZeroMem(args, sizeof(args));
  }
  if (status == PBNS_OK) {
    write_u32_be(command, TPM2_CC_PolicyCpHash);
    const pbns_view parts[] = {
        {first, sizeof(first)},
        {command, sizeof(command)},
        {Authorization->cp_hash, sizeof(Authorization->cp_hash)},
    };
    status = sha256_parts(parts, 3U, Output);
  }
  ZeroMem(first, sizeof(first));
  return status;
}

static pbns_status
compute_cp_hash(PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context,
                const pbns_recovery_policy_authorization *Authorization,
                uint8_t Output[32]) {
  TPM2B_MAX_NV_BUFFER data = {.size = sizeof(Authorization->operand)};
  CopyMem(data.buffer, Authorization->operand, sizeof(Authorization->operand));
  TSS2_RC result = Tss2_Sys_NV_Write_Prepare(
      Context->Sys, Authorization->nv_index, Authorization->nv_index, &data,
      Authorization->offset);
  ZeroMem(&data, sizeof(data));
  if (result != TSS2_RC_SUCCESS) {
    return tss_status(result);
  }
  size_t parameter_size = 0U;
  const uint8_t *parameters = NULL;
  result = Tss2_Sys_GetCpBuffer(Context->Sys, &parameter_size, &parameters);
  if (result != TSS2_RC_SUCCESS || parameters == NULL ||
      parameter_size > PBNS_TPM_TRANSPORT_MAX) {
    return PBNS_ERR_CRYPTO;
  }
  uint8_t command[4] = {0};
  write_u32_be(command, TPM2_CC_NV_Write);
  const pbns_view parts[] = {
      {command, sizeof(command)},
      {Authorization->nv_name.name, Authorization->nv_name.size},
      {Authorization->nv_name.name, Authorization->nv_name.size},
      {parameters, parameter_size},
  };
  return sha256_parts(parts, 4U, Output);
}

static bool nv_public_equal(const TPM2B_NV_PUBLIC *Left,
                            const TPM2B_NV_PUBLIC *Right) {
  uint8_t left[PBNS_TPM_MARSHAL_MAX] = {0};
  uint8_t right[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t left_size = 0U;
  size_t right_size = 0U;
  const bool equal =
      Tss2_MU_TPM2B_NV_PUBLIC_Marshal(Left, left, sizeof(left), &left_size) ==
          TSS2_RC_SUCCESS &&
      Tss2_MU_TPM2B_NV_PUBLIC_Marshal(Right, right, sizeof(right),
                                      &right_size) == TSS2_RC_SUCCESS &&
      left_size == right_size && CompareMem(left, right, left_size) == 0;
  ZeroMem(left, sizeof(left));
  ZeroMem(right, sizeof(right));
  return equal;
}

static bool public_equal(const TPM2B_PUBLIC *Left, const TPM2B_PUBLIC *Right) {
  uint8_t left[PBNS_TPM_MARSHAL_MAX] = {0};
  uint8_t right[PBNS_TPM_MARSHAL_MAX] = {0};
  size_t left_size = 0U;
  size_t right_size = 0U;
  const bool equal =
      Tss2_MU_TPM2B_PUBLIC_Marshal(Left, left, sizeof(left), &left_size) ==
          TSS2_RC_SUCCESS &&
      Tss2_MU_TPM2B_PUBLIC_Marshal(Right, right, sizeof(right), &right_size) ==
          TSS2_RC_SUCCESS &&
      left_size == right_size && CompareMem(left, right, left_size) == 0;
  ZeroMem(left, sizeof(left));
  ZeroMem(right, sizeof(right));
  return equal;
}

static pbns_status verify_public_calculations(
    PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context,
    const pbns_recovery_policy_authorization *Authorization) {
  TPM2B_NAME key_name = {0};
  TPM2B_NAME index_name = {0};
  uint8_t digest[32] = {0};
  if (!public_equal(&Authorization->policy_key_public,
                    &Context->ExpectedPolicyKey) ||
      !names_equal(&Authorization->policy_key_name,
                   &Context->ExpectedPolicyKeyName) ||
      CompareMem(Authorization->final_policy, Context->ExpectedFinalPolicy,
                 sizeof(Context->ExpectedFinalPolicy)) != 0) {
    return PBNS_ERR_AUTHENTICATION;
  }
  pbns_status status =
      public_name(&Authorization->policy_key_public, &key_name);
  if (status == PBNS_OK &&
      !names_equal(&key_name, &Authorization->policy_key_name)) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = nv_name(&Authorization->nv_public, &index_name);
  }
  if (status == PBNS_OK && !names_equal(&index_name, &Authorization->nv_name)) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = compute_final_policy(Authorization, digest);
  }
  if (status == PBNS_OK &&
      CompareMem(digest, Authorization->final_policy, sizeof(digest)) != 0) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = compute_approved_policy(Authorization, digest);
  }
  if (status == PBNS_OK &&
      CompareMem(digest, Authorization->approved_policy, sizeof(digest)) != 0) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK) {
    status = compute_cp_hash(Context, Authorization, digest);
  }
  if (status == PBNS_OK &&
      CompareMem(digest, Authorization->cp_hash, sizeof(digest)) != 0) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  ZeroMem(digest, sizeof(digest));
  ZeroMem(&key_name, sizeof(key_name));
  ZeroMem(&index_name, sizeof(index_name));
  return status;
}

static pbns_status read_current(void *Opaque, uint64_t *Version) {
  PBNS_ANTI_ROLLBACK_TPM_CONTEXT *context = Opaque;
  if (context == NULL || context->Sys == NULL || Version == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  TPM2B_NV_PUBLIC public_area = {0};
  TPM2B_NAME name = {0};
  TSS2_RC result = TSS2_RC_SUCCESS;
  PBNS_TPM_EXECUTE(
      result, (Tss2_Sys_NV_ReadPublic(context->Sys, PBNS_TPM_RECOVERY_NV_INDEX,
                                      NULL, &public_area, &name, NULL)));
  if (result != TSS2_RC_SUCCESS) {
    return tss_status(result);
  }
  const TPMA_NV required =
      TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD | TPMA_NV_NO_DA | TPMA_NV_WRITTEN;
  if (public_area.nvPublic.nvIndex != PBNS_TPM_RECOVERY_NV_INDEX ||
      public_area.nvPublic.nameAlg != TPM2_ALG_SHA256 ||
      public_area.nvPublic.attributes != required ||
      public_area.nvPublic.dataSize != 8U ||
      public_area.nvPublic.authPolicy.size !=
          sizeof(context->ExpectedFinalPolicy) ||
      CompareMem(public_area.nvPublic.authPolicy.buffer,
                 context->ExpectedFinalPolicy,
                 sizeof(context->ExpectedFinalPolicy)) != 0) {
    return PBNS_ERR_AUTHENTICATION;
  }
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth();
  TPM2B_MAX_NV_BUFFER data = {0};
  PBNS_TPM_EXECUTE(result, (Tss2_Sys_NV_Read(context->Sys, TPM2_RH_OWNER,
                                             PBNS_TPM_RECOVERY_NV_INDEX, &auth,
                                             8U, 0U, &data, NULL)));
  if (result != TSS2_RC_SUCCESS || data.size != 8U) {
    ZeroMem(&data, sizeof(data));
    return result == TSS2_RC_SUCCESS ? PBNS_ERR_FORMAT : tss_status(result);
  }
  uint64_t version = 0U;
  for (size_t index = 0U; index < 8U; ++index) {
    version = (version << 8U) | data.buffer[index];
  }
  ZeroMem(&data, sizeof(data));
  *Version = version;
  return PBNS_OK;
}

static pbns_status
define_if_absent(PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context,
                 const pbns_recovery_policy_authorization *Authorization) {
  TPM2B_NV_PUBLIC current = {0};
  TPM2B_NAME name = {0};
  TSS2_RC result = TSS2_RC_SUCCESS;
  PBNS_TPM_EXECUTE(
      result, (Tss2_Sys_NV_ReadPublic(Context->Sys, PBNS_TPM_RECOVERY_NV_INDEX,
                                      NULL, &current, &name, NULL)));
  if (result == TSS2_RC_SUCCESS) {
    return nv_public_equal(&current, &Authorization->nv_public) &&
                   names_equal(&name, &Authorization->nv_name)
               ? PBNS_OK
               : PBNS_ERR_AUTHENTICATION;
  }
  if (!missing_handle(result)) {
    return tss_status(result);
  }
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth();
  const TPM2B_AUTH empty_auth = {0};
  PBNS_TPM_EXECUTE(result, (Tss2_Sys_NV_DefineSpace(
                               Context->Sys, TPM2_RH_OWNER, &auth, &empty_auth,
                               &Authorization->nv_public, NULL)));
  if (result != TSS2_RC_SUCCESS) {
    return tss_status(result);
  }
  PBNS_TPM_EXECUTE(
      result, (Tss2_Sys_NV_ReadPublic(Context->Sys, PBNS_TPM_RECOVERY_NV_INDEX,
                                      NULL, &current, &name, NULL)));
  return result == TSS2_RC_SUCCESS &&
                 nv_public_equal(&current, &Authorization->nv_public) &&
                 names_equal(&name, &Authorization->nv_name)
             ? PBNS_OK
             : PBNS_ERR_AUTHENTICATION;
}

static pbns_status
validate_existing(PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context,
                  const pbns_recovery_policy_authorization *Authorization) {
  TPM2B_NV_PUBLIC current = {0};
  TPM2B_NAME name = {0};
  TSS2_RC result = TSS2_RC_SUCCESS;
  PBNS_TPM_EXECUTE(
      result, (Tss2_Sys_NV_ReadPublic(Context->Sys, PBNS_TPM_RECOVERY_NV_INDEX,
                                      NULL, &current, &name, NULL)));
  return result == TSS2_RC_SUCCESS &&
                 nv_public_equal(&current, &Authorization->nv_public) &&
                 names_equal(&name, &Authorization->nv_name)
             ? PBNS_OK
             : PBNS_ERR_AUTHENTICATION;
}

static pbns_status
approval_digest(const pbns_recovery_policy_authorization *Authorization,
                TPM2B_DIGEST *Digest) {
  Digest->size = 32U;
  const pbns_view parts[] = {
      {Authorization->approved_policy, sizeof(Authorization->approved_policy)},
      {Authorization->policy_ref, Authorization->policy_ref_size},
  };
  return sha256_parts(parts, 2U, Digest->buffer);
}

static pbns_status
execute_policy(PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context,
               const pbns_recovery_policy_authorization *Authorization) {
  pbns_status status = verify_public_calculations(Context, Authorization);
  if (status != PBNS_OK) {
    return status;
  }
  status = Authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE
               ? define_if_absent(Context, Authorization)
               : validate_existing(Context, Authorization);
  if (status != PBNS_OK) {
    return status;
  }

  TPMI_SH_AUTH_SESSION session = TPM2_RH_NULL;
  TPM2_HANDLE key_handle = TPM2_RH_NULL;
  TPM2B_DIGEST digest = {0};
  TPM2B_NONCE nonce_caller = {0};
  TPM2B_NONCE nonce_tpm = {0};
  TPM2B_ENCRYPTED_SECRET salt = {0};
  TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
  TPMT_TK_VERIFIED ticket = {0};
  TPM2B_NAME loaded_name = {0};
  TPM2B_MAX_NV_BUFFER data = {.size = sizeof(Authorization->operand)};
  CopyMem(data.buffer, Authorization->operand, sizeof(Authorization->operand));

  TSS2_RC result = TSS2_RC_SUCCESS;
  PBNS_TPM_EXECUTE(result, (Tss2_Sys_GetRandom(Context->Sys, NULL,
                                               PBNS_TPM_POLICY_NONCE_SIZE,
                                               &nonce_caller, NULL)));
  if (result != TSS2_RC_SUCCESS ||
      nonce_caller.size != PBNS_TPM_POLICY_NONCE_SIZE) {
    status = result == TSS2_RC_SUCCESS ? PBNS_ERR_FORMAT : tss_status(result);
    goto cleanup;
  }
  PBNS_TPM_EXECUTE(result, (Tss2_Sys_StartAuthSession(
                               Context->Sys, TPM2_RH_NULL, TPM2_RH_NULL, NULL,
                               &nonce_caller, &salt, TPM2_SE_POLICY, &symmetric,
                               TPM2_ALG_SHA256, &session, &nonce_tpm, NULL)));
  if (result != TSS2_RC_SUCCESS) {
    status = tss_status(result);
    goto cleanup;
  }
  if (Authorization->kind == PBNS_RECOVERY_POLICY_KIND_INITIALIZE) {
    PBNS_TPM_EXECUTE(result, (Tss2_Sys_PolicyNvWritten(Context->Sys, session,
                                                       NULL, TPM2_NO, NULL)));
  } else {
    const TSS2L_SYS_AUTH_COMMAND owner_auth = password_auth();
    TPM2B_OPERAND operand = {.size = sizeof(Authorization->operand)};
    CopyMem(operand.buffer, Authorization->operand,
            sizeof(Authorization->operand));
    PBNS_TPM_EXECUTE(
        result, (Tss2_Sys_PolicyNV(Context->Sys, TPM2_RH_OWNER,
                                   PBNS_TPM_RECOVERY_NV_INDEX, session,
                                   &owner_auth, &operand, Authorization->offset,
                                   (TPM2_EO)Authorization->operation, NULL)));
    ZeroMem(&operand, sizeof(operand));
  }
  if (result != TSS2_RC_SUCCESS) {
    status = tss_status(result);
    goto cleanup;
  }
  TPM2B_DIGEST cp_hash = {.size = sizeof(Authorization->cp_hash)};
  CopyMem(cp_hash.buffer, Authorization->cp_hash,
          sizeof(Authorization->cp_hash));
  PBNS_TPM_EXECUTE(result, (Tss2_Sys_PolicyCpHash(Context->Sys, session, NULL,
                                                  &cp_hash, NULL)));
  ZeroMem(&cp_hash, sizeof(cp_hash));
  if (result != TSS2_RC_SUCCESS) {
    status = tss_status(result);
    goto cleanup;
  }
  PBNS_TPM_EXECUTE(
      result, (Tss2_Sys_LoadExternal(
                  Context->Sys, NULL, NULL, &Authorization->policy_key_public,
                  TPM2_RH_OWNER, &key_handle, &loaded_name, NULL)));
  if (result != TSS2_RC_SUCCESS ||
      !names_equal(&loaded_name, &Authorization->policy_key_name)) {
    status = result == TSS2_RC_SUCCESS ? PBNS_ERR_AUTHENTICATION
                                       : tss_status(result);
    goto cleanup;
  }
  status = approval_digest(Authorization, &digest);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  PBNS_TPM_EXECUTE(result, (Tss2_Sys_VerifySignature(
                               Context->Sys, key_handle, NULL, &digest,
                               &Authorization->signature, &ticket, NULL)));
  if (result != TSS2_RC_SUCCESS) {
    status = tss_status(result);
    goto cleanup;
  }
  TPM2B_DIGEST approved = {.size = sizeof(Authorization->approved_policy)};
  TPM2B_NONCE policy_ref = {.size = (UINT16)Authorization->policy_ref_size};
  CopyMem(approved.buffer, Authorization->approved_policy,
          sizeof(Authorization->approved_policy));
  CopyMem(policy_ref.buffer, Authorization->policy_ref,
          Authorization->policy_ref_size);
  PBNS_TPM_EXECUTE(result,
                   (Tss2_Sys_PolicyAuthorize(
                       Context->Sys, session, NULL, &approved, &policy_ref,
                       &Authorization->policy_key_name, &ticket, NULL)));
  ZeroMem(&approved, sizeof(approved));
  ZeroMem(&policy_ref, sizeof(policy_ref));
  ZeroMem(&ticket, sizeof(ticket));
  if (result != TSS2_RC_SUCCESS) {
    status = tss_status(result);
    goto cleanup;
  }
  const TSS2L_SYS_AUTH_COMMAND write_auth = policy_auth(session);
  PBNS_TPM_EXECUTE(result,
                   (Tss2_Sys_NV_Write(Context->Sys, PBNS_TPM_RECOVERY_NV_INDEX,
                                      PBNS_TPM_RECOVERY_NV_INDEX, &write_auth,
                                      &data, Authorization->offset, NULL)));
  status = tss_status(result);

cleanup:
  ZeroMem(&data, sizeof(data));
  ZeroMem(&digest, sizeof(digest));
  ZeroMem(&nonce_caller, sizeof(nonce_caller));
  ZeroMem(&nonce_tpm, sizeof(nonce_tpm));
  ZeroMem(&salt, sizeof(salt));
  ZeroMem(&ticket, sizeof(ticket));
  if (key_handle != TPM2_RH_NULL) {
    PBNS_TPM_EXECUTE(result, (Tss2_Sys_FlushContext(Context->Sys, key_handle)));
    if (result != TSS2_RC_SUCCESS) {
      status = PBNS_ERR_CRYPTO;
    }
  }
  if (session != TPM2_RH_NULL) {
    PBNS_TPM_EXECUTE(result, (Tss2_Sys_FlushContext(Context->Sys, session)));
    if (result != TSS2_RC_SUCCESS) {
      status = PBNS_ERR_CRYPTO;
    }
  }
  if (status != PBNS_OK) {
    return status;
  }
  uint64_t version = 0U;
  status = read_current(Context, &version);
  return status == PBNS_OK && version == Authorization->target_version
             ? PBNS_OK
             : PBNS_ERR_STATE;
}

static pbns_status advance_tpm(void *Opaque, uint64_t CurrentVersion,
                               uint64_t TargetVersion,
                               pbns_view Authorization) {
  PBNS_ANTI_ROLLBACK_TPM_CONTEXT *context = Opaque;
  pbns_recovery_policy_authorization decoded = {0};
  pbns_status status = pbns_recovery_policy_decode(
      Authorization, context->CanonicalScratch, &decoded);
  if (status != PBNS_OK || decoded.kind != PBNS_RECOVERY_POLICY_KIND_UPDATE ||
      decoded.target_version != TargetVersion) {
    return status != PBNS_OK ? status : PBNS_ERR_AUTHENTICATION;
  }
  uint64_t current = 0U;
  status = read_current(context, &current);
  if (status != PBNS_OK || current != CurrentVersion ||
      TargetVersion <= current) {
    return status != PBNS_OK ? status : PBNS_ERR_REPLAY;
  }
  return execute_policy(context, &decoded);
}

EFI_STATUS EFIAPI PbnsAntiRollbackTpmController(
    PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context, TSS2_SYS_CONTEXT *Sys,
    pbns_buffer CanonicalScratch, const TPM2B_PUBLIC *ExpectedPolicyKey,
    pbns_anti_rollback *Controller) {
  if (Context == NULL || Sys == NULL || ExpectedPolicyKey == NULL ||
      Controller == NULL || CanonicalScratch.ptr == NULL ||
      CanonicalScratch.len != 0U ||
      CanonicalScratch.cap != PBNS_RECOVERY_POLICY_OBJECT_MAX_SIZE) {
    return EFI_INVALID_PARAMETER;
  }
  *Context = (PBNS_ANTI_ROLLBACK_TPM_CONTEXT){
      .Sys = Sys,
      .CanonicalScratch = CanonicalScratch,
      .ExpectedPolicyKey = *ExpectedPolicyKey,
  };
  if (public_name(&Context->ExpectedPolicyKey,
                  &Context->ExpectedPolicyKeyName) != PBNS_OK) {
    ZeroMem(Context, sizeof(*Context));
    return EFI_SECURITY_VIOLATION;
  }
  pbns_recovery_policy_authorization expected = {0};
  expected.policy_key_name = Context->ExpectedPolicyKeyName;
  CopyMem(expected.policy_ref, "PBNS-RECOVERY-POLICY-REF-v1",
          sizeof("PBNS-RECOVERY-POLICY-REF-v1") - 1U);
  expected.policy_ref_size = sizeof("PBNS-RECOVERY-POLICY-REF-v1") - 1U;
  if (compute_final_policy(&expected, Context->ExpectedFinalPolicy) !=
      PBNS_OK) {
    ZeroMem(Context, sizeof(*Context));
    return EFI_SECURITY_VIOLATION;
  }
  return pbns_anti_rollback_init_tpm(Controller, read_current, advance_tpm,
                                     Context) == PBNS_OK
             ? EFI_SUCCESS
             : EFI_DEVICE_ERROR;
}

EFI_STATUS EFIAPI PbnsAntiRollbackTpmInitialize(
    PBNS_ANTI_ROLLBACK_TPM_CONTEXT *Context, pbns_view Authorization,
    pbns_anti_rollback_state *State) {
  if (State != NULL) {
    *State = (pbns_anti_rollback_state){0};
  }
  if (Context == NULL || Context->Sys == NULL || State == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  pbns_recovery_policy_authorization decoded = {0};
  pbns_status status = pbns_recovery_policy_decode(
      Authorization, Context->CanonicalScratch, &decoded);
  if (status != PBNS_OK ||
      decoded.kind != PBNS_RECOVERY_POLICY_KIND_INITIALIZE) {
    return EFI_SECURITY_VIOLATION;
  }
  status = execute_policy(Context, &decoded);
  if (status != PBNS_OK) {
    return EFI_SECURITY_VIOLATION;
  }
  uint64_t version = 0U;
  status = read_current(Context, &version);
  if (status != PBNS_OK || version != decoded.target_version) {
    return EFI_SECURITY_VIOLATION;
  }
  *State = (pbns_anti_rollback_state){
      .version = version,
      .generation = 0U,
      .active_slot = PBNS_ANTI_ROLLBACK_NO_SLOT,
      .assurance = PBNS_ANTI_ROLLBACK_ASSURANCE_TPM,
  };
  return EFI_SUCCESS;
}
