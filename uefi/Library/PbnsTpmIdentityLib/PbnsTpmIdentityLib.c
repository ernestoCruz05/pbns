#include "PbnsTpmIdentityLib.h"

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PbnsTpmEkCertificateLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <mbedtls/sha256.h>
#include <qcbor/qcbor.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>

#include "PbnsTpmIdentityUefi.h"
#include "PbnsTpmPolicy.h"
#include "PbnsTpmQuoteCore.h"
#include "PbnsTpmStorage.h"
#include "PbnsTpmSubmitUefi.h"
#include "PbnsTss2Tcti.h"
#include "pbns/measured_boot.h"
#include "pbns/tpm_profile.h"

#define PBNS_TPM_SYS_CONTEXT_MAX 4608U
#define PBNS_TPM_COMMAND_MAX 4096U
#define PBNS_TPM_PUBLIC_COSE_MAX 128U
#define PBNS_TPM_FINGERPRINT_SIZE 32U
#define PBNS_TPM_RAW_SIGNATURE_SIZE 64U
#define PBNS_TPM_COORDINATE_SIZE 32U
#define PBNS_TPM_HANDLE_INVALID ((TPM2_HANDLE)0U)

typedef union PBNS_TPM_ALIGNED_SYS_CONTEXT {
  uint64_t Alignment;
  uint8_t Bytes[PBNS_TPM_SYS_CONTEXT_MAX];
} PBNS_TPM_ALIGNED_SYS_CONTEXT;

typedef struct PBNS_TPM_CONTEXT {
  PBNS_TPM_ALIGNED_SYS_CONTEXT SysStorage;
  TSS2_SYS_CONTEXT *Sys;
  pbns_tss2_tcti Tcti;
  uint8_t SubmitStorage[PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE];
  TPM2_HANDLE AkHandle;
  TPM2_HANDLE IdentityHandle;
  TPM2B_PUBLIC AkPublic;
  TPM2B_PUBLIC IdentityPublic;
  uint8_t PublicCose[PBNS_TPM_PUBLIC_COSE_MAX];
  size_t PublicCoseLength;
  uint8_t Fingerprint[PBNS_TPM_FINGERPRINT_SIZE];
  pbns_tpm_capability_result Capabilities;
} PBNS_TPM_CONTEXT;

static TSS2L_SYS_AUTH_COMMAND password_auth(size_t Count) {
  TSS2L_SYS_AUTH_COMMAND auth = {0};
  auth.count = (uint16_t)Count;
  for (size_t index = 0U; index < Count; ++index) {
    auth.auths[index].sessionHandle = TPM2_RS_PW;
  }
  return auth;
}

static pbns_status sha256_callback(void *Context, pbns_view Input,
                                   pbns_buffer Digest) {
  (void)Context;
  if (Digest.ptr == NULL || Digest.len != 0U || Digest.cap < 32U) {
    return PBNS_ERR_ARGUMENT;
  }
  return mbedtls_sha256(Input.ptr, Input.len, Digest.ptr, 0) == 0
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static EFI_STATUS tss_status(TSS2_RC Result) {
  return Result == TSS2_RC_SUCCESS ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

static bool retry_command_after_delay(TSS2_RC Result, size_t Attempt) {
  size_t delay_us = 0U;
  if (!pbns_tpm_command_retry_delay_us((uint32_t)Result, Attempt, &delay_us) ||
      gBS == NULL || delay_us > (size_t)MAX_UINTN) {
    return false;
  }
  return !EFI_ERROR(gBS->Stall((UINTN)delay_us));
}

static void flush_handle(PBNS_TPM_CONTEXT *Context, TPM2_HANDLE *Handle) {
  if (Context != NULL && Context->Sys != NULL && Handle != NULL &&
      *Handle != PBNS_TPM_HANDLE_INVALID) {
    (void)Tss2_Sys_FlushContext(Context->Sys, *Handle);
    *Handle = PBNS_TPM_HANDLE_INVALID;
  }
}

static void context_final(PBNS_TPM_CONTEXT *Context) {
  if (Context == NULL) {
    return;
  }
  flush_handle(Context, &Context->IdentityHandle);
  flush_handle(Context, &Context->AkHandle);
  if (Context->Sys != NULL) {
    Tss2_Sys_Finalize(Context->Sys);
    Context->Sys = NULL;
  }
  if (Context->Tcti.common.v1.finalize != NULL) {
    Context->Tcti.common.v1.finalize(
        (TSS2_TCTI_CONTEXT *)(void *)&Context->Tcti);
  }
  pbns_tpm_submit_uefi_final(Context->SubmitStorage);
}

static EFI_STATUS context_init(PBNS_TPM_CONTEXT *Context) {
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  ZeroMem(Context, sizeof(*Context));
  const size_t required = Tss2_Sys_GetContextSize(PBNS_TPM_COMMAND_MAX);
  if (required == 0U || required > sizeof(Context->SysStorage.Bytes)) {
    return EFI_OUT_OF_RESOURCES;
  }
  pbns_tpm_submit submit = NULL;
  void *submit_context = NULL;
  pbns_status status = pbns_tpm_submit_uefi_init(Context->SubmitStorage,
                                                 &submit, &submit_context);
  if (status != PBNS_OK) {
    return EFI_UNSUPPORTED;
  }
  status = pbns_tss2_tcti_initialize(&Context->Tcti, submit, submit_context);
  if (status != PBNS_OK) {
    pbns_tpm_submit_uefi_final(Context->SubmitStorage);
    return EFI_DEVICE_ERROR;
  }
  Context->Sys = (TSS2_SYS_CONTEXT *)(void *)Context->SysStorage.Bytes;
  TSS2_ABI_VERSION abi = TSS2_ABI_VERSION_CURRENT;
  const TSS2_RC result =
      Tss2_Sys_Initialize(Context->Sys, required,
                          (TSS2_TCTI_CONTEXT *)(void *)&Context->Tcti, &abi);
  if (result != TSS2_RC_SUCCESS) {
    Context->Sys = NULL;
    Context->Tcti.common.v1.finalize(
        (TSS2_TCTI_CONTEXT *)(void *)&Context->Tcti);
    pbns_tpm_submit_uefi_final(Context->SubmitStorage);
    return EFI_DEVICE_ERROR;
  }
  return EFI_SUCCESS;
}

static EFI_STATUS create_primary(PBNS_TPM_CONTEXT *Context,
                                 TPMI_RH_HIERARCHY Hierarchy,
                                 const TPM2B_PUBLIC *Template,
                                 TPM2_HANDLE *Handle, TPM2B_PUBLIC *Public,
                                 TPM2B_NAME *Name) {
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth(1U);
  const TPM2B_SENSITIVE_CREATE sensitive = {0};
  const TPM2B_DATA outside = {0};
  const TPML_PCR_SELECTION pcr = {0};
  return tss_status(Tss2_Sys_CreatePrimary(
      Context->Sys, Hierarchy, &auth, &sensitive, Template, &outside, &pcr,
      Handle, Public, NULL, NULL, NULL, Name, NULL));
}

static EFI_STATUS create_child(PBNS_TPM_CONTEXT *Context, TPM2_HANDLE Parent,
                               const TPM2B_PUBLIC *Template,
                               TPM2B_PRIVATE *Private, TPM2B_PUBLIC *Public) {
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth(1U);
  const TPM2B_SENSITIVE_CREATE sensitive = {0};
  const TPM2B_DATA outside = {0};
  const TPML_PCR_SELECTION pcr = {0};
  return tss_status(Tss2_Sys_Create(Context->Sys, Parent, &auth, &sensitive,
                                    Template, &outside, &pcr, Private, Public,
                                    NULL, NULL, NULL, NULL));
}

static EFI_STATUS load_child(PBNS_TPM_CONTEXT *Context, TPM2_HANDLE Parent,
                             const TPM2B_PRIVATE *Private,
                             const TPM2B_PUBLIC *Public, TPM2_HANDLE *Handle,
                             TPM2B_NAME *Name) {
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth(1U);
  return tss_status(Tss2_Sys_Load(Context->Sys, Parent, &auth, Private, Public,
                                  Handle, Name, NULL));
}

static bool names_equal(const TPM2B_NAME *Left, pbns_view Right) {
  return Left != NULL && Left->size == Right.len && Right.ptr != NULL &&
         CompareMem(Left->name, Right.ptr, Right.len) == 0;
}

static EFI_STATUS encode_public(const TPM2B_PUBLIC *Public, uint8_t *Output,
                                size_t Capacity, size_t *Length) {
  const pbns_status status = pbns_tpm_public_encode(
      Public, (pbns_buffer){Output, 0U, Capacity}, Length);
  return status == PBNS_OK ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
}

static EFI_STATUS encode_private(const TPM2B_PRIVATE *Private, uint8_t *Output,
                                 size_t Capacity, size_t *Length) {
  const pbns_status status = pbns_tpm_private_encode(
      Private, (pbns_buffer){Output, 0U, Capacity}, Length);
  return status == PBNS_OK ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
}

static EFI_STATUS compare_public_blob(const TPM2B_PUBLIC *Public,
                                      pbns_view Expected) {
  uint8_t encoded[PBNS_TPM_PUBLIC_MAX] = {0};
  size_t length = 0U;
  const EFI_STATUS status =
      encode_public(Public, encoded, sizeof(encoded), &length);
  const bool match = !EFI_ERROR(status) && length == Expected.len &&
                     CompareMem(encoded, Expected.ptr, length) == 0;
  ZeroMem(encoded, sizeof(encoded));
  return match ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

static EFI_STATUS read_and_validate(PBNS_TPM_CONTEXT *Context,
                                    TPM2_HANDLE Handle, pbns_view PublicBlob,
                                    pbns_view ExpectedName,
                                    TPM2B_PUBLIC *Public) {
  TPM2B_NAME name = {0};
  TPM2B_NAME qualified_name = {0};
  TSS2_RC result = Tss2_Sys_ReadPublic(Context->Sys, Handle, NULL, Public,
                                       &name, &qualified_name, NULL);
  if (result != TSS2_RC_SUCCESS || !names_equal(&name, ExpectedName)) {
    return EFI_SECURITY_VIOLATION;
  }
  return compare_public_blob(Public, PublicBlob);
}

static pbns_status public_name_from_blob(void *Context, pbns_view PublicBlob,
                                         pbns_buffer Name) {
  (void)Context;
  TPM2B_PUBLIC public_value = {0};
  if (pbns_tpm_public_decode(PublicBlob, &public_value) != PBNS_OK) {
    return PBNS_ERR_FORMAT;
  }
  size_t written = 0U;
  return pbns_tpm_public_name(&public_value, sha256_callback, NULL, Name,
                              &written);
}

static EFI_STATUS discover_capabilities(PBNS_TPM_CONTEXT *Context,
                                        pbns_tpm_capability_result *Result) {
  TPMS_CAPABILITY_DATA properties = {0};
  TPMI_YES_NO more = TPM2_NO;
  TSS2_RC rc = Tss2_Sys_GetCapability(
      Context->Sys, NULL, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER, 8U,
      &more, &properties, NULL);
  if (rc != TSS2_RC_SUCCESS ||
      properties.capability != TPM2_CAP_TPM_PROPERTIES) {
    return EFI_UNSUPPORTED;
  }
  uint32_t manufacturer = 0U;
  uint32_t firmware1 = 0U;
  uint32_t firmware2 = 0U;
  for (UINT32 index = 0U; index < properties.data.tpmProperties.count;
       ++index) {
    const TPMS_TAGGED_PROPERTY property =
        properties.data.tpmProperties.tpmProperty[index];
    if (property.property == TPM2_PT_MANUFACTURER) {
      manufacturer = property.value;
    } else if (property.property == TPM2_PT_FIRMWARE_VERSION_1) {
      firmware1 = property.value;
    } else if (property.property == TPM2_PT_FIRMWARE_VERSION_2) {
      firmware2 = property.value;
    }
  }

  TPMS_CAPABILITY_DATA algorithms = {0};
  rc = Tss2_Sys_GetCapability(Context->Sys, NULL, TPM2_CAP_ALGS, 0U, 64U, &more,
                              &algorithms, NULL);
  bool ecc = false;
  bool sha256 = false;
  if (rc == TSS2_RC_SUCCESS && algorithms.capability == TPM2_CAP_ALGS) {
    for (UINT32 index = 0U; index < algorithms.data.algorithms.count; ++index) {
      const TPM2_ALG_ID algorithm =
          algorithms.data.algorithms.algProperties[index].alg;
      ecc = ecc || algorithm == TPM2_ALG_ECC;
      sha256 = sha256 || algorithm == TPM2_ALG_SHA256;
    }
  }
  TPMS_CAPABILITY_DATA curves = {0};
  rc = Tss2_Sys_GetCapability(Context->Sys, NULL, TPM2_CAP_ECC_CURVES, 0U, 64U,
                              &more, &curves, NULL);
  bool p256 = false;
  if (rc == TSS2_RC_SUCCESS && curves.capability == TPM2_CAP_ECC_CURVES) {
    for (UINT32 index = 0U; index < curves.data.eccCurves.count; ++index) {
      p256 =
          p256 || curves.data.eccCurves.eccCurves[index] == TPM2_ECC_NIST_P256;
    }
  }

  const TPML_PCR_SELECTION selection = {
      .count = 1U,
      .pcrSelections = {{.hash = TPM2_ALG_SHA256,
                         .sizeofSelect = 3U,
                         .pcrSelect = {1U, 0U, 0U, 0U}}},
  };
  UINT32 update_counter = 0U;
  TPML_PCR_SELECTION selection_out = {0};
  TPML_DIGEST values = {0};
  const bool sha256_pcr =
      Tss2_Sys_PCR_Read(Context->Sys, NULL, &selection, &update_counter,
                        &selection_out, &values, NULL) == TSS2_RC_SUCCESS &&
      selection_out.count > 0U;
  TPM2B_DIGEST random = {0};
  const bool random_ok = Tss2_Sys_GetRandom(Context->Sys, NULL, 1U, &random,
                                            NULL) == TSS2_RC_SUCCESS &&
                         random.size > 0U;
  *Result = (pbns_tpm_capability_result){
      .required =
          {
              .manufacturer = manufacturer,
              .firmware1 = firmware1,
              .firmware2 = firmware2,
              .tpm2 = manufacturer != 0U,
              .ecc_p256 = ecc && p256,
              .sha256 = sha256,
              .sha256_pcr_bank = sha256_pcr,
              .sign = true,
              .certify = true,
              .activate_credential = true,
              .get_random = random_ok,
          },
      .ek_certificate_present = false,
      .ek_chain_digest = {0},
  };
  return pbns_tpm_capabilities_validate(&Result->required) == PBNS_OK
             ? EFI_SUCCESS
             : EFI_UNSUPPORTED;
}

static pbns_status encode_cose(PBNS_TPM_CONTEXT *Context) {
  const TPMS_ECC_POINT *point = &Context->IdentityPublic.publicArea.unique.ecc;
  if (point->x.size == 0U || point->x.size > PBNS_TPM_COORDINATE_SIZE ||
      point->y.size == 0U || point->y.size > PBNS_TPM_COORDINATE_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  uint8_t x[PBNS_TPM_COORDINATE_SIZE] = {0};
  uint8_t y[PBNS_TPM_COORDINATE_SIZE] = {0};
  CopyMem(x + sizeof(x) - point->x.size, point->x.buffer, point->x.size);
  CopyMem(y + sizeof(y) - point->y.size, point->y.buffer, point->y.size);
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(
      &encoder, (UsefulBuf){Context->PublicCose, sizeof(Context->PublicCose)});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, 2);
  QCBOREncode_AddInt64ToMapN(&encoder, -1, 1);
  QCBOREncode_AddBytesToMapN(&encoder, -2, (UsefulBufC){x, sizeof(x)});
  QCBOREncode_AddBytesToMapN(&encoder, -3, (UsefulBufC){y, sizeof(y)});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  ZeroMem(x, sizeof(x));
  ZeroMem(y, sizeof(y));
  if (error != QCBOR_SUCCESS || encoded.len == 0U ||
      encoded.len > sizeof(Context->PublicCose)) {
    return PBNS_ERR_CRYPTO;
  }
  Context->PublicCoseLength = encoded.len;
  return mbedtls_sha256(Context->PublicCose, Context->PublicCoseLength,
                        Context->Fingerprint, 0) == 0
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static pbns_status signature_raw(const TPMT_SIGNATURE *Signature,
                                 pbns_buffer Output, size_t *Written) {
  if (Written != NULL) {
    *Written = 0U;
  }
  if (Signature == NULL || Output.ptr == NULL || Output.len != 0U ||
      Output.cap < PBNS_TPM_RAW_SIGNATURE_SIZE || Written == NULL ||
      Signature->sigAlg != TPM2_ALG_ECDSA ||
      Signature->signature.ecdsa.hash != TPM2_ALG_SHA256 ||
      Signature->signature.ecdsa.signatureR.size > PBNS_TPM_COORDINATE_SIZE ||
      Signature->signature.ecdsa.signatureS.size > PBNS_TPM_COORDINATE_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  ZeroMem(Output.ptr, PBNS_TPM_RAW_SIGNATURE_SIZE);
  CopyMem(Output.ptr + PBNS_TPM_COORDINATE_SIZE -
              Signature->signature.ecdsa.signatureR.size,
          Signature->signature.ecdsa.signatureR.buffer,
          Signature->signature.ecdsa.signatureR.size);
  CopyMem(Output.ptr + PBNS_TPM_RAW_SIGNATURE_SIZE -
              Signature->signature.ecdsa.signatureS.size,
          Signature->signature.ecdsa.signatureS.buffer,
          Signature->signature.ecdsa.signatureS.size);
  *Written = PBNS_TPM_RAW_SIGNATURE_SIZE;
  return PBNS_OK;
}

static pbns_status signature_marshaled(const TPMT_SIGNATURE *Signature,
                                       pbns_buffer Output, size_t *Written) {
  if (Written != NULL) {
    *Written = 0U;
  }
  if (Signature == NULL || Output.ptr == NULL || Output.len != 0U ||
      Written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_tpm_signature_encode(Signature, Output, Written);
}

static pbns_status identity_public(void *Opaque, pbns_buffer Output,
                                   size_t *Written) {
  PBNS_TPM_CONTEXT *context = Opaque;
  if (Written == NULL || Output.ptr == NULL || Output.len != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  *Written = 0U;
  if (Output.cap < context->PublicCoseLength) {
    return PBNS_ERR_LIMIT;
  }
  CopyMem(Output.ptr, context->PublicCose, context->PublicCoseLength);
  *Written = context->PublicCoseLength;
  return PBNS_OK;
}

static pbns_status identity_fingerprint(void *Opaque, pbns_buffer Output) {
  PBNS_TPM_CONTEXT *context = Opaque;
  if (Output.ptr == NULL || Output.len != 0U ||
      Output.cap < sizeof(context->Fingerprint)) {
    return PBNS_ERR_ARGUMENT;
  }
  CopyMem(Output.ptr, context->Fingerprint, sizeof(context->Fingerprint));
  return PBNS_OK;
}

static pbns_status identity_sign(void *Opaque, pbns_view Digest,
                                 pbns_buffer Signature, size_t *Written) {
  PBNS_TPM_CONTEXT *context = Opaque;
  if (Digest.ptr == NULL || Digest.len != 32U) {
    return PBNS_ERR_ARGUMENT;
  }
  TPM2B_DIGEST tpm_digest = {.size = 32U};
  CopyMem(tpm_digest.buffer, Digest.ptr, Digest.len);
  const TPMT_SIG_SCHEME scheme = {
      .scheme = TPM2_ALG_ECDSA,
      .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
  };
  const TPMT_TK_HASHCHECK validation = {
      .tag = TPM2_ST_HASHCHECK,
      .hierarchy = TPM2_RH_NULL,
      .digest = {0},
  };
  TPMT_SIGNATURE result = {0};
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth(1U);
  TSS2_RC rc = TSS2_BASE_RC_GENERAL_FAILURE;
  for (size_t attempt = 0U; attempt < PBNS_TPM_COMMAND_RETRY_LIMIT; ++attempt) {
    ZeroMem(&result, sizeof(result));
    rc = Tss2_Sys_Sign(context->Sys, context->IdentityHandle, &auth,
                       &tpm_digest, &scheme, &validation, &result, NULL);
    if (!retry_command_after_delay(rc, attempt)) {
      break;
    }
  }
  ZeroMem(&tpm_digest, sizeof(tpm_digest));
  if (rc != TSS2_RC_SUCCESS) {
    return PBNS_ERR_CRYPTO;
  }
  const pbns_status status = signature_raw(&result, Signature, Written);
  ZeroMem(&result, sizeof(result));
  return status;
}

static pbns_status identity_random(void *Opaque, pbns_buffer Output) {
  PBNS_TPM_CONTEXT *context = Opaque;
  if (Output.ptr == NULL || Output.len != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  size_t offset = 0U;
  while (offset < Output.cap) {
    const size_t remaining = Output.cap - offset;
    const UINT16 request =
        (UINT16)(remaining > sizeof(((TPM2B_DIGEST *)0)->buffer)
                     ? sizeof(((TPM2B_DIGEST *)0)->buffer)
                     : remaining);
    TPM2B_DIGEST random = {0};
    TSS2_RC rc = TSS2_BASE_RC_GENERAL_FAILURE;
    for (size_t attempt = 0U; attempt < PBNS_TPM_COMMAND_RETRY_LIMIT;
         ++attempt) {
      ZeroMem(&random, sizeof(random));
      rc = Tss2_Sys_GetRandom(context->Sys, NULL, request, &random, NULL);
      if (!retry_command_after_delay(rc, attempt)) {
        break;
      }
    }
    if (rc != TSS2_RC_SUCCESS || random.size == 0U || random.size > request) {
      ZeroMem(Output.ptr, Output.cap);
      ZeroMem(&random, sizeof(random));
      return PBNS_ERR_ENTROPY;
    }
    CopyMem(Output.ptr + offset, random.buffer, random.size);
    offset += random.size;
    ZeroMem(&random, sizeof(random));
  }
  return PBNS_OK;
}

static void identity_close(void *Opaque) {
  PBNS_TPM_CONTEXT *context = Opaque;
  context_final(context);
  ZeroMem(context, sizeof(*context));
  FreePool(context);
}

static const pbns_identity_ops mIdentityOps = {
    .public_cose_key = identity_public,
    .fingerprint = identity_fingerprint,
    .sign_digest = identity_sign,
    .random = identity_random,
    .close = identity_close,
};

static EFI_STATUS expose_identity(PBNS_TPM_CONTEXT *Context,
                                  pbns_identity *Identity) {
  const pbns_status status = encode_cose(Context);
  if (status != PBNS_OK ||
      pbns_identity_open(Identity, &mIdentityOps, Context,
                         PBNS_IDENTITY_TPM_UNVERIFIED_EK) != PBNS_OK) {
    return EFI_SECURITY_VIOLATION;
  }
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI
PbnsTpmIdentityCapabilities(pbns_tpm_capability_result *Result) {
  if (Result == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  ZeroMem(Result, sizeof(*Result));
  PBNS_TPM_CONTEXT context = {0};
  EFI_STATUS status = context_init(&context);
  if (!EFI_ERROR(status)) {
    status = discover_capabilities(&context, Result);
  }
  context_final(&context);
  ZeroMem(&context, sizeof(context));
  return status;
}

EFI_STATUS EFIAPI PbnsTpmIdentityCreate(pbns_identity *Identity,
                                        pbns_tpm_capability_result *Result) {
  if (Identity == NULL || Result == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Identity = (pbns_identity){0};
  ZeroMem(Result, sizeof(*Result));
  PBNS_TPM_CONTEXT *context = AllocateZeroPool(sizeof(*context));
  if (context == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  EFI_STATUS status = context_init(context);
  if (EFI_ERROR(status)) {
    goto fail;
  }
  status = discover_capabilities(context, &context->Capabilities);
  if (EFI_ERROR(status)) {
    goto fail;
  }

  TPM2B_PUBLIC ek_template = {0};
  TPM2B_PUBLIC srk_template = {0};
  TPM2B_PUBLIC ak_template = {0};
  TPM2B_PUBLIC identity_template = {0};
  if (PbnsTpmEndorsementTemplate(&ek_template) != PBNS_OK ||
      PbnsTpmStorageTemplate(&srk_template) != PBNS_OK ||
      pbns_tpm_ak_template(&ak_template) != PBNS_OK ||
      pbns_tpm_identity_template(&identity_template) != PBNS_OK) {
    status = EFI_SECURITY_VIOLATION;
    goto fail;
  }

  TPM2_HANDLE ek_handle = PBNS_TPM_HANDLE_INVALID;
  TPM2B_PUBLIC ek_public = {0};
  TPM2B_NAME ek_name = {0};
  status = create_primary(context, TPM2_RH_ENDORSEMENT, &ek_template,
                          &ek_handle, &ek_public, &ek_name);
  flush_handle(context, &ek_handle);
  if (EFI_ERROR(status)) {
    goto fail;
  }

  TPM2_HANDLE srk_handle = PBNS_TPM_HANDLE_INVALID;
  TPM2B_PUBLIC srk_public = {0};
  TPM2B_NAME srk_name = {0};
  status = create_primary(context, TPM2_RH_OWNER, &srk_template, &srk_handle,
                          &srk_public, &srk_name);
  if (EFI_ERROR(status)) {
    goto fail;
  }
  TPM2B_PRIVATE ak_private = {0};
  TPM2B_PRIVATE identity_private = {0};
  status = create_child(context, srk_handle, &ak_template, &ak_private,
                        &context->AkPublic);
  if (!EFI_ERROR(status)) {
    TPM2B_NAME loaded_name = {0};
    status = load_child(context, srk_handle, &ak_private, &context->AkPublic,
                        &context->AkHandle, &loaded_name);
  }
  TPM2B_NAME identity_name = {0};
  TPM2B_NAME ak_name = {0};
  if (!EFI_ERROR(status)) {
    status = Tss2_Sys_ReadPublic(context->Sys, context->AkHandle, NULL,
                                 &context->AkPublic, &ak_name, NULL,
                                 NULL) == TSS2_RC_SUCCESS
                 ? EFI_SUCCESS
                 : EFI_DEVICE_ERROR;
  }
  if (!EFI_ERROR(status)) {
    status = create_child(context, srk_handle, &identity_template,
                          &identity_private, &context->IdentityPublic);
  }
  if (!EFI_ERROR(status)) {
    status = load_child(context, srk_handle, &identity_private,
                        &context->IdentityPublic, &context->IdentityHandle,
                        &identity_name);
  }
  flush_handle(context, &srk_handle);
  if (EFI_ERROR(status)) {
    goto fail;
  }
  uint8_t ek_public_blob[PBNS_TPM_PUBLIC_MAX] = {0};
  uint8_t srk_public_blob[PBNS_TPM_PUBLIC_MAX] = {0};
  uint8_t ak_public_blob[PBNS_TPM_PUBLIC_MAX] = {0};
  uint8_t identity_public_blob[PBNS_TPM_PUBLIC_MAX] = {0};
  uint8_t ak_private_blob[PBNS_TPM_PRIVATE_MAX] = {0};
  uint8_t identity_private_blob[PBNS_TPM_PRIVATE_MAX] = {0};
  size_t ek_public_size = 0U;
  size_t srk_public_size = 0U;
  size_t ak_public_size = 0U;
  size_t identity_public_size = 0U;
  size_t ak_private_size = 0U;
  size_t identity_private_size = 0U;
  if (EFI_ERROR(encode_public(&ek_public, ek_public_blob,
                              sizeof(ek_public_blob), &ek_public_size)) ||
      EFI_ERROR(encode_public(&srk_public, srk_public_blob,
                              sizeof(srk_public_blob), &srk_public_size)) ||
      EFI_ERROR(encode_public(&context->AkPublic, ak_public_blob,
                              sizeof(ak_public_blob), &ak_public_size)) ||
      EFI_ERROR(encode_public(&context->IdentityPublic, identity_public_blob,
                              sizeof(identity_public_blob),
                              &identity_public_size)) ||
      EFI_ERROR(encode_private(&ak_private, ak_private_blob,
                               sizeof(ak_private_blob), &ak_private_size)) ||
      EFI_ERROR(encode_private(&identity_private, identity_private_blob,
                               sizeof(identity_private_blob),
                               &identity_private_size))) {
    status = EFI_COMPROMISED_DATA;
    goto fail;
  }
  const uint8_t no_ek_chain[32] = {0};
  const pbns_tpm_storage_record record = {
      .manufacturer = context->Capabilities.required.manufacturer,
      .firmware1 = context->Capabilities.required.firmware1,
      .firmware2 = context->Capabilities.required.firmware2,
      .ek_public = {ek_public_blob, ek_public_size},
      .ek_name = {ek_name.name, ek_name.size},
      .srk_public = {srk_public_blob, srk_public_size},
      .srk_name = {srk_name.name, srk_name.size},
      .ak_public = {ak_public_blob, ak_public_size},
      .ak_private = {ak_private_blob, ak_private_size},
      .ak_name = {ak_name.name, ak_name.size},
      .identity_public = {identity_public_blob, identity_public_size},
      .identity_private = {identity_private_blob, identity_private_size},
      .identity_name = {identity_name.name, identity_name.size},
      .ek_chain_digest = {no_ek_chain, sizeof(no_ek_chain)},
  };
  uint8_t encoded[PBNS_TPM_STORAGE_MAX_SIZE] = {0};
  size_t encoded_size = 0U;
  if (pbns_tpm_storage_encode(&record,
                              (pbns_buffer){encoded, 0U, sizeof(encoded)},
                              &encoded_size) != PBNS_OK) {
    status = EFI_COMPROMISED_DATA;
    goto fail;
  }
  status = PbnsTpmStorageUefiWrite(encoded, encoded_size);
  ZeroMem(encoded, sizeof(encoded));
  ZeroMem(ak_private_blob, sizeof(ak_private_blob));
  ZeroMem(identity_private_blob, sizeof(identity_private_blob));
  ZeroMem(&ak_private, sizeof(ak_private));
  ZeroMem(&identity_private, sizeof(identity_private));
  if (EFI_ERROR(status)) {
    goto fail;
  }
  *Result = context->Capabilities;
  status = expose_identity(context, Identity);
  if (EFI_ERROR(status)) {
    goto fail;
  }
  return EFI_SUCCESS;

fail:
  context_final(context);
  ZeroMem(context, sizeof(*context));
  FreePool(context);
  *Identity = (pbns_identity){0};
  return status;
}

EFI_STATUS EFIAPI PbnsTpmIdentityOpen(pbns_identity *Identity,
                                      pbns_tpm_capability_result *Result) {
  if (Identity == NULL || Result == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Identity = (pbns_identity){0};
  ZeroMem(Result, sizeof(*Result));
  uint8_t encoded[PBNS_TPM_STORAGE_MAX_SIZE] = {0};
  UINTN encoded_size = 0U;
  EFI_STATUS status =
      PbnsTpmStorageUefiRead(encoded, sizeof(encoded), &encoded_size);
  if (EFI_ERROR(status)) {
    ZeroMem(encoded, sizeof(encoded));
    return status;
  }
  pbns_tpm_storage_record record = {0};
  if (pbns_tpm_storage_decode((pbns_view){encoded, encoded_size}, &record) !=
          PBNS_OK ||
      pbns_tpm_storage_validate_names(&record, public_name_from_blob, NULL) !=
          PBNS_OK) {
    ZeroMem(encoded, sizeof(encoded));
    return EFI_COMPROMISED_DATA;
  }
  PBNS_TPM_CONTEXT *context = AllocateZeroPool(sizeof(*context));
  if (context == NULL) {
    ZeroMem(encoded, sizeof(encoded));
    return EFI_OUT_OF_RESOURCES;
  }
  status = context_init(context);
  if (EFI_ERROR(status)) {
    goto fail;
  }
  status = discover_capabilities(context, &context->Capabilities);
  if (EFI_ERROR(status) ||
      context->Capabilities.required.manufacturer != record.manufacturer ||
      context->Capabilities.required.firmware1 != record.firmware1 ||
      context->Capabilities.required.firmware2 != record.firmware2) {
    status = EFI_SECURITY_VIOLATION;
    goto fail;
  }

  TPM2B_PUBLIC ek_template = {0};
  TPM2B_PUBLIC srk_template = {0};
  if (PbnsTpmEndorsementTemplate(&ek_template) != PBNS_OK ||
      PbnsTpmStorageTemplate(&srk_template) != PBNS_OK) {
    status = EFI_SECURITY_VIOLATION;
    goto fail;
  }
  TPM2_HANDLE ek_handle = PBNS_TPM_HANDLE_INVALID;
  TPM2B_PUBLIC ek_public = {0};
  TPM2B_NAME ek_name = {0};
  status = create_primary(context, TPM2_RH_ENDORSEMENT, &ek_template,
                          &ek_handle, &ek_public, &ek_name);
  flush_handle(context, &ek_handle);
  if (EFI_ERROR(status) || !names_equal(&ek_name, record.ek_name) ||
      EFI_ERROR(compare_public_blob(&ek_public, record.ek_public))) {
    status = EFI_SECURITY_VIOLATION;
    goto fail;
  }
  TPM2_HANDLE srk_handle = PBNS_TPM_HANDLE_INVALID;
  TPM2B_PUBLIC srk_public = {0};
  TPM2B_NAME srk_name = {0};
  status = create_primary(context, TPM2_RH_OWNER, &srk_template, &srk_handle,
                          &srk_public, &srk_name);
  if (EFI_ERROR(status) || !names_equal(&srk_name, record.srk_name) ||
      EFI_ERROR(compare_public_blob(&srk_public, record.srk_public))) {
    flush_handle(context, &srk_handle);
    status = EFI_SECURITY_VIOLATION;
    goto fail;
  }
  TPM2B_PRIVATE ak_private = {0};
  TPM2B_PRIVATE identity_private = {0};
  if (pbns_tpm_public_decode(record.ak_public, &context->AkPublic) != PBNS_OK ||
      pbns_tpm_private_decode(record.ak_private, &ak_private) != PBNS_OK ||
      pbns_tpm_public_decode(record.identity_public,
                             &context->IdentityPublic) != PBNS_OK ||
      pbns_tpm_private_decode(record.identity_private, &identity_private) !=
          PBNS_OK) {
    flush_handle(context, &srk_handle);
    status = EFI_COMPROMISED_DATA;
    goto fail;
  }
  TPM2B_NAME loaded_name = {0};
  status = load_child(context, srk_handle, &ak_private, &context->AkPublic,
                      &context->AkHandle, &loaded_name);
  if (!EFI_ERROR(status) && !names_equal(&loaded_name, record.ak_name)) {
    status = EFI_SECURITY_VIOLATION;
  }
  if (!EFI_ERROR(status)) {
    status = read_and_validate(context, context->AkHandle, record.ak_public,
                               record.ak_name, &context->AkPublic);
  }
  if (!EFI_ERROR(status)) {
    status = load_child(context, srk_handle, &identity_private,
                        &context->IdentityPublic, &context->IdentityHandle,
                        &loaded_name);
  }
  if (!EFI_ERROR(status) && !names_equal(&loaded_name, record.identity_name)) {
    status = EFI_SECURITY_VIOLATION;
  }
  if (!EFI_ERROR(status)) {
    status = read_and_validate(context, context->IdentityHandle,
                               record.identity_public, record.identity_name,
                               &context->IdentityPublic);
  }
  flush_handle(context, &srk_handle);
  ZeroMem(&ak_private, sizeof(ak_private));
  ZeroMem(&identity_private, sizeof(identity_private));
  ZeroMem(encoded, sizeof(encoded));
  if (EFI_ERROR(status)) {
    goto fail_no_encoded;
  }
  *Result = context->Capabilities;
  status = expose_identity(context, Identity);
  if (!EFI_ERROR(status)) {
    return EFI_SUCCESS;
  }

fail:
  ZeroMem(encoded, sizeof(encoded));
fail_no_encoded:
  context_final(context);
  ZeroMem(context, sizeof(*context));
  FreePool(context);
  *Identity = (pbns_identity){0};
  return status;
}

EFI_STATUS EFIAPI PbnsTpmIdentityReset(void) {
  return PbnsTpmStorageUefiDelete();
}

static EFI_STATUS marshal_public_area(const TPM2B_PUBLIC *Public,
                                      pbns_buffer *Output) {
  if (Public == NULL || Output == NULL || Output->ptr == NULL ||
      Output->len != 0U || Output->cap == 0U) {
    return EFI_INVALID_PARAMETER;
  }
  size_t written = 0U;
  const EFI_STATUS status =
      encode_public(Public, Output->ptr, Output->cap, &written);
  if (EFI_ERROR(status) || written == 0U) {
    ZeroMem(Output->ptr, Output->cap);
    return status;
  }
  Output->len = written;
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI PbnsTpmIdentityEnrollmentPublic(
    pbns_identity *Identity, pbns_tpm_enrollment_public *Evidence) {
  if (Identity == NULL || Identity->ops != &mIdentityOps ||
      Identity->context == NULL || Evidence == NULL ||
      Evidence->EkPublic.ptr == NULL || Evidence->EkPublic.len != 0U ||
      Evidence->AkPublic.ptr == NULL || Evidence->AkPublic.len != 0U ||
      Evidence->AkName.ptr == NULL || Evidence->AkName.len != 0U ||
      Evidence->EkCertificate.len != 0U ||
      (Evidence->EkCertificate.ptr == NULL &&
       Evidence->EkCertificate.cap != 0U) ||
      (Evidence->EkCertificate.ptr != NULL &&
       (Evidence->EkCertificate.cap == 0U ||
        Evidence->EkCertificate.cap > PBNS_TPM_EK_CERTIFICATE_MAX_SIZE)) ||
      Evidence->IdentityPublic.ptr == NULL ||
      Evidence->IdentityPublic.len != 0U) {
    return EFI_INVALID_PARAMETER;
  }
  PBNS_TPM_CONTEXT *context = Identity->context;
  TPM2B_PUBLIC ek_template = {0};
  TPM2B_PUBLIC ek_public = {0};
  TPM2B_NAME ek_name = {0};
  TPM2_HANDLE ek_handle = PBNS_TPM_HANDLE_INVALID;
  if (PbnsTpmEndorsementTemplate(&ek_template) != PBNS_OK) {
    return EFI_SECURITY_VIOLATION;
  }
  EFI_STATUS status = create_primary(context, TPM2_RH_ENDORSEMENT, &ek_template,
                                     &ek_handle, &ek_public, &ek_name);
  flush_handle(context, &ek_handle);
  TPM2B_NAME ak_name = {0};
  TPM2B_NAME qualified_name = {0};
  if (!EFI_ERROR(status) &&
      Tss2_Sys_ReadPublic(context->Sys, context->AkHandle, NULL,
                          &context->AkPublic, &ak_name, &qualified_name,
                          NULL) != TSS2_RC_SUCCESS) {
    status = EFI_DEVICE_ERROR;
  }
  if (!EFI_ERROR(status)) {
    status = marshal_public_area(&ek_public, &Evidence->EkPublic);
  }
  if (!EFI_ERROR(status)) {
    status = marshal_public_area(&context->AkPublic, &Evidence->AkPublic);
  }
  if (!EFI_ERROR(status)) {
    if (ak_name.size == 0U || ak_name.size > Evidence->AkName.cap) {
      status = EFI_BUFFER_TOO_SMALL;
    } else {
      CopyMem(Evidence->AkName.ptr, ak_name.name, ak_name.size);
      Evidence->AkName.len = ak_name.size;
    }
  }
  if (!EFI_ERROR(status)) {
    status = marshal_public_area(&context->IdentityPublic,
                                 &Evidence->IdentityPublic);
  }
  if (!EFI_ERROR(status) && Evidence->EkCertificate.ptr != NULL) {
    UINTN certificate_size = 0U;
    const EFI_STATUS certificate_status = PbnsTpmEkCertificateRead(
        Evidence->EkCertificate, &certificate_size);
    if (certificate_status == EFI_INVALID_PARAMETER ||
        certificate_status == EFI_BUFFER_TOO_SMALL) {
      status = certificate_status;
    } else if (!EFI_ERROR(certificate_status)) {
      Evidence->EkCertificate.len = certificate_size;
    }
  }
  if (EFI_ERROR(status)) {
    ZeroMem(Evidence->EkPublic.ptr, Evidence->EkPublic.cap);
    ZeroMem(Evidence->AkPublic.ptr, Evidence->AkPublic.cap);
    ZeroMem(Evidence->AkName.ptr, Evidence->AkName.cap);
    if (Evidence->EkCertificate.ptr != NULL) {
      ZeroMem(Evidence->EkCertificate.ptr, Evidence->EkCertificate.cap);
    }
    ZeroMem(Evidence->IdentityPublic.ptr, Evidence->IdentityPublic.cap);
    Evidence->EkPublic.len = 0U;
    Evidence->AkPublic.len = 0U;
    Evidence->AkName.len = 0U;
    Evidence->EkCertificate.len = 0U;
    Evidence->IdentityPublic.len = 0U;
  }
  ZeroMem(&ek_public, sizeof(ek_public));
  ZeroMem(&ek_name, sizeof(ek_name));
  ZeroMem(&ak_name, sizeof(ak_name));
  ZeroMem(&qualified_name, sizeof(qualified_name));
  return status;
}

static bool tpm_quote_retry(void *Context, TSS2_RC Result, size_t Attempt) {
  (void)Context;
  return retry_command_after_delay(Result, Attempt);
}

static TSS2_RC tpm_quote_command(
    void *Context, TPM2_HANDLE AkHandle, const TSS2L_SYS_AUTH_COMMAND *Auth,
    const TPM2B_DATA *QualifyingData, const TPMT_SIG_SCHEME *Scheme,
    const TPML_PCR_SELECTION *Selection, TPM2B_ATTEST *Quoted,
    TPMT_SIGNATURE *Signature) {
  return Tss2_Sys_Quote(Context, AkHandle, Auth, QualifyingData, Scheme,
                        Selection, Quoted, Signature, NULL);
}

EFI_STATUS EFIAPI PbnsTpmIdentityQuote(
    pbns_identity *Identity, pbns_measured_boot_selection Selection,
    const uint8_t QualifyingData[32], pbns_buffer Attestation,
    UINTN *AttestationSize, pbns_buffer Signature, UINTN *SignatureSize,
    UINT32 *CommandResult) {
  if (Identity == NULL || Identity->ops != &mIdentityOps ||
      Identity->context == NULL || AttestationSize == NULL ||
      SignatureSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  PBNS_TPM_CONTEXT *context = Identity->context;
  size_t attestation_size = 0U;
  size_t signature_size = 0U;
  const pbns_status status = pbns_tpm_quote_core(
      context->AkHandle, Selection, QualifyingData, tpm_quote_command,
      context->Sys, tpm_quote_retry, NULL, Attestation, &attestation_size,
      Signature, &signature_size, CommandResult);
  if (status != PBNS_OK) {
    return status == PBNS_ERR_ARGUMENT || status == PBNS_ERR_FORMAT ||
                   status == PBNS_ERR_UNSUPPORTED
               ? EFI_INVALID_PARAMETER
               : EFI_DEVICE_ERROR;
  }
  *AttestationSize = (UINTN)attestation_size;
  *SignatureSize = (UINTN)signature_size;
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI PbnsTpmIdentityCertify(
    pbns_identity *Identity, pbns_view Nonce, pbns_buffer Attestation,
    UINTN *AttestationSize, pbns_buffer Signature, UINTN *SignatureSize,
    UINT32 *CommandResult) {
  if (Identity == NULL || Identity->ops != &mIdentityOps ||
      Identity->context == NULL || Nonce.ptr == NULL || Nonce.len > 64U ||
      Attestation.ptr == NULL || Attestation.len != 0U ||
      AttestationSize == NULL || Signature.ptr == NULL || Signature.len != 0U ||
      SignatureSize == NULL || CommandResult == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *AttestationSize = 0U;
  *SignatureSize = 0U;
  *CommandResult = 0U;
  PBNS_TPM_CONTEXT *context = Identity->context;
  TPM2B_DATA qualifying = {.size = (UINT16)Nonce.len};
  CopyMem(qualifying.buffer, Nonce.ptr, Nonce.len);
  const TPMT_SIG_SCHEME scheme = {
      .scheme = TPM2_ALG_ECDSA,
      .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
  };
  TPM2B_ATTEST attest = {0};
  TPMT_SIGNATURE signature = {0};
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth(2U);
  TSS2_RC rc = TSS2_BASE_RC_GENERAL_FAILURE;
  for (size_t attempt = 0U; attempt < PBNS_TPM_COMMAND_RETRY_LIMIT; ++attempt) {
    ZeroMem(&attest, sizeof(attest));
    ZeroMem(&signature, sizeof(signature));
    rc = Tss2_Sys_Certify(context->Sys, context->IdentityHandle,
                          context->AkHandle, &auth, &qualifying, &scheme,
                          &attest, &signature, NULL);
    if (!retry_command_after_delay(rc, attempt)) {
      break;
    }
  }
  *CommandResult = (UINT32)rc;
  ZeroMem(&qualifying, sizeof(qualifying));
  if (rc != TSS2_RC_SUCCESS || Attestation.cap < attest.size) {
    ZeroMem(&attest, sizeof(attest));
    ZeroMem(&signature, sizeof(signature));
    return EFI_DEVICE_ERROR;
  }
  const UINTN attest_size = attest.size;
  CopyMem(Attestation.ptr, attest.attestationData, attest_size);
  size_t raw_size = 0U;
  const pbns_status raw_status =
      signature_marshaled(&signature, Signature, &raw_size);
  ZeroMem(&attest, sizeof(attest));
  ZeroMem(&signature, sizeof(signature));
  if (raw_status != PBNS_OK) {
    ZeroMem(Attestation.ptr, Attestation.cap);
    return EFI_SECURITY_VIOLATION;
  }
  *AttestationSize = attest_size;
  *SignatureSize = raw_size;
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI PbnsTpmIdentityActivateCredential(
    pbns_identity *Identity, pbns_view CredentialBlob, pbns_view Secret,
    pbns_buffer Output, UINTN *OutputSize, UINT32 *CommandResult) {
  if (Identity == NULL || Identity->ops != &mIdentityOps ||
      Identity->context == NULL || CredentialBlob.ptr == NULL ||
      CredentialBlob.len == 0U || Secret.ptr == NULL || Secret.len == 0U ||
      Output.ptr == NULL || Output.len != 0U || OutputSize == NULL ||
      CommandResult == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *OutputSize = 0U;
  *CommandResult = 0U;
  TPM2B_ID_OBJECT credential = {0};
  TPM2B_ENCRYPTED_SECRET secret = {0};
  size_t credential_offset = 0U;
  size_t secret_offset = 0U;
  const TSS2_RC credential_rc = Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(
      CredentialBlob.ptr, CredentialBlob.len, &credential_offset, &credential);
  const TSS2_RC secret_rc = Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(
      Secret.ptr, Secret.len, &secret_offset, &secret);
  if (credential_rc != TSS2_RC_SUCCESS ||
      credential_offset != CredentialBlob.len || credential.size == 0U ||
      secret_rc != TSS2_RC_SUCCESS || secret_offset != Secret.len ||
      secret.size == 0U) {
    ZeroMem(&credential, sizeof(credential));
    ZeroMem(&secret, sizeof(secret));
    return EFI_SECURITY_VIOLATION;
  }
  PBNS_TPM_CONTEXT *context = Identity->context;
  TPM2B_PUBLIC ek_template = {0};
  if (PbnsTpmEndorsementTemplate(&ek_template) != PBNS_OK) {
    ZeroMem(&credential, sizeof(credential));
    ZeroMem(&secret, sizeof(secret));
    return EFI_SECURITY_VIOLATION;
  }
  TPM2_HANDLE ek_handle = PBNS_TPM_HANDLE_INVALID;
  TPM2B_PUBLIC ek_public = {0};
  TPM2B_NAME ek_name = {0};
  EFI_STATUS status = create_primary(context, TPM2_RH_ENDORSEMENT, &ek_template,
                                     &ek_handle, &ek_public, &ek_name);
  if (EFI_ERROR(status)) {
    ZeroMem(&credential, sizeof(credential));
    ZeroMem(&secret, sizeof(secret));
    return status;
  }
  TPM2B_DIGEST result = {0};
  const TSS2L_SYS_AUTH_COMMAND auth = password_auth(2U);
  TSS2_RC rc = TSS2_BASE_RC_GENERAL_FAILURE;
  for (size_t attempt = 0U; attempt < PBNS_TPM_COMMAND_RETRY_LIMIT; ++attempt) {
    ZeroMem(&result, sizeof(result));
    rc =
        Tss2_Sys_ActivateCredential(context->Sys, context->AkHandle, ek_handle,
                                    &auth, &credential, &secret, &result, NULL);
    if (!retry_command_after_delay(rc, attempt)) {
      break;
    }
  }
  *CommandResult = (UINT32)rc;
  flush_handle(context, &ek_handle);
  ZeroMem(&credential, sizeof(credential));
  ZeroMem(&secret, sizeof(secret));
  if (rc != TSS2_RC_SUCCESS || Output.cap < result.size) {
    ZeroMem(&result, sizeof(result));
    return EFI_DEVICE_ERROR;
  }
  CopyMem(Output.ptr, result.buffer, result.size);
  *OutputSize = result.size;
  ZeroMem(&result, sizeof(result));
  return EFI_SUCCESS;
}

static EFI_STATUS read_baseline_pcrs_once(PBNS_TPM_CONTEXT *Context,
                                          uint8_t Digests[4][32],
                                          uint32_t *UpdateCounter) {
  const TPML_PCR_SELECTION selection = {
      .count = 1U,
      .pcrSelections = {{.hash = TPM2_ALG_SHA256,
                         .sizeofSelect = 3U,
                         .pcrSelect = {0x95U, 0U, 0U, 0U}}},
  };
  TPML_PCR_SELECTION selection_out = {0};
  TPML_DIGEST values = {0};
  UINT32 update_counter = 0U;
  const TSS2_RC result =
      Tss2_Sys_PCR_Read(Context->Sys, NULL, &selection, &update_counter,
                        &selection_out, &values, NULL);
  if (result != TSS2_RC_SUCCESS || selection_out.count != 1U ||
      selection_out.pcrSelections[0].hash != TPM2_ALG_SHA256 ||
      selection_out.pcrSelections[0].sizeofSelect != 3U ||
      selection_out.pcrSelections[0].pcrSelect[0] != 0x95U ||
      selection_out.pcrSelections[0].pcrSelect[1] != 0U ||
      selection_out.pcrSelections[0].pcrSelect[2] != 0U || values.count != 4U) {
    ZeroMem(&values, sizeof(values));
    return EFI_DEVICE_ERROR;
  }
  for (UINT32 index = 0U; index < values.count; ++index) {
    if (values.digests[index].size != 32U) {
      ZeroMem(&values, sizeof(values));
      ZeroMem(Digests, sizeof(uint8_t[4][32]));
      return EFI_SECURITY_VIOLATION;
    }
    CopyMem(Digests[index], values.digests[index].buffer, 32U);
  }
  *UpdateCounter = update_counter;
  ZeroMem(&values, sizeof(values));
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI PbnsTpmReadBaselinePcrs(uint8_t Digests[4][32],
                                          uint32_t *UpdateCounter) {
  if (Digests == NULL || UpdateCounter == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  ZeroMem(Digests, sizeof(uint8_t[4][32]));
  *UpdateCounter = 0U;
  PBNS_TPM_CONTEXT context = {0};
  EFI_STATUS status = context_init(&context);
  if (EFI_ERROR(status)) {
    return status;
  }
  uint8_t first[4][32] = {{0}};
  uint8_t second[4][32] = {{0}};
  uint32_t first_counter = 0U;
  uint32_t second_counter = 0U;
  status = read_baseline_pcrs_once(&context, first, &first_counter);
  if (!EFI_ERROR(status)) {
    status = read_baseline_pcrs_once(&context, second, &second_counter);
  }
  context_final(&context);
  if (EFI_ERROR(status)) {
    ZeroMem(first, sizeof(first));
    ZeroMem(second, sizeof(second));
    return status;
  }
  const pbns_status stability = pbns_measured_boot_check_pcr_stability(
      (pbns_view){&first[0][0], sizeof(first)}, first_counter,
      (pbns_view){&second[0][0], sizeof(second)}, second_counter);
  if (stability != PBNS_OK) {
    ZeroMem(first, sizeof(first));
    ZeroMem(second, sizeof(second));
    return EFI_NOT_READY;
  }
  CopyMem(Digests, second, sizeof(second));
  *UpdateCounter = second_counter;
  ZeroMem(first, sizeof(first));
  ZeroMem(second, sizeof(second));
  return EFI_SUCCESS;
}
