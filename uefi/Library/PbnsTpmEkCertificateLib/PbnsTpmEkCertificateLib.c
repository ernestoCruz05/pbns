#include "PbnsTpmEkCertificateInternal.h"

#include <Library/BaseMemoryLib.h>
#include <Library/Tpm2CommandLib.h>

#include <stdbool.h>

#define PBNS_TPM_NV_PUBLIC_WIRE_SIZE 14U

static TPMA_NV expected_attributes(void) {
  return (TPMA_NV){
      .TPMA_NV_PPWRITE = 1U,
      .TPMA_NV_WRITEDEFINE = 1U,
      .TPMA_NV_PPREAD = 1U,
      .TPMA_NV_OWNERREAD = 1U,
      .TPMA_NV_AUTHREAD = 1U,
      .TPMA_NV_NO_DA = 1U,
      .TPMA_NV_WRITTEN = 1U,
      .TPMA_NV_PLATFORMCREATE = 1U,
  };
}

static bool public_profile_valid(const TPM2B_NV_PUBLIC *value) {
  const TPMA_NV expected = expected_attributes();
  return value != NULL && value->size == PBNS_TPM_NV_PUBLIC_WIRE_SIZE &&
         value->nvPublic.nvIndex == PBNS_TPM_EK_CERTIFICATE_NV_INDEX &&
         value->nvPublic.nameAlg == TPM_ALG_SHA256 &&
         CompareMem(&value->nvPublic.attributes, &expected, sizeof(expected)) ==
             0 &&
         value->nvPublic.authPolicy.size == 0U && value->nvPublic.dataSize > 0U;
}

static bool public_values_equal(const TPM2B_NV_PUBLIC *first,
                                const TPM2B_NV_PUBLIC *second) {
  return first->size == second->size &&
         first->nvPublic.nvIndex == second->nvPublic.nvIndex &&
         first->nvPublic.nameAlg == second->nvPublic.nameAlg &&
         CompareMem(&first->nvPublic.attributes, &second->nvPublic.attributes,
                    sizeof(first->nvPublic.attributes)) == 0 &&
         first->nvPublic.authPolicy.size == second->nvPublic.authPolicy.size &&
         first->nvPublic.dataSize == second->nvPublic.dataSize;
}

static pbns_status fail_with_zero(pbns_buffer output, size_t *written,
                                  pbns_status status) {
  ZeroMem(output.ptr, output.cap);
  *written = 0U;
  return status;
}

pbns_status PbnsTpmEkCertificateReadWithCommands(
    const PBNS_TPM_EK_CERTIFICATE_COMMANDS *commands, pbns_buffer output,
    size_t *written) {
  if (written != NULL) {
    *written = 0U;
  }
  const bool output_valid = output.ptr != NULL && output.len == 0U &&
                            output.cap > 0U &&
                            output.cap <= PBNS_TPM_EK_CERTIFICATE_MAX_SIZE;
  if (output_valid) {
    ZeroMem(output.ptr, output.cap);
  }
  if (commands == NULL || commands->NvReadPublic == NULL ||
      commands->NvRead == NULL || !output_valid || written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }

  TPM2B_NV_PUBLIC initial_public = {0};
  TPM2B_NAME initial_name = {0};
  EFI_STATUS status = commands->NvReadPublic(commands->Context,
                                             PBNS_TPM_EK_CERTIFICATE_NV_INDEX,
                                             &initial_public, &initial_name);
  if (status == EFI_NOT_FOUND) {
    return PBNS_OK;
  }
  if (EFI_ERROR(status)) {
    return PBNS_ERR_IO;
  }
  if (!public_profile_valid(&initial_public)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  const size_t certificate_size = initial_public.nvPublic.dataSize;
  if (certificate_size > PBNS_TPM_EK_CERTIFICATE_MAX_SIZE) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (certificate_size > output.cap) {
    return PBNS_ERR_LIMIT;
  }

  TPMS_AUTH_COMMAND auth = {.sessionHandle = TPM_RS_PW};
  size_t offset = 0U;
  while (offset < certificate_size) {
    size_t requested = certificate_size - offset;
    if (requested > MAX_DIGEST_BUFFER) {
      requested = MAX_DIGEST_BUFFER;
    }
    TPM2B_MAX_BUFFER chunk = {0};
    status = commands->NvRead(commands->Context, TPM_RH_OWNER,
                              PBNS_TPM_EK_CERTIFICATE_NV_INDEX, &auth,
                              (UINT16)requested, (UINT16)offset, &chunk);
    if (EFI_ERROR(status) || chunk.size != requested) {
      ZeroMem(&chunk, sizeof(chunk));
      return fail_with_zero(output, written, PBNS_ERR_IO);
    }
    CopyMem(output.ptr + offset, chunk.buffer, requested);
    offset += requested;
    ZeroMem(&chunk, sizeof(chunk));
  }

  TPM2B_NV_PUBLIC final_public = {0};
  TPM2B_NAME final_name = {0};
  status = commands->NvReadPublic(commands->Context,
                                  PBNS_TPM_EK_CERTIFICATE_NV_INDEX,
                                  &final_public, &final_name);
  if (EFI_ERROR(status)) {
    return fail_with_zero(output, written, PBNS_ERR_IO);
  }
  if (!public_profile_valid(&final_public) ||
      !public_values_equal(&initial_public, &final_public)) {
    return fail_with_zero(output, written, PBNS_ERR_AUTHENTICATION);
  }
  *written = certificate_size;
  return PBNS_OK;
}

static EFI_STATUS EFIAPI native_read_public(void *context,
                                            TPMI_RH_NV_INDEX nv_index,
                                            TPM2B_NV_PUBLIC *nv_public,
                                            TPM2B_NAME *nv_name) {
  (void)context;
  return Tpm2NvReadPublic(nv_index, nv_public, nv_name);
}

static EFI_STATUS EFIAPI native_read(void *context, TPMI_RH_NV_AUTH auth_handle,
                                     TPMI_RH_NV_INDEX nv_index,
                                     TPMS_AUTH_COMMAND *auth_session,
                                     UINT16 size, UINT16 offset,
                                     TPM2B_MAX_BUFFER *out_data) {
  (void)context;
  return Tpm2NvRead(auth_handle, nv_index, auth_session, size, offset,
                    out_data);
}

EFI_STATUS EFIAPI PbnsTpmEkCertificateRead(pbns_buffer output, UINTN *written) {
  if (written == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *written = 0U;
  const PBNS_TPM_EK_CERTIFICATE_COMMANDS commands = {
      .NvReadPublic = native_read_public,
      .NvRead = native_read,
  };
  size_t certificate_size = 0U;
  const pbns_status status = PbnsTpmEkCertificateReadWithCommands(
      &commands, output, &certificate_size);
  if (status == PBNS_OK) {
    *written = certificate_size;
    return EFI_SUCCESS;
  }
  if (status == PBNS_ERR_LIMIT) {
    return EFI_BUFFER_TOO_SMALL;
  }
  if (status == PBNS_ERR_AUTHENTICATION) {
    return EFI_SECURITY_VIOLATION;
  }
  if (status == PBNS_ERR_ARGUMENT) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_DEVICE_ERROR;
}
