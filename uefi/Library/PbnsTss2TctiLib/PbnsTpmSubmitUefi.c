#include "PbnsTpmSubmitUefi.h"

#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>

typedef struct PBNS_TPM_SUBMIT_UEFI_CONTEXT {
  EFI_TCG2_PROTOCOL *Protocol;
} PBNS_TPM_SUBMIT_UEFI_CONTEXT;

_Static_assert(sizeof(PBNS_TPM_SUBMIT_UEFI_CONTEXT) <=
                   PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE,
               "submit storage too small");

static pbns_status submit_command(void *context, pbns_view input,
                                  pbns_buffer output, size_t *output_length) {
  PBNS_TPM_SUBMIT_UEFI_CONTEXT *submit_context = context;
  if (submit_context == NULL || submit_context->Protocol == NULL ||
      input.ptr == NULL || input.len == 0U || input.len > UINT32_MAX ||
      output.ptr == NULL || output.len != 0U || output.cap == 0U ||
      output.cap > PBNS_TPM_SUBMIT_RESPONSE_MAX || output.cap > UINT32_MAX ||
      output_length == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  UINT8 command[PBNS_TPM_SUBMIT_RESPONSE_MAX] = {0};
  if (input.len > sizeof(command)) {
    return PBNS_ERR_LIMIT;
  }
  ZeroMem(output.ptr, output.cap);
  *output_length = 0U;
  CopyMem(command, input.ptr, input.len);
  const EFI_STATUS status = submit_context->Protocol->SubmitCommand(
      submit_context->Protocol, (UINT32)input.len, command, (UINT32)output.cap,
      output.ptr);
  ZeroMem(command, sizeof(command));
  if (EFI_ERROR(status)) {
    return PBNS_ERR_IO;
  }
  return pbns_tpm_response_size(output.ptr, output.cap, output_length);
}

pbns_status
pbns_tpm_submit_uefi_init(uint8_t storage[PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE],
                          pbns_tpm_submit *submit, void **submit_context) {
  if (storage == NULL || submit == NULL || submit_context == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  ZeroMem(storage, PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE);
  PBNS_TPM_SUBMIT_UEFI_CONTEXT *context =
      (PBNS_TPM_SUBMIT_UEFI_CONTEXT *)(void *)storage;
  const EFI_STATUS status = gBS->LocateProtocol(&gEfiTcg2ProtocolGuid, NULL,
                                                (VOID **)&context->Protocol);
  if (EFI_ERROR(status) || context->Protocol == NULL) {
    ZeroMem(storage, PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE);
    return PBNS_ERR_UNSUPPORTED;
  }
  *submit = submit_command;
  *submit_context = context;
  return PBNS_OK;
}

void pbns_tpm_submit_uefi_final(
    uint8_t storage[PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE]) {
  if (storage != NULL) {
    ZeroMem(storage, PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE);
  }
}
