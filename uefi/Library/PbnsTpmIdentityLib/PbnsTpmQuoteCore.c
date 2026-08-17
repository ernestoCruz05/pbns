#include "PbnsTpmQuoteCore.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/tpm_profile.h"

static void wipe(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  for (size_t index = 0U; bytes != NULL && index < length; ++index) {
    bytes[index] = 0U;
  }
}

pbns_status pbns_tpm_quote_core(
    TPM2_HANDLE ak_handle, pbns_measured_boot_selection selection,
    const uint8_t qualifying_data[32], pbns_tpm_quote_command_fn command,
    void *command_context, pbns_tpm_quote_retry_fn retry,
    void *retry_context, pbns_buffer quote, size_t *quote_size,
    pbns_buffer signature, size_t *signature_size, uint32_t *command_result) {
  if (quote_size != NULL) {
    *quote_size = 0U;
  }
  if (signature_size != NULL) {
    *signature_size = 0U;
  }
  if (command_result != NULL) {
    *command_result = 0U;
  }
  if (quote.ptr != NULL && quote.len == 0U) {
    wipe(quote.ptr, quote.cap);
  }
  if (signature.ptr != NULL && signature.len == 0U) {
    wipe(signature.ptr, signature.cap);
  }
  if (ak_handle == 0U || selection.items == NULL || selection.count == 0U ||
      selection.count > PBNS_MEASURED_BOOT_SELECTION_MAX_COUNT ||
      qualifying_data == NULL || command == NULL || retry == NULL ||
      quote.ptr == NULL || quote.len != 0U || quote_size == NULL ||
      signature.ptr == NULL ||
      signature.len != 0U || signature_size == NULL || command_result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  TPML_PCR_SELECTION pcr = {
      .count = 1U,
      .pcrSelections = {{.hash = TPM2_ALG_SHA256, .sizeofSelect = 3U}},
  };
  uint8_t previous = 0U;
  for (size_t index = 0U; index < selection.count; ++index) {
    const pbns_measured_boot_selection_item item = selection.items[index];
    if (item.hash_algorithm != PBNS_TPM_ALG_SHA256 || item.pcr_index >= 24U ||
        (index > 0U && item.pcr_index <= previous)) {
      wipe(&pcr, sizeof(pcr));
      return item.hash_algorithm != PBNS_TPM_ALG_SHA256
                 ? PBNS_ERR_UNSUPPORTED
                 : PBNS_ERR_FORMAT;
    }
    pcr.pcrSelections[0].pcrSelect[item.pcr_index / 8U] |=
        (uint8_t)(1U << (item.pcr_index % 8U));
    previous = item.pcr_index;
  }
  TSS2L_SYS_AUTH_COMMAND auth = {0};
  auth.count = 1U;
  auth.auths[0].sessionHandle = TPM2_RS_PW;
  TPM2B_DATA qualifying = {.size = 32U};
  memcpy(qualifying.buffer, qualifying_data, sizeof(qualifying_data[0]) * 32U);
  const TPMT_SIG_SCHEME scheme = {
      .scheme = TPM2_ALG_ECDSA,
      .details = {.ecdsa = {.hashAlg = TPM2_ALG_SHA256}},
  };
  TPM2B_ATTEST quoted = {0};
  TPMT_SIGNATURE tpm_signature = {0};
  TSS2_RC rc = TSS2_BASE_RC_GENERAL_FAILURE;
  for (size_t attempt = 0U; attempt < PBNS_TPM_COMMAND_RETRY_LIMIT;
       ++attempt) {
    wipe(&quoted, sizeof(quoted));
    wipe(&tpm_signature, sizeof(tpm_signature));
    wipe(quote.ptr, quote.cap);
    wipe(signature.ptr, signature.cap);
    *quote_size = 0U;
    *signature_size = 0U;
    rc = command(command_context, ak_handle, &auth, &qualifying, &scheme, &pcr,
                 &quoted, &tpm_signature);
    if (!retry(retry_context, rc, attempt)) {
      break;
    }
  }
  *command_result = (uint32_t)rc;
  wipe(&auth, sizeof(auth));
  wipe(&qualifying, sizeof(qualifying));
  wipe(&pcr, sizeof(pcr));
  if (rc != TSS2_RC_SUCCESS || quoted.size == 0U ||
      quote.cap < quoted.size) {
    wipe(&quoted, sizeof(quoted));
    wipe(&tpm_signature, sizeof(tpm_signature));
    return rc == TSS2_RC_SUCCESS ? PBNS_ERR_LIMIT : PBNS_ERR_CRYPTO;
  }
  memcpy(quote.ptr, quoted.attestationData, quoted.size);
  *quote_size = quoted.size;
  const pbns_status status =
      pbns_tpm_signature_encode(&tpm_signature, signature, signature_size);
  wipe(&quoted, sizeof(quoted));
  wipe(&tpm_signature, sizeof(tpm_signature));
  if (status != PBNS_OK) {
    wipe(quote.ptr, quote.cap);
    wipe(signature.ptr, signature.cap);
    *quote_size = 0U;
    *signature_size = 0U;
  }
  return status;
}
