#include "PbnsTpmQuoteCore.h"
#include "pbns/tpm_profile.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct fake_quote {
  size_t calls;
  TPM2_HANDLE handle;
  uint8_t qualifying[32];
  TPMT_SIG_SCHEME scheme;
  TPML_PCR_SELECTION selection;
  TSS2_RC results[PBNS_TPM_COMMAND_RETRY_LIMIT];
  size_t result_count;
  size_t retry_calls;
  size_t retry_attempts[PBNS_TPM_COMMAND_RETRY_LIMIT];
  size_t delays[PBNS_TPM_COMMAND_RETRY_LIMIT];
  size_t delay_count;
} fake_quote;

static TSS2_RC quote_command(void *context, TPM2_HANDLE handle,
                             const TSS2L_SYS_AUTH_COMMAND *auth,
                             const TPM2B_DATA *qualifying,
                             const TPMT_SIG_SCHEME *scheme,
                             const TPML_PCR_SELECTION *selection,
                             TPM2B_ATTEST *quoted,
                             TPMT_SIGNATURE *signature) {
  fake_quote *fake = context;
  ++fake->calls;
  fake->handle = handle;
  assert(auth->count == 1U && auth->auths[0].sessionHandle == TPM2_RS_PW);
  assert(qualifying->size == 32U);
  memcpy(fake->qualifying, qualifying->buffer, sizeof(fake->qualifying));
  fake->scheme = *scheme;
  fake->selection = *selection;
  const size_t result_index = fake->calls - 1U;
  const TSS2_RC result = result_index < fake->result_count
                             ? fake->results[result_index]
                             : TSS2_RC_SUCCESS;
  if (result != TSS2_RC_SUCCESS) {
    memset(quoted, 0xa5, sizeof(*quoted));
    memset(signature, 0xa5, sizeof(*signature));
    return result;
  }
  static const uint8_t attest[] = "TPMS_ATTEST";
  quoted->size = sizeof(attest) - 1U;
  memcpy(quoted->attestationData, attest, quoted->size);
  signature->sigAlg = TPM2_ALG_ECDSA;
  signature->signature.ecdsa.hash = TPM2_ALG_SHA256;
  signature->signature.ecdsa.signatureR.size = 32U;
  signature->signature.ecdsa.signatureS.size = 32U;
  memset(signature->signature.ecdsa.signatureR.buffer, 0x51,
         signature->signature.ecdsa.signatureR.size);
  memset(signature->signature.ecdsa.signatureS.buffer, 0x52,
         signature->signature.ecdsa.signatureS.size);
  return TSS2_RC_SUCCESS;
}

static bool retry_seam(void *context, TSS2_RC result, size_t attempt) {
  fake_quote *fake = context;
  fake->retry_attempts[fake->retry_calls++] = attempt;
  size_t delay = 0U;
  if (!pbns_tpm_command_retry_delay_us((uint32_t)result, attempt, &delay)) {
    return false;
  }
  fake->delays[fake->delay_count++] = delay;
  return true;
}

static void assert_zero(const uint8_t *bytes, size_t size) {
  for (size_t index = 0U; index < size; ++index) {
    assert(bytes[index] == 0U);
  }
}

int main(void) {
  const pbns_measured_boot_selection_item items[] = {
      {PBNS_TPM_ALG_SHA256, 0U},
      {PBNS_TPM_ALG_SHA256, 2U},
      {PBNS_TPM_ALG_SHA256, 7U},
  };
  uint8_t qualifying[32] = {0};
  memset(qualifying, 0x33, sizeof(qualifying));
  uint8_t quote[128] = {0};
  uint8_t signature[128] = {0};
  size_t quote_size = 0U;
  size_t signature_size = 0U;
  uint32_t command_result = 0U;
  fake_quote fake = {0};
  assert(pbns_tpm_quote_core(
             UINT32_C(0x81000042),
             (pbns_measured_boot_selection){items, 3U}, qualifying,
             quote_command, &fake, retry_seam, &fake,
             (pbns_buffer){quote, 0U, sizeof(quote)},
             &quote_size,
             (pbns_buffer){signature, 0U, sizeof(signature)}, &signature_size,
             &command_result) == PBNS_OK);
  assert(fake.calls == 1U && fake.handle == UINT32_C(0x81000042));
  assert(memcmp(fake.qualifying, qualifying, sizeof(qualifying)) == 0);
  assert(fake.scheme.scheme == TPM2_ALG_ECDSA &&
         fake.scheme.details.ecdsa.hashAlg == TPM2_ALG_SHA256);
  assert(fake.selection.count == 1U &&
         fake.selection.pcrSelections[0].hash == TPM2_ALG_SHA256 &&
         fake.selection.pcrSelections[0].sizeofSelect == 3U);
  assert(fake.selection.pcrSelections[0].pcrSelect[0] == 0x85U);
  assert(quote_size == 11U && memcmp(quote, "TPMS_ATTEST", quote_size) == 0);
  assert(signature_size > 64U && command_result == TSS2_RC_SUCCESS);

  memset(quote, 0xa5, sizeof(quote));
  memset(signature, 0xa5, sizeof(signature));
  fake = (fake_quote){.results = {TSS2_SYS_RC_BAD_VALUE}, .result_count = 1U};
  assert(pbns_tpm_quote_core(
             UINT32_C(0x81000042),
             (pbns_measured_boot_selection){items, 3U}, qualifying,
             quote_command, &fake, retry_seam, &fake,
             (pbns_buffer){quote, 0U, sizeof(quote)},
             &quote_size,
             (pbns_buffer){signature, 0U, sizeof(signature)}, &signature_size,
             &command_result) == PBNS_ERR_CRYPTO);
  assert(quote_size == 0U && signature_size == 0U &&
         command_result == TSS2_SYS_RC_BAD_VALUE);
  assert_zero(quote, sizeof(quote));
  assert_zero(signature, sizeof(signature));

  memset(quote, 0xa5, sizeof(quote));
  memset(signature, 0xa5, sizeof(signature));
  fake = (fake_quote){
      .results = {TPM2_RC_RETRY, TPM2_RC_YIELDED, TSS2_RC_SUCCESS},
      .result_count = 3U,
  };
  assert(pbns_tpm_quote_core(
             UINT32_C(0x81000042),
             (pbns_measured_boot_selection){items, 3U}, qualifying,
             quote_command, &fake, retry_seam, &fake,
             (pbns_buffer){quote, 0U, sizeof(quote)}, &quote_size,
             (pbns_buffer){signature, 0U, sizeof(signature)}, &signature_size,
             &command_result) == PBNS_OK);
  assert(fake.calls == 3U && fake.retry_calls == 3U);
  assert(fake.retry_attempts[0] == 0U && fake.retry_attempts[1] == 1U &&
         fake.retry_attempts[2] == 2U);
  assert(fake.delay_count == 2U &&
         fake.delays[0] == PBNS_TPM_COMMAND_RETRY_STALL_US &&
         fake.delays[1] == 2U * PBNS_TPM_COMMAND_RETRY_STALL_US);
  assert(quote_size == 11U && signature_size > 64U);

  memset(quote, 0xa5, sizeof(quote));
  memset(signature, 0xa5, sizeof(signature));
  fake = (fake_quote){
      .results = {TPM2_RC_RETRY, TPM2_RC_YIELDED, TPM2_RC_RETRY},
      .result_count = 3U,
  };
  assert(pbns_tpm_quote_core(
             UINT32_C(0x81000042),
             (pbns_measured_boot_selection){items, 3U}, qualifying,
             quote_command, &fake, retry_seam, &fake,
             (pbns_buffer){quote, 0U, sizeof(quote)}, &quote_size,
             (pbns_buffer){signature, 0U, sizeof(signature)}, &signature_size,
             &command_result) == PBNS_ERR_CRYPTO);
  assert(fake.calls == PBNS_TPM_COMMAND_RETRY_LIMIT &&
         fake.retry_calls == PBNS_TPM_COMMAND_RETRY_LIMIT &&
         fake.delay_count == PBNS_TPM_COMMAND_RETRY_LIMIT - 1U);
  assert(quote_size == 0U && signature_size == 0U &&
         command_result == TPM2_RC_RETRY);
  assert_zero(quote, sizeof(quote));
  assert_zero(signature, sizeof(signature));

  const pbns_measured_boot_selection_item wrong[] = {{TPM2_ALG_SHA1, 0U}};
  memset(quote, 0xa5, sizeof(quote));
  memset(signature, 0xa5, sizeof(signature));
  assert(pbns_tpm_quote_core(
             UINT32_C(0x81000042),
             (pbns_measured_boot_selection){wrong, 1U}, qualifying,
             quote_command, &fake, retry_seam, &fake,
             (pbns_buffer){quote, 0U, sizeof(quote)},
             &quote_size,
             (pbns_buffer){signature, 0U, sizeof(signature)}, &signature_size,
             &command_result) == PBNS_ERR_UNSUPPORTED);
  assert_zero(quote, sizeof(quote));
  assert_zero(signature, sizeof(signature));
  return EXIT_SUCCESS;
}
