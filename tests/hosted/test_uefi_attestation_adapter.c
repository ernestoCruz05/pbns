#include "PbnsAttestationClientLib.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/sha256.h>

#define TEST_KEY_MAGIC UINT32_C(0x61747473)

static size_t reset_calls;
static bool fail_identity_key;
static pbns_identity *expected_identity;
static PBNS_ATTESTATION_CLIENT_ADAPTER *expected_adapter;
static const pbns_cose_key *expected_challenge_key;
static const pbns_cose_key *expected_recipient_key;
static const pbns_cose_key *expected_receipt_key;

static bool all_zero(const void *value, size_t size) {
  const uint8_t *bytes = value;
  for (size_t index = 0U; index < size; ++index) {
    if (bytes[index] != 0U) {
      return false;
    }
  }
  return true;
}

pbns_status pbns_cose_key_from_identity(pbns_cose_key *key,
                                        const pbns_identity *identity) {
  assert(expected_adapter != NULL);
  assert(key == &expected_adapter->IdentityKey);
  assert(all_zero(expected_adapter, sizeof(*expected_adapter)));
  if (fail_identity_key) {
    key->owned_secret[0] = UINT8_C(0xa5);
    return PBNS_ERR_CRYPTO;
  }
  *key = (pbns_cose_key){
      .magic = TEST_KEY_MAGIC,
      .identity = identity,
      .native = key,
  };
  memset(key->owned_secret, 0x5a, sizeof(key->owned_secret));
  return PBNS_OK;
}

void pbns_cose_key_reset(pbns_cose_key *key) {
  ++reset_calls;
  memset(key, 0, sizeof(*key));
}

pbns_status pbns_cose_uefi_sign1_verify(const pbns_cose_key *key,
                                        pbns_view message,
                                        pbns_view external_aad,
                                        pbns_view *payload) {
  (void)external_aad;
  assert(key == expected_receipt_key);
  *payload = message;
  return PBNS_OK;
}

pbns_status pbns_cose_uefi_sign1_verify_profile(
    const pbns_cose_key *key, pbns_view message, pbns_view external_aad,
    pbns_view expected_kid, pbns_view *payload) {
  (void)external_aad;
  (void)expected_kid;
  assert(key == expected_challenge_key);
  *payload = message;
  return PBNS_OK;
}

pbns_status pbns_cose_uefi_sign1_sign(const pbns_cose_key *key,
                                      pbns_view payload, pbns_view external_aad,
                                      pbns_buffer output, size_t *written) {
  (void)external_aad;
  assert(key->magic == TEST_KEY_MAGIC && key->identity == expected_identity);
  assert(key->native == key);
  assert(output.cap >= payload.len);
  memcpy(output.ptr, payload.ptr, payload.len);
  *written = payload.len;
  return PBNS_OK;
}

pbns_status pbns_cose_uefi_attestation_encrypt_for_recipient(
    const pbns_identity *random_identity, const pbns_cose_key *recipient_key,
    pbns_view recipient_key_id, pbns_view plaintext, pbns_view external_aad,
    pbns_buffer output, size_t *written) {
  (void)recipient_key_id;
  (void)external_aad;
  assert(random_identity == expected_identity);
  assert(recipient_key == expected_recipient_key);
  assert(output.cap >= plaintext.len);
  memcpy(output.ptr, plaintext.ptr, plaintext.len);
  *written = plaintext.len;
  return PBNS_OK;
}

int mbedtls_sha256(const unsigned char *input, size_t input_size,
                   unsigned char output[32], int is224) {
  assert(input != NULL && input_size == 1U && is224 == 0);
  memset(output, input[0], 32U);
  return 0;
}

EFI_STATUS EFIAPI PbnsTpmIdentityQuote(
    pbns_identity *identity, pbns_measured_boot_selection selection,
    const uint8_t qualifying_data[32], pbns_buffer attestation,
    UINTN *attestation_size, pbns_buffer signature, UINTN *signature_size,
    UINT32 *command_result) {
  (void)selection;
  assert(identity == expected_identity && qualifying_data != NULL);
  assert(attestation.cap >= 1U && signature.cap >= 1U);
  attestation.ptr[0] = UINT8_C(0x41);
  signature.ptr[0] = UINT8_C(0x53);
  *attestation_size = 1U;
  *signature_size = 1U;
  *command_result = UINT32_C(0x12345678);
  return EFI_SUCCESS;
}

static void assert_clean_template(const pbns_attestation_submission *value) {
  assert(value->inventory_report == NULL && value->measured_boot == NULL);
  assert(value->ak_name.ptr == NULL && value->ak_name.len == 0U);
  assert(value->ak_reference.ptr == NULL && value->ak_reference.len == 0U);
  assert(value->consume == NULL && value->send_data == NULL);
  assert(value->consume_context == NULL && value->send_context == NULL);
  assert(value->consume_context_region.ptr == NULL &&
         value->consume_context_region.len == 0U);
  assert(value->send_context_region.ptr == NULL &&
         value->send_context_region.len == 0U);
  assert(value->evidence_digest.ptr == NULL && value->evidence_digest.len == 0U &&
         value->evidence_digest.cap == 0U);
}

static void test_initializer_binds_complete_owned_adapter(void) {
  pbns_identity identity = {0};
  pbns_cose_key challenge = {.magic = 1U};
  pbns_cose_key recipient = {.magic = 2U};
  pbns_cose_key receipt = {.magic = 3U};
  expected_identity = &identity;
  expected_challenge_key = &challenge;
  expected_recipient_key = &recipient;
  expected_receipt_key = &receipt;
  PBNS_ATTESTATION_CLIENT_ADAPTER adapter = {0};
  adapter.TpmCommandResult = UINT32_MAX;
  expected_adapter = &adapter;

  assert(PbnsAttestationClientAdapterInit(&adapter, &identity, &challenge,
                                          &recipient, &receipt) == EFI_SUCCESS);
  assert(adapter.Initialized);
  assert(adapter.IdentityKey.native == &adapter.IdentityKey);
  assert(PbnsAttestationClientAdapterInit(&adapter, &identity, &challenge,
                                          &recipient, &receipt) ==
         EFI_INVALID_PARAMETER);
  assert(adapter.Initialized);
  assert(adapter.IdentityKey.native == &adapter.IdentityKey);
  assert(adapter.ChallengeVerifier.context == &adapter.ChallengeContext);
  assert(adapter.ReceiptVerifier.context == &adapter.ReceiptContext);
  assert(adapter.HostSigner.context == &adapter.HostSignerContext);
  assert(adapter.RecipientEncrypter.context == &adapter.RecipientContext);
  assert(adapter.Submission.host_signer == &adapter.HostSigner);
  assert(adapter.Submission.recipient_encrypter == &adapter.RecipientEncrypter);
  assert(adapter.Submission.host_signer_context_region.ptr ==
         (const uint8_t *)&adapter.HostSignerContext);
  assert(adapter.Submission.host_signer_context_region.len ==
         sizeof(adapter.HostSignerContext));
  assert(adapter.Submission.recipient_encrypter_context_region.ptr ==
         (const uint8_t *)&adapter.RecipientContext);
  assert(adapter.Submission.recipient_encrypter_context_region.len ==
         sizeof(adapter.RecipientContext));
  assert(adapter.Submission.sha256_context_region.ptr ==
         (const uint8_t *)&adapter.Sha256Context);
  assert(adapter.Submission.sha256_context_region.len ==
         sizeof(adapter.Sha256Context));
  assert(adapter.Submission.quote_context_region.ptr ==
         (const uint8_t *)&adapter.QuoteContext);
  assert(adapter.Submission.quote_context_region.len ==
         sizeof(adapter.QuoteContext));
  assert(adapter.ChallengeVerifierContextRegion.ptr ==
         (const uint8_t *)&adapter.ChallengeContext);
  assert(adapter.ChallengeVerifierContextRegion.len ==
         sizeof(adapter.ChallengeContext));
  assert(adapter.ReceiptVerifierContextRegion.ptr ==
         (const uint8_t *)&adapter.ReceiptContext);
  assert(adapter.ReceiptVerifierContextRegion.len ==
         sizeof(adapter.ReceiptContext));
  assert_clean_template(&adapter.Submission);

  uint8_t byte = UINT8_C(0x6b);
  uint8_t output[32] = {0};
  size_t written = 0U;
  pbns_view payload = {0};
  assert(adapter.ChallengeVerifier.ops->sign1_verify_profile(
             adapter.ChallengeVerifier.context, (pbns_view){&byte, 1U},
             (pbns_view){0}, (pbns_view){&byte, 1U}, &payload) == PBNS_OK);
  assert(adapter.ReceiptVerifier.ops->sign1_verify(
             adapter.ReceiptVerifier.context, (pbns_view){&byte, 1U},
             (pbns_view){0}, &payload) == PBNS_OK);
  assert(adapter.HostSigner.ops->sign1_sign(
             adapter.HostSigner.context, (pbns_view){&byte, 1U},
             (pbns_view){0}, (pbns_buffer){output, 0U, sizeof(output)},
             &written) == PBNS_OK && written == 1U);
  assert(adapter.RecipientEncrypter.ops->encrypt_for_recipient(
             adapter.RecipientEncrypter.context, (pbns_view){&byte, 1U},
             (pbns_view){&byte, 1U}, (pbns_view){0},
             (pbns_buffer){output, 0U, sizeof(output)}, &written) == PBNS_OK);
  assert(adapter.Submission.sha256(adapter.Submission.sha256_context,
                                   (pbns_view){&byte, 1U}, output) == PBNS_OK &&
         output[0] == byte);
  size_t quote_size = 0U;
  size_t signature_size = 0U;
  uint8_t qualifying[32] = {0};
  assert(adapter.Submission.quote(
             adapter.Submission.quote_context, (pbns_measured_boot_selection){0},
             qualifying, (pbns_buffer){output, 0U, sizeof(output)}, &quote_size,
             (pbns_buffer){output + 1U, 0U, sizeof(output) - 1U},
             &signature_size) == PBNS_OK);
  assert(quote_size == 1U && signature_size == 1U &&
         adapter.TpmCommandResult == UINT32_C(0x12345678));

  PbnsAttestationClientAdapterReset(&adapter);
  assert(reset_calls == 1U);
  assert(all_zero(&adapter, sizeof(adapter)));
}

static void test_failed_initializer_resets_transient_key_and_output(void) {
  pbns_identity identity = {0};
  pbns_cose_key key = {0};
  PBNS_ATTESTATION_CLIENT_ADAPTER adapter = {0};
  adapter.TpmCommandResult = UINT32_MAX;
  expected_adapter = &adapter;
  fail_identity_key = true;
  assert(PbnsAttestationClientAdapterInit(&adapter, &identity, &key, &key,
                                          &key) == EFI_SECURITY_VIOLATION);
  fail_identity_key = false;
  assert(reset_calls == 2U);
  assert(all_zero(&adapter, sizeof(adapter)));
}

int main(void) {
  test_initializer_binds_complete_owned_adapter();
  test_failed_initializer_resets_transient_key_and_output();
  return 0;
}
