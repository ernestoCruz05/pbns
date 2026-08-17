#include "PbnsAttestationClientLib.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include <mbedtls/sha256.h>

#define PBNS_ATTESTATION_SHA256_CONTEXT_GUARD UINT32_C(0x53484132)

_Static_assert(PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE ==
                   PBNS_COSE_ATTESTATION_MESSAGE_MAX_SIZE,
               "attestation COSE profile maximum must match core");

typedef PBNS_ATTESTATION_CLIENT_COSE_CONTEXT cose_context;
typedef PBNS_ATTESTATION_CLIENT_QUOTE_CONTEXT quote_context;
typedef PBNS_ATTESTATION_CLIENT_SHA256_CONTEXT sha256_context;

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  if (bytes == NULL) {
    return;
  }
  for (size_t index = 0U; index < length; ++index) {
    bytes[index] = 0U;
  }
}

static pbns_status verifier_verify(void *context, pbns_view cose, pbns_view aad,
                                   pbns_view *payload) {
  const cose_context *adapter = context;
  if (adapter == NULL || adapter->Key == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_cose_uefi_sign1_verify(adapter->Key, cose, aad, payload);
}

static pbns_status verifier_verify_profile(void *context, pbns_view cose,
                                           pbns_view aad,
                                           pbns_view expected_kid,
                                           pbns_view *payload) {
  const cose_context *adapter = context;
  if (adapter == NULL || adapter->Key == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_cose_uefi_sign1_verify_profile(adapter->Key, cose, aad,
                                             expected_kid, payload);
}

static pbns_status host_sign(void *context, pbns_view payload, pbns_view aad,
                             pbns_buffer output, size_t *written) {
  const cose_context *adapter = context;
  if (adapter == NULL || adapter->Key == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_cose_uefi_sign1_sign(adapter->Key, payload, aad, output, written);
}

static pbns_status recipient_encrypt(void *context, pbns_view recipient_kid,
                                     pbns_view plaintext, pbns_view aad,
                                     pbns_buffer output, size_t *written) {
  const cose_context *adapter = context;
  if (adapter == NULL || adapter->Identity == NULL || adapter->Key == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return pbns_cose_uefi_attestation_encrypt_for_recipient(
      adapter->Identity, adapter->Key, recipient_kid, plaintext, aad, output,
      written);
}

static pbns_status hash_sha256(void *context, pbns_view input,
                               uint8_t digest[32]) {
  const sha256_context *adapter = context;
  if (adapter == NULL ||
      adapter->Guard != PBNS_ATTESTATION_SHA256_CONTEXT_GUARD ||
      (input.ptr == NULL && input.len != 0U) || digest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return mbedtls_sha256(input.ptr, input.len, digest, 0) == 0
             ? PBNS_OK
             : PBNS_ERR_CRYPTO;
}

static pbns_status quote_tpm(void *context,
                             pbns_measured_boot_selection selection,
                             const uint8_t qualifying_data[32],
                             pbns_buffer quote, size_t *quote_size,
                             pbns_buffer signature, size_t *signature_size) {
  quote_context *adapter = context;
  if (adapter == NULL || adapter->Identity == NULL ||
      adapter->CommandResult == NULL || qualifying_data == NULL ||
      quote_size == NULL || signature_size == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *adapter->CommandResult = 0U;
  UINTN actual_quote_size = 0U;
  UINTN actual_signature_size = 0U;
  const EFI_STATUS status = PbnsTpmIdentityQuote(
      adapter->Identity, selection, qualifying_data, quote, &actual_quote_size,
      signature, &actual_signature_size, adapter->CommandResult);
  if (EFI_ERROR(status)) {
    return status == EFI_INVALID_PARAMETER ? PBNS_ERR_ARGUMENT
                                           : PBNS_ERR_CRYPTO;
  }
  if (actual_quote_size > quote.cap || actual_signature_size > signature.cap) {
    return PBNS_ERR_LIMIT;
  }
  *quote_size = (size_t)actual_quote_size;
  *signature_size = (size_t)actual_signature_size;
  return PBNS_OK;
}

static const pbns_crypto_ops CHALLENGE_VERIFIER_OPS = {
    .sign1_verify = verifier_verify,
    .sign1_verify_profile = verifier_verify_profile,
};
static const pbns_crypto_ops RECEIPT_VERIFIER_OPS = {
    .sign1_verify = verifier_verify,
};
static const pbns_crypto_ops HOST_SIGNER_OPS = {
    .sign1_sign = host_sign,
};
static const pbns_crypto_ops RECIPIENT_ENCRYPTER_OPS = {
    .encrypt_for_recipient = recipient_encrypt,
};

EFI_STATUS EFIAPI PbnsAttestationClientAdapterInit(
    PBNS_ATTESTATION_CLIENT_ADAPTER *adapter, pbns_identity *identity,
    const pbns_cose_key *challenge_verifier_key,
    const pbns_cose_key *recipient_key,
    const pbns_cose_key *receipt_verifier_key) {
  if (adapter == NULL || identity == NULL || challenge_verifier_key == NULL ||
      recipient_key == NULL || receipt_verifier_key == NULL ||
      adapter->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  secure_zero(adapter, sizeof(*adapter));
  const pbns_status key_status =
      pbns_cose_key_from_identity(&adapter->IdentityKey, identity);
  if (key_status != PBNS_OK) {
    pbns_cose_key_reset(&adapter->IdentityKey);
    secure_zero(adapter, sizeof(*adapter));
    return EFI_SECURITY_VIOLATION;
  }
  adapter->ChallengeContext.Key = challenge_verifier_key;
  adapter->ReceiptContext.Key = receipt_verifier_key;
  adapter->HostSignerContext =
      (cose_context){.Identity = identity, .Key = &adapter->IdentityKey};
  adapter->RecipientContext =
      (cose_context){.Identity = identity, .Key = recipient_key};
  adapter->Sha256Context.Guard = PBNS_ATTESTATION_SHA256_CONTEXT_GUARD;
  adapter->QuoteContext = (quote_context){
      .Identity = identity,
      .CommandResult = &adapter->TpmCommandResult,
  };
  adapter->ChallengeVerifier = (pbns_crypto){
      .ops = &CHALLENGE_VERIFIER_OPS,
      .context = &adapter->ChallengeContext,
  };
  adapter->ReceiptVerifier = (pbns_crypto){
      .ops = &RECEIPT_VERIFIER_OPS,
      .context = &adapter->ReceiptContext,
  };
  adapter->HostSigner = (pbns_crypto){
      .ops = &HOST_SIGNER_OPS,
      .context = &adapter->HostSignerContext,
  };
  adapter->RecipientEncrypter = (pbns_crypto){
      .ops = &RECIPIENT_ENCRYPTER_OPS,
      .context = &adapter->RecipientContext,
  };
  adapter->ChallengeVerifierContextRegion = (pbns_view){
      (const uint8_t *)&adapter->ChallengeContext,
      sizeof(adapter->ChallengeContext),
  };
  adapter->ReceiptVerifierContextRegion = (pbns_view){
      (const uint8_t *)&adapter->ReceiptContext,
      sizeof(adapter->ReceiptContext),
  };
  adapter->Submission = (pbns_attestation_submission){
      .host_signer = &adapter->HostSigner,
      .recipient_encrypter = &adapter->RecipientEncrypter,
      .sha256 = hash_sha256,
      .quote = quote_tpm,
      .sha256_context = &adapter->Sha256Context,
      .quote_context = &adapter->QuoteContext,
      .host_signer_context_region = {
          (const uint8_t *)&adapter->HostSignerContext,
          sizeof(adapter->HostSignerContext),
      },
      .recipient_encrypter_context_region = {
          (const uint8_t *)&adapter->RecipientContext,
          sizeof(adapter->RecipientContext),
      },
      .sha256_context_region = {
          (const uint8_t *)&adapter->Sha256Context,
          sizeof(adapter->Sha256Context),
      },
      .quote_context_region = {
          (const uint8_t *)&adapter->QuoteContext,
          sizeof(adapter->QuoteContext),
      },
  };
  adapter->Initialized = true;
  return EFI_SUCCESS;
}

void EFIAPI PbnsAttestationClientAdapterReset(
    PBNS_ATTESTATION_CLIENT_ADAPTER *adapter) {
  if (adapter == NULL) {
    return;
  }
  if (adapter->Initialized) {
    pbns_cose_key_reset(&adapter->IdentityKey);
  }
  secure_zero(adapter, sizeof(*adapter));
}
