#include "pbns/attestation.h"

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "qcbor/qcbor.h"
#include "qcbor/qcbor_spiffy_decode.h"

#include "../vectors/attestation-challenge-v1/challenge_vector.inc"

#define ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))

typedef struct test_arenas {
  uint8_t *inventory;
  uint8_t *selection;
  uint8_t *quote;
  uint8_t *signature;
  uint8_t *evidence;
  uint8_t *signed_evidence;
  uint8_t *ciphertext;
  uint8_t *aad;
  pbns_attestation_workspace workspace;
} test_arenas;

typedef struct test_seams {
  size_t consume_calls;
  size_t quote_calls;
  size_t send_calls;
  pbns_request_id request_id;
  pbns_measured_boot_selection_item selection[4];
  size_t selection_count;
  uint8_t qualifying_data[32];
  uint8_t *message;
  size_t message_capacity;
  size_t message_size;
  bool final_seen;
  size_t final_count;
  bool quote_variant;
  bool fail_send;
  bool fail_quote;
  bool fail_consume;
  size_t sha_calls;
  size_t fail_sha_call;
} test_seams;

static void fill(uint8_t *bytes, size_t size, uint8_t value) {
  memset(bytes, value, size);
}

static pbns_status unexpected_verify(void *context, pbns_view cose,
                                     pbns_view external_aad,
                                     pbns_view *payload) {
  size_t *calls = context;
  (void)cose;
  (void)external_aad;
  (void)payload;
  ++*calls;
  return PBNS_ERR_AUTHENTICATION;
}

static pbns_status accept_profile_without_crypto(
    void *context, pbns_view cose, pbns_view external_aad,
    pbns_view expected_kid, pbns_view *payload) {
  size_t *calls = context;
  (void)external_aad;
  (void)expected_kid;
  ++*calls;
  QCBORDecodeContext decoder = {0};
  UsefulBufC protected_headers = {0};
  UsefulBufC verified_payload = {0};
  UsefulBufC signature = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){cose.ptr, cose.len},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterArray(&decoder, NULL);
  QCBORDecode_GetByteString(&decoder, &protected_headers);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_GetByteString(&decoder, &verified_payload);
  QCBORDecode_GetByteString(&decoder, &signature);
  QCBORDecode_ExitArray(&decoder);
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  (void)protected_headers;
  (void)signature;
  *payload = (pbns_view){verified_payload.ptr, verified_payload.len};
  return PBNS_OK;
}

static uint8_t *find_bytes(const uint8_t *haystack, size_t haystack_size,
                           const uint8_t *needle, size_t needle_size) {
  if (needle_size == 0U || needle_size > haystack_size) {
    return NULL;
  }
  for (size_t offset = 0U; offset <= haystack_size - needle_size; ++offset) {
    if (memcmp(&haystack[offset], needle, needle_size) == 0) {
      return (uint8_t *)(uintptr_t)&haystack[offset];
    }
  }
  return NULL;
}

static void store_u16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
}

static void store_u32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)value;
  output[1] = (uint8_t)(value >> 8U);
  output[2] = (uint8_t)(value >> 16U);
  output[3] = (uint8_t)(value >> 24U);
}

static size_t make_valid_event_log(uint8_t *output, size_t capacity,
                                   size_t event_data_size) {
  static const uint8_t signature[16] = "Spec ID Event03";
  const size_t required = 119U + event_data_size;
  assert(output != NULL && capacity >= required && event_data_size <= UINT32_MAX);
  size_t offset = 0U;
  store_u32(output + offset, 0U);
  offset += 4U;
  store_u32(output + offset, 3U);
  offset += 4U;
  memset(output + offset, 0, 20U);
  offset += 20U;
  store_u32(output + offset, 37U);
  offset += 4U;
  memcpy(output + offset, signature, sizeof(signature));
  offset += sizeof(signature);
  store_u32(output + offset, 0U);
  offset += 4U;
  output[offset++] = 0U;
  output[offset++] = 2U;
  output[offset++] = 0U;
  output[offset++] = 2U;
  store_u32(output + offset, 2U);
  offset += 4U;
  store_u16(output + offset, UINT16_C(0x0004));
  store_u16(output + offset + 2U, 20U);
  offset += 4U;
  store_u16(output + offset, UINT16_C(0x000b));
  store_u16(output + offset + 2U, 32U);
  offset += 4U;
  output[offset++] = 0U;
  store_u32(output + offset, 7U);
  offset += 4U;
  store_u32(output + offset, UINT32_C(0x80000001));
  offset += 4U;
  store_u32(output + offset, 1U);
  offset += 4U;
  store_u16(output + offset, UINT16_C(0x000b));
  offset += 2U;
  memset(output + offset, 0x5a, 32U);
  offset += 32U;
  store_u32(output + offset, (uint32_t)event_data_size);
  offset += 4U;
  memset(output + offset, 0x65, event_data_size);
  offset += event_data_size;
  assert(offset == required);
  return offset;
}

static pbns_status sha256(void *context, pbns_view input, uint8_t digest[32]) {
  (void)context;
  unsigned int written = 0U;
  return EVP_Digest(input.ptr, input.len, digest, &written, EVP_sha256(), NULL) ==
                 1 &&
             written == 32U
         ? PBNS_OK
         : PBNS_ERR_CRYPTO;
}

static pbns_status bounded_encrypt_seam(
    void *context, pbns_view recipient_kid, pbns_view plaintext,
    pbns_view external_aad, pbns_buffer output, size_t *written) {
  size_t *calls = context;
  (void)recipient_kid;
  (void)plaintext;
  (void)external_aad;
  (void)output;
  ++*calls;
  *written = 1U;
  return PBNS_OK;
}

typedef struct reported_encrypt_length {
  size_t value;
  size_t calls;
} reported_encrypt_length;

static pbns_status report_encrypt_length(
    void *context, pbns_view recipient_kid, pbns_view plaintext,
    pbns_view external_aad, pbns_buffer output, size_t *written) {
  reported_encrypt_length *reported = context;
  (void)recipient_kid;
  (void)plaintext;
  (void)external_aad;
  ++reported->calls;
  fill(output.ptr, output.cap, 0x5aU);
  *written = reported->value;
  return PBNS_OK;
}

static void test_rejects_invalid_encrypt_callback_lengths(void) {
  static const pbns_crypto_ops ops = {
      .encrypt_for_recipient = report_encrypt_length,
  };
  static const uint8_t kid[] = {0x01U};
  static const uint8_t plaintext[] = {0x02U};
  uint8_t output[16] = {0};
  reported_encrypt_length reported = {0};
  const pbns_crypto crypto = {.ops = &ops, .context = &reported};
  const size_t invalid_lengths[] = {0U, sizeof(output) + 1U, SIZE_MAX};

  for (size_t index = 0U;
       index < ARRAY_COUNT(invalid_lengths); ++index) {
    reported.value = invalid_lengths[index];
    fill(output, sizeof(output), 0xa5U);
    size_t written = SIZE_MAX;
    assert(pbns_attestation_encrypt_message(
               &crypto, (pbns_view){kid, sizeof(kid)},
               (pbns_view){plaintext, sizeof(plaintext)},
               (pbns_view){NULL, 0U},
               (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
           PBNS_ERR_LIMIT);
    assert(written == 0U);
    for (size_t byte = 0U; byte < sizeof(output); ++byte) {
      assert(output[byte] == 0U);
    }
  }

  reported.value = sizeof(output);
  fill(output, sizeof(output), 0xa5U);
  size_t written = 0U;
  assert(pbns_attestation_encrypt_message(
             &crypto, (pbns_view){kid, sizeof(kid)},
             (pbns_view){plaintext, sizeof(plaintext)},
             (pbns_view){NULL, 0U},
             (pbns_buffer){output, 0U, sizeof(output)}, &written) == PBNS_OK);
  assert(written == sizeof(output));
  for (size_t byte = 0U; byte < sizeof(output); ++byte) {
    assert(output[byte] == 0x5aU);
  }
  assert(reported.calls == 4U);
}

static void test_cose_message_profiles(void) {
  static const pbns_crypto_ops ops = {
      .encrypt_for_recipient = bounded_encrypt_seam,
  };
  size_t calls = 0U;
  pbns_crypto crypto = {.ops = &ops, .context = &calls};
  static const uint8_t kid[] = "kid";
  static const uint8_t aad[] = "aad";
  uint8_t *plaintext = calloc(1U, PBNS_ATTESTATION_SIGNED_MAX_SIZE + 1U);
  uint8_t *output = calloc(1U, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE + 1U);
  assert(plaintext != NULL && output != NULL);
  size_t written = SIZE_MAX;
  assert(pbns_encrypt_for_recipient(
             &crypto, (pbns_view){kid, sizeof(kid) - 1U},
             (pbns_view){plaintext, PBNS_ENCRYPT_MAX_MESSAGE + 1U},
             (pbns_view){aad, sizeof(aad) - 1U},
             (pbns_buffer){output, 0U, PBNS_ENCRYPT_MAX_MESSAGE + 1U},
             &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U && calls == 0U);
  assert(pbns_attestation_encrypt_message(
             &crypto, (pbns_view){kid, sizeof(kid) - 1U},
             (pbns_view){plaintext, PBNS_ATTESTATION_SIGNED_MAX_SIZE},
             (pbns_view){aad, sizeof(aad) - 1U},
             (pbns_buffer){output, 0U, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE},
             &written) == PBNS_OK);
  assert(written == 1U && calls == 1U);
  written = SIZE_MAX;
  assert(pbns_attestation_encrypt_message(
             &crypto, (pbns_view){kid, sizeof(kid) - 1U},
             (pbns_view){plaintext, PBNS_ATTESTATION_SIGNED_MAX_SIZE + 1U},
             (pbns_view){aad, sizeof(aad) - 1U},
             (pbns_buffer){output, 0U, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE},
             &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U && calls == 1U);
  written = SIZE_MAX;
  assert(pbns_attestation_encrypt_message(
             &crypto, (pbns_view){kid, sizeof(kid) - 1U},
             (pbns_view){plaintext, PBNS_ATTESTATION_SIGNED_MAX_SIZE},
             (pbns_view){aad, sizeof(aad) - 1U},
             (pbns_buffer){output, 0U,
                           PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE + 1U},
             &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U && calls == 1U);
  free(output);
  free(plaintext);
}

static EVP_PKEY *new_p256_key(void) {
  EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
  assert(key != NULL);
  return key;
}

typedef struct bounded_crypto_context {
  pbns_crypto delegate;
  bool fail_sign;
  bool fail_encrypt;
  bool override_sign_written;
  bool override_encrypt_written;
  size_t sign_written;
  size_t encrypt_written;
  size_t sign_calls;
  size_t encrypt_calls;
} bounded_crypto_context;

static pbns_status bounded_sign(void *context, pbns_view payload, pbns_view aad,
                                pbns_buffer output, size_t *written) {
  bounded_crypto_context *bounded = context;
  ++bounded->sign_calls;
  if (bounded->fail_sign) {
    return PBNS_ERR_CRYPTO;
  }
  if (bounded->override_sign_written) {
    fill(output.ptr, output.cap, 0x5aU);
    *written = bounded->sign_written;
    return PBNS_OK;
  }
  return pbns_sign1_sign(&bounded->delegate, payload, aad, output, written);
}

static pbns_status bounded_verify(void *context, pbns_view cose, pbns_view aad,
                                  pbns_view *payload) {
  const bounded_crypto_context *bounded = context;
  return pbns_sign1_verify(&bounded->delegate, cose, aad, payload);
}

static pbns_status bounded_encrypt(void *context, pbns_view kid,
                                   pbns_view plaintext, pbns_view aad,
                                   pbns_buffer output, size_t *written) {
  bounded_crypto_context *bounded = context;
  ++bounded->encrypt_calls;
  if (bounded->fail_encrypt) {
    return PBNS_ERR_CRYPTO;
  }
  if (bounded->override_encrypt_written) {
    fill(output.ptr, output.cap, 0x5aU);
    *written = bounded->encrypt_written;
    return PBNS_OK;
  }
  return pbns_attestation_encrypt_message(&bounded->delegate, kid, plaintext,
                                           aad, output, written);
}

static pbns_status bounded_decrypt(void *context, pbns_view kid,
                                   pbns_view message, pbns_view aad,
                                   pbns_buffer output, size_t *written) {
  const bounded_crypto_context *bounded = context;
  return pbns_decrypt_for_recipient(&bounded->delegate, kid, message, aad,
                                    output, written);
}

static const pbns_crypto_ops bounded_crypto_ops = {
    .sign1_sign = bounded_sign,
    .sign1_verify = bounded_verify,
    .encrypt_for_recipient = bounded_encrypt,
    .decrypt_for_recipient = bounded_decrypt,
};

static pbns_crypto wrap_key(EVP_PKEY *key) {
  pbns_crypto crypto = {0};
  assert(pbns_crypto_openssl_wrap(&crypto, key) == PBNS_OK);
  return crypto;
}

static pbns_crypto bounded_key(EVP_PKEY *key,
                               bounded_crypto_context *context) {
  *context = (bounded_crypto_context){.delegate = wrap_key(key)};
  return (pbns_crypto){.ops = &bounded_crypto_ops, .context = context};
}

static pbns_attestation_challenge make_challenge(uint8_t request_value,
                                                  uint8_t nonce_value) {
  pbns_attestation_challenge challenge = {0};
  fill(challenge.request_id.bytes, sizeof(challenge.request_id.bytes),
       request_value);
  fill(challenge.host_fingerprint, sizeof(challenge.host_fingerprint), 0x22U);
  fill(challenge.verifier_nonce, sizeof(challenge.verifier_nonce), nonce_value);
  challenge.selection_items[0] =
      (pbns_measured_boot_selection_item){PBNS_TPM_ALG_SHA256, 0U};
  challenge.selection_items[1] =
      (pbns_measured_boot_selection_item){PBNS_TPM_ALG_SHA256, 2U};
  challenge.selection_items[2] =
      (pbns_measured_boot_selection_item){PBNS_TPM_ALG_SHA256, 7U};
  challenge.selection_count = 3U;
  static const uint8_t kid[] = "attestation-recipient";
  memcpy(challenge.recipient_kid, kid, sizeof(kid) - 1U);
  challenge.recipient_kid_len = sizeof(kid) - 1U;
  challenge.issued_at_ns = UINT64_C(1000000000);
  challenge.expiry_ns = UINT64_C(2000000000);
  return challenge;
}

static pbns_attestation_challenge_expected expected_from(
    const pbns_attestation_challenge *challenge) {
  pbns_attestation_challenge_expected expected = {0};
  expected.request_id = challenge->request_id;
  memcpy(expected.host_fingerprint, challenge->host_fingerprint,
         sizeof(expected.host_fingerprint));
  memcpy(expected.verifier_nonce, challenge->verifier_nonce,
         sizeof(expected.verifier_nonce));
  expected.recipient_kid = (pbns_view){challenge->recipient_kid,
                                       challenge->recipient_kid_len};
  static const uint8_t challenge_kid[] = "challenge-kid";
  expected.challenge_kid =
      (pbns_view){challenge_kid, sizeof(challenge_kid) - 1U};
  return expected;
}

static size_t signed_challenge(const pbns_crypto *signer,
                               const pbns_attestation_challenge *challenge,
                               const pbns_attestation_challenge_expected *aad_for,
                               uint8_t output[8192]) {
  uint8_t payload[PBNS_ATTESTATION_CHALLENGE_MAX_SIZE] = {0};
  uint8_t aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  size_t payload_size = 0U;
  size_t aad_size = 0U;
  size_t output_size = 0U;
  assert(pbns_attestation_challenge_encode(
             challenge, (pbns_buffer){payload, 0U, sizeof(payload)},
             &payload_size) == PBNS_OK);
  assert(pbns_attestation_challenge_aad(
             aad_for, (pbns_buffer){aad, 0U, sizeof(aad)}, &aad_size) ==
         PBNS_OK);
  assert(pbns_sign1_sign_profile(
             signer, (pbns_view){payload, payload_size},
             (pbns_view){aad, aad_size}, aad_for->challenge_kid,
             (pbns_buffer){output, 0U, 8192U}, &output_size) == PBNS_OK);
  return output_size;
}

static pbns_status accept(const pbns_crypto *verifier, pbns_view message,
                          const pbns_attestation_challenge_expected *expected,
                          const pbns_time_interval *time,
                          pbns_attestation_challenge *accepted) {
  uint8_t canonical[PBNS_ATTESTATION_CHALLENGE_MAX_SIZE] = {0};
  uint8_t aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  pbns_attestation_challenge_workspace workspace = {
      .canonical = {canonical, 0U, sizeof(canonical)},
      .aad = {aad, 0U, sizeof(aad)},
  };
  return pbns_attestation_accept_challenge(verifier, message, expected, time,
                                           &workspace, accepted);
}

static void test_exact_aad_and_qualifying_data(void) {
  pbns_attestation_challenge challenge = make_challenge(0x11U, 0x33U);
  const pbns_attestation_challenge_expected expected =
      expected_from(&challenge);
  uint8_t first[256] = {0};
  uint8_t second[256] = {0};
  size_t first_size = 0U;
  size_t second_size = 0U;
  assert(pbns_attestation_challenge_aad(
             &expected, (pbns_buffer){first, 0U, sizeof(first)}, &first_size) ==
         PBNS_OK);
  assert(pbns_attestation_challenge_aad(
             &expected, (pbns_buffer){second, 0U, sizeof(second)},
             &second_size) == PBNS_OK);
  assert(first_size == second_size &&
         memcmp(first, second, first_size) == 0);
  uint8_t exact[256] = {0};
  size_t exact_size = 0U;
#define EXACT_BYTE(value) exact[exact_size++] = (value)
#define EXACT_BYTES(value, length)                                             \
  do {                                                                         \
    memcpy(&exact[exact_size], (value), (length));                              \
    exact_size += (length);                                                     \
  } while (false)
  EXACT_BYTE(0x87U);
  EXACT_BYTE(0x78U);
  EXACT_BYTE(34U);
  EXACT_BYTES(PBNS_ATTESTATION_CHALLENGE_AAD_DOMAIN, 34U);
  EXACT_BYTE(0x01U);
  EXACT_BYTE(0x03U);
  EXACT_BYTE(0x50U);
  EXACT_BYTES(challenge.request_id.bytes, 16U);
  EXACT_BYTE(0x58U);
  EXACT_BYTE(0x20U);
  EXACT_BYTES(challenge.host_fingerprint, 32U);
  EXACT_BYTE(0x58U);
  EXACT_BYTE(0x20U);
  EXACT_BYTES(challenge.verifier_nonce, 32U);
  EXACT_BYTE(0x55U);
  EXACT_BYTES(challenge.recipient_kid, 21U);
  assert(first_size == exact_size && memcmp(first, exact, exact_size) == 0);

  assert(pbns_attestation_sign_aad(
             &challenge, (pbns_view){(const uint8_t *)"ak", 2U},
             (pbns_buffer){first, 0U, sizeof(first)}, &first_size) == PBNS_OK);
  exact_size = 0U;
  EXACT_BYTE(0x86U);
  EXACT_BYTE(0x78U);
  EXACT_BYTE(24U);
  EXACT_BYTES(PBNS_ATTESTATION_SIGN_AAD_DOMAIN, 24U);
  EXACT_BYTE(0x01U);
  EXACT_BYTE(0x50U);
  EXACT_BYTES(challenge.request_id.bytes, 16U);
  EXACT_BYTE(0x58U);
  EXACT_BYTE(0x20U);
  EXACT_BYTES(challenge.host_fingerprint, 32U);
  EXACT_BYTE(0x58U);
  EXACT_BYTE(0x20U);
  EXACT_BYTES(challenge.verifier_nonce, 32U);
  EXACT_BYTE(0x42U);
  EXACT_BYTES("ak", 2U);
  assert(first_size == exact_size && memcmp(first, exact, exact_size) == 0);
  assert(pbns_attestation_encrypt_aad(
             &challenge, (pbns_buffer){second, 0U, sizeof(second)},
             &second_size) == PBNS_OK);
  exact_size = 0U;
  EXACT_BYTE(0x87U);
  EXACT_BYTE(0x78U);
  EXACT_BYTE(27U);
  EXACT_BYTES(PBNS_ATTESTATION_ENCRYPT_AAD_DOMAIN, 27U);
  EXACT_BYTE(0x01U);
  EXACT_BYTE(0x03U);
  EXACT_BYTE(0x50U);
  EXACT_BYTES(challenge.request_id.bytes, 16U);
  EXACT_BYTE(0x58U);
  EXACT_BYTE(0x20U);
  EXACT_BYTES(challenge.host_fingerprint, 32U);
  EXACT_BYTE(0x58U);
  EXACT_BYTE(0x20U);
  EXACT_BYTES(challenge.verifier_nonce, 32U);
  EXACT_BYTE(0x55U);
  EXACT_BYTES(challenge.recipient_kid, 21U);
  assert(second_size == exact_size && memcmp(second, exact, exact_size) == 0);
#undef EXACT_BYTES
#undef EXACT_BYTE

  uint8_t report[32] = {0};
  uint8_t selection[32] = {0};
  uint8_t event_log[32] = {0};
  fill(report, sizeof(report), 0x44U);
  fill(selection, sizeof(selection), 0x55U);
  fill(event_log, sizeof(event_log), 0x66U);
  uint8_t scratch[256] = {0};
  uint8_t actual[32] = {0};
  assert(pbns_attestation_qualifying_data(
             sha256, NULL, &challenge.request_id, challenge.verifier_nonce,
             report, selection, event_log,
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, actual) == PBNS_OK);
  static const uint8_t domain[] = PBNS_ATTESTATION_QUALIFYING_DOMAIN;
  uint8_t material[256] = {0};
  size_t offset = 0U;
#define APPEND(value, length)                                                  \
  do {                                                                         \
    memcpy(&material[offset], (value), (length));                               \
    offset += (length);                                                         \
  } while (false)
  APPEND(domain, sizeof(domain) - 1U);
  APPEND(challenge.request_id.bytes, sizeof(challenge.request_id.bytes));
  APPEND(challenge.verifier_nonce, sizeof(challenge.verifier_nonce));
  APPEND(report, sizeof(report));
  APPEND(selection, sizeof(selection));
  APPEND(event_log, sizeof(event_log));
#undef APPEND
  uint8_t expected_digest[32] = {0};
  assert(sha256(NULL, (pbns_view){material, offset}, expected_digest) ==
         PBNS_OK);
  assert(memcmp(actual, expected_digest, sizeof(actual)) == 0);
  for (size_t mutation = 0U; mutation < 5U; ++mutation) {
    uint8_t mutated_request[16] = {0};
    uint8_t mutated_nonce[32] = {0};
    uint8_t mutated_report[32] = {0};
    uint8_t mutated_selection[32] = {0};
    uint8_t mutated_log[32] = {0};
    memcpy(mutated_request, challenge.request_id.bytes,
           sizeof(mutated_request));
    memcpy(mutated_nonce, challenge.verifier_nonce, sizeof(mutated_nonce));
    memcpy(mutated_report, report, sizeof(mutated_report));
    memcpy(mutated_selection, selection, sizeof(mutated_selection));
    memcpy(mutated_log, event_log, sizeof(mutated_log));
    uint8_t *targets[] = {mutated_request, mutated_nonce, mutated_report,
                          mutated_selection, mutated_log};
    targets[mutation][0] ^= 1U;
    pbns_request_id request = {0};
    memcpy(request.bytes, mutated_request, sizeof(request.bytes));
    uint8_t changed[32] = {0};
    assert(pbns_attestation_qualifying_data(
               sha256, NULL, &request, mutated_nonce, mutated_report,
               mutated_selection, mutated_log,
               (pbns_buffer){scratch, 0U, sizeof(scratch)}, changed) ==
           PBNS_OK);
    assert(memcmp(changed, actual, sizeof(changed)) != 0);
  }
}

static void assert_challenge_rejected(const pbns_crypto *crypto,
                                      const pbns_attestation_challenge *challenge,
                                      const pbns_attestation_challenge_expected *expected,
                                      const pbns_time_interval *time,
                                      const uint8_t *protected_headers,
                                      size_t protected_size,
                                      bool unprotected_nonempty) {
  uint8_t payload[PBNS_ATTESTATION_CHALLENGE_MAX_SIZE] = {0};
  uint8_t aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  uint8_t message[8192] = {0};
  size_t payload_size = 0U;
  size_t aad_size = 0U;
  assert(pbns_attestation_challenge_encode(
             challenge, (pbns_buffer){payload, 0U, sizeof(payload)},
             &payload_size) == PBNS_OK);
  assert(pbns_attestation_challenge_aad(
             expected, (pbns_buffer){aad, 0U, sizeof(aad)}, &aad_size) ==
         PBNS_OK);
  uint8_t signature[64] = {0};
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){message, sizeof(message)});
  QCBOREncode_AddTag(&encoder, 18U);
  QCBOREncode_OpenArray(&encoder);
  QCBOREncode_AddBytes(
      &encoder, (UsefulBufC){protected_headers, protected_size});
  QCBOREncode_OpenMap(&encoder);
  if (unprotected_nonempty) {
    QCBOREncode_AddInt64ToMapN(&encoder, 4, 1);
  }
  QCBOREncode_CloseMap(&encoder);
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){payload, payload_size});
  QCBOREncode_AddBytes(&encoder, (UsefulBufC){signature, sizeof(signature)});
  QCBOREncode_CloseArray(&encoder);
  assert(QCBOREncode_Finish(&encoder, &encoded) == QCBOR_SUCCESS);
  pbns_attestation_challenge accepted = {0};
  assert(accept(crypto, (pbns_view){encoded.ptr, encoded.len}, expected, time,
                &accepted) == PBNS_ERR_FORMAT);
}

static size_t append_cbor_bytes(uint8_t *output, size_t capacity,
                                size_t offset, pbns_view value,
                                bool nonminimal_length) {
  assert(output != NULL && offset <= capacity &&
         value.len <= capacity - offset);
  uint8_t header[5] = {0};
  size_t header_size = 0U;
  if (!nonminimal_length && value.len < 24U) {
    header[0] = (uint8_t)(0x40U | value.len);
    header_size = 1U;
  } else if ((!nonminimal_length && value.len <= UINT8_MAX) ||
             (nonminimal_length && value.len < 24U)) {
    header[0] = 0x58U;
    header[1] = (uint8_t)value.len;
    header_size = 2U;
  } else if ((!nonminimal_length && value.len <= UINT16_MAX) ||
             (nonminimal_length && value.len <= UINT8_MAX)) {
    header[0] = 0x59U;
    header[1] = (uint8_t)(value.len >> 8U);
    header[2] = (uint8_t)value.len;
    header_size = 3U;
  } else {
    assert(value.len <= UINT32_MAX);
    header[0] = 0x5aU;
    header[1] = (uint8_t)(value.len >> 24U);
    header[2] = (uint8_t)(value.len >> 16U);
    header[3] = (uint8_t)(value.len >> 8U);
    header[4] = (uint8_t)value.len;
    header_size = 5U;
  }
  assert(header_size <= capacity - offset &&
         value.len <= capacity - offset - header_size);
  memcpy(&output[offset], header, header_size);
  offset += header_size;
  if (value.len > 0U) {
    assert(value.ptr != NULL);
    memcpy(&output[offset], value.ptr, value.len);
  }
  return offset + value.len;
}

static size_t make_raw_challenge_envelope(
    uint8_t *output, size_t capacity, pbns_view tag, pbns_view array,
    pbns_view protected_headers, bool nonminimal_protected_length,
    pbns_view unprotected, pbns_view payload,
    bool nonminimal_payload_length, pbns_view signature,
    bool nonminimal_signature_length) {
  size_t offset = 0U;
#define APPEND_RAW(value)                                                       \
  do {                                                                          \
    assert((value).len <= capacity - offset);                                    \
    if ((value).len > 0U) {                                                      \
      assert((value).ptr != NULL);                                               \
      memcpy(&output[offset], (value).ptr, (value).len);                         \
      offset += (value).len;                                                     \
    }                                                                            \
  } while (false)
  APPEND_RAW(tag);
  APPEND_RAW(array);
  offset = append_cbor_bytes(output, capacity, offset, protected_headers,
                             nonminimal_protected_length);
  APPEND_RAW(unprotected);
  offset = append_cbor_bytes(output, capacity, offset, payload,
                             nonminimal_payload_length);
  offset = append_cbor_bytes(output, capacity, offset, signature,
                             nonminimal_signature_length);
#undef APPEND_RAW
  return offset;
}

typedef struct challenge_profile_case {
  const char *name;
  pbns_view tag;
  pbns_view array;
  pbns_view protected_headers;
  bool nonminimal_protected_length;
  pbns_view unprotected;
  pbns_view payload;
  bool nonminimal_payload_length;
  size_t signature_size;
  bool nonminimal_signature_length;
} challenge_profile_case;

static void test_complete_challenge_profile_mutants(void) {
  static const uint8_t tag[] = {0xd2U};
  static const uint8_t wrong_tag[] = {0xd1U};
  static const uint8_t array[] = {0x84U};
  static const uint8_t wrong_array[] = {0x83U};
  static const uint8_t protected_canonical[] = {
      0xa2U, 0x01U, 0x26U, 0x04U, 0x4dU, 'c', 'h', 'a', 'l', 'l', 'e',
      'n',   'g',   'e',   '-',   'k',   'i', 'd'};
  static const uint8_t protected_reordered[] = {
      0xa2U, 0x04U, 0x4dU, 'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e',
      '-',   'k',   'i',   'd', 0x01U, 0x26U};
  static const uint8_t protected_nonminimal_key[] = {
      0xa2U, 0x18U, 0x01U, 0x26U, 0x04U, 0x4dU, 'c', 'h', 'a', 'l', 'l',
      'e',   'n',   'g',   'e',   '-',   'k',   'i',   'd'};
  static const uint8_t protected_nonminimal_algorithm[] = {
      0xa2U, 0x01U, 0x38U, 0x06U, 0x04U, 0x4dU, 'c', 'h', 'a', 'l', 'l',
      'e',   'n',   'g',   'e',   '-',   'k',   'i',   'd'};
  static const uint8_t protected_nonminimal_map[] = {
      0xb8U, 0x02U, 0x01U, 0x26U, 0x04U, 0x4dU, 'c', 'h', 'a', 'l', 'l',
      'e',   'n',   'g',   'e',   '-',   'k',   'i',   'd'};
  static const uint8_t protected_nonminimal_kid[] = {
      0xa2U, 0x01U, 0x26U, 0x04U, 0x58U, 0x0dU, 'c', 'h', 'a', 'l', 'l',
      'e',   'n',   'g',   'e',   '-',   'k',   'i',   'd'};
  static const uint8_t empty_map[] = {0xa0U};
  static const uint8_t nonempty_map[] = {0xa1U, 0x05U, 0x01U};
  static const uint8_t indefinite_empty_map[] = {0xbfU, 0xffU};
  static const uint8_t malformed_payload[] = {0xffU};
  uint8_t payload[PBNS_ATTESTATION_CHALLENGE_MAX_SIZE] = {0};
  uint8_t signature[65] = {0};
  pbns_attestation_challenge challenge = make_challenge(0x11U, 0x33U);
  const pbns_attestation_challenge_expected expected =
      expected_from(&challenge);
  size_t payload_size = 0U;
  assert(pbns_attestation_challenge_encode(
             &challenge, (pbns_buffer){payload, 0U, sizeof(payload)},
             &payload_size) == PBNS_OK);
  const challenge_profile_case cases[] = {
      {"reordered protected labels", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_reordered, sizeof(protected_reordered)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"nonminimal protected integer key", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_nonminimal_key, sizeof(protected_nonminimal_key)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"nonminimal protected algorithm value", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_nonminimal_algorithm,
        sizeof(protected_nonminimal_algorithm)},
       false, {empty_map, sizeof(empty_map)}, {payload, payload_size}, false,
       64U, false},
      {"nonminimal protected map length", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_nonminimal_map, sizeof(protected_nonminimal_map)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"nonminimal inner KID bstr length", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_nonminimal_kid, sizeof(protected_nonminimal_kid)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"nonempty unprotected map", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {nonempty_map, sizeof(nonempty_map)}, {payload, payload_size}, false,
       64U, false},
      {"indefinite empty unprotected map", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {indefinite_empty_map, sizeof(indefinite_empty_map)},
       {payload, payload_size}, false, 64U, false},
      {"missing tag", {NULL, 0U}, {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"wrong tag", {wrong_tag, sizeof(wrong_tag)}, {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"wrong array length", {tag, sizeof(tag)},
       {wrong_array, sizeof(wrong_array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       false},
      {"nonminimal outer payload bstr length", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, true, 64U,
       false},
      {"nonminimal outer signature bstr length", {tag, sizeof(tag)},
       {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 64U,
       true},
      {"empty payload", {tag, sizeof(tag)}, {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {NULL, 0U}, false, 64U, false},
      {"short signature", {tag, sizeof(tag)}, {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 63U,
       false},
      {"long signature", {tag, sizeof(tag)}, {array, sizeof(array)},
       {protected_canonical, sizeof(protected_canonical)}, false,
       {empty_map, sizeof(empty_map)}, {payload, payload_size}, false, 65U,
       false},
  };
  EVP_PKEY *key = new_p256_key();
  const pbns_crypto crypto = wrap_key(key);
  const pbns_time_interval time = {INT64_C(1100000000), INT64_C(1200000000)};
  for (size_t index = 0U; index < ARRAY_COUNT(cases); ++index) {
    uint8_t message[8192] = {0};
    const size_t message_size = make_raw_challenge_envelope(
        message, sizeof(message), cases[index].tag, cases[index].array,
        cases[index].protected_headers,
        cases[index].nonminimal_protected_length, cases[index].unprotected,
        cases[index].payload, cases[index].nonminimal_payload_length,
        (pbns_view){signature, cases[index].signature_size},
        cases[index].nonminimal_signature_length);
    pbns_attestation_challenge accepted = {0};
    const pbns_status status =
        accept(&crypto, (pbns_view){message, message_size}, &expected, &time,
               &accepted);
    if (status != PBNS_ERR_FORMAT) {
      fprintf(stderr, "%s: actual=%d expected=%d\n", cases[index].name,
              (int)status, (int)PBNS_ERR_FORMAT);
    }
    assert(status == PBNS_ERR_FORMAT);
  }

  uint8_t malformed_message[8192] = {0};
  const size_t malformed_size = make_raw_challenge_envelope(
      malformed_message, sizeof(malformed_message),
      (pbns_view){tag, sizeof(tag)}, (pbns_view){array, sizeof(array)},
      (pbns_view){protected_canonical, sizeof(protected_canonical)}, false,
      (pbns_view){empty_map, sizeof(empty_map)},
      (pbns_view){malformed_payload, sizeof(malformed_payload)}, false,
      (pbns_view){signature, 64U}, false);
  size_t verify_calls = 0U;
  const pbns_crypto_ops verifier_ops = {
      .sign1_verify_profile = accept_profile_without_crypto,
  };
  const pbns_crypto format_verifier = {
      .ops = &verifier_ops,
      .context = &verify_calls,
  };
  pbns_attestation_challenge accepted = {0};
  assert(accept(&format_verifier,
                (pbns_view){malformed_message, malformed_size}, &expected,
                &time, &accepted) == PBNS_ERR_FORMAT);
  assert(verify_calls == 1U);
  EVP_PKEY_free(key);
}

static void test_genuine_go_challenge_vector(void) {
  assert(sizeof(pbns_challenge_vector_public_der) <= (size_t)LONG_MAX);
  const unsigned char *der = pbns_challenge_vector_public_der;
  EVP_PKEY *key = d2i_PUBKEY(NULL, &der,
                             (long)sizeof(pbns_challenge_vector_public_der));
  assert(key != NULL &&
         der == pbns_challenge_vector_public_der +
                    sizeof(pbns_challenge_vector_public_der));
  const pbns_crypto verifier = wrap_key(key);
  pbns_attestation_challenge_expected expected = {0};
  memcpy(expected.request_id.bytes, pbns_challenge_vector_request_id,
         sizeof(expected.request_id.bytes));
  memcpy(expected.host_fingerprint, pbns_challenge_vector_host_fingerprint,
         sizeof(expected.host_fingerprint));
  memcpy(expected.verifier_nonce, pbns_challenge_vector_nonce,
         sizeof(expected.verifier_nonce));
  expected.recipient_kid =
      (pbns_view){pbns_challenge_vector_recipient_kid,
                  sizeof(pbns_challenge_vector_recipient_kid)};
  expected.challenge_kid =
      (pbns_view){pbns_challenge_vector_challenge_kid,
                  sizeof(pbns_challenge_vector_challenge_kid)};
  uint8_t aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  size_t aad_size = 0U;
  assert(pbns_attestation_challenge_aad(
             &expected, (pbns_buffer){aad, 0U, sizeof(aad)}, &aad_size) ==
         PBNS_OK);
  assert(aad_size == sizeof(pbns_challenge_vector_external_aad) &&
         memcmp(aad, pbns_challenge_vector_external_aad, aad_size) == 0);
  const pbns_time_interval time = {
      pbns_challenge_vector_time_earliest,
      pbns_challenge_vector_time_latest,
  };
  pbns_attestation_challenge accepted = {0};
  assert(accept(&verifier,
                (pbns_view){pbns_challenge_vector_signed,
                            sizeof(pbns_challenge_vector_signed)},
                &expected, &time, &accepted) == PBNS_OK);
  assert(accepted.selection_count ==
         ARRAY_COUNT(pbns_challenge_vector_selection_indices));
  for (size_t index = 0U; index < accepted.selection_count; ++index) {
    assert(accepted.selection_items[index].hash_algorithm ==
           pbns_challenge_vector_selection_algorithms[index]);
    assert(accepted.selection_items[index].pcr_index ==
           pbns_challenge_vector_selection_indices[index]);
  }
  EVP_PKEY_free(key);
}

static void test_challenge_binding_and_canonicality(void) {
  EVP_PKEY *key = new_p256_key();
  const pbns_crypto crypto = wrap_key(key);
  pbns_attestation_challenge challenge = make_challenge(0x11U, 0x33U);
  pbns_attestation_challenge_expected expected = expected_from(&challenge);
  uint8_t message[8192] = {0};
  size_t message_size = signed_challenge(&crypto, &challenge, &expected, message);
  const pbns_time_interval time = {INT64_C(1100000000), INT64_C(1200000000)};
  pbns_attestation_challenge accepted = {0};
  assert(accept(&crypto, (pbns_view){message, message_size}, &expected, &time,
                &accepted) == PBNS_OK);
  assert(accepted.selection_count == challenge.selection_count);

  for (size_t mutation = 0U; mutation < 4U; ++mutation) {
    uint8_t noncanonical[8192] = {0};
    memcpy(noncanonical, message, message_size);
    size_t noncanonical_size = message_size;
    if (mutation == 0U) {
      memmove(&noncanonical[1], &noncanonical[0], noncanonical_size);
      noncanonical[0] = 0xd8U;
      noncanonical[1] = 0x12U;
      ++noncanonical_size;
    } else if (mutation == 1U) {
      memmove(&noncanonical[3], &noncanonical[2], noncanonical_size - 2U);
      noncanonical[1] = 0x98U;
      noncanonical[2] = 0x04U;
      ++noncanonical_size;
    } else if (mutation == 2U) {
      assert((noncanonical[2] & 0xe0U) == 0x40U &&
             (noncanonical[2] & 0x1fU) < 24U);
      const uint8_t protected_size = noncanonical[2] & 0x1fU;
      memmove(&noncanonical[4], &noncanonical[3], noncanonical_size - 3U);
      noncanonical[2] = 0x58U;
      noncanonical[3] = protected_size;
      ++noncanonical_size;
    } else {
      noncanonical[noncanonical_size] = 0x00U;
      ++noncanonical_size;
    }
    assert(accept(&crypto,
                  (pbns_view){noncanonical, noncanonical_size}, &expected,
                  &time, &accepted) == PBNS_ERR_FORMAT);
  }

  static const uint8_t missing_kid[] = {0xa1U, 0x01U, 0x26U};
  static const uint8_t wrong_alg[] = {0xa2U, 0x01U, 0x25U, 0x04U, 0x4dU,
                                      'c', 'h', 'a', 'l', 'l', 'e', 'n',
                                      'g', 'e', '-', 'k', 'i', 'd'};
  static const uint8_t wrong_kid[] = {0xa2U, 0x01U, 0x26U, 0x04U, 0x45U,
                                      'w', 'r', 'o', 'n', 'g'};
  static const uint8_t extra_header[] = {
      0xa3U, 0x01U, 0x26U, 0x04U, 0x4dU, 'c', 'h', 'a', 'l', 'l', 'e',
      'n',   'g',   'e',   '-',   'k',   'i', 'd', 0x05U, 0x40U};
  assert_challenge_rejected(&crypto, &challenge, &expected, &time,
                            missing_kid, sizeof(missing_kid), false);
  assert_challenge_rejected(&crypto, &challenge, &expected, &time,
                            wrong_alg, sizeof(wrong_alg), false);
  assert_challenge_rejected(&crypto, &challenge, &expected, &time,
                            wrong_kid, sizeof(wrong_kid), false);
  assert_challenge_rejected(&crypto, &challenge, &expected, &time,
                            extra_header, sizeof(extra_header), false);
  assert_challenge_rejected(&crypto, &challenge, &expected, &time,
                            wrong_kid, sizeof(wrong_kid), true);

  for (size_t mutation = 0U; mutation < 4U; ++mutation) {
    pbns_attestation_challenge changed = challenge;
    if (mutation == 0U) {
      changed.request_id.bytes[0] ^= 1U;
    } else if (mutation == 1U) {
      changed.host_fingerprint[0] ^= 1U;
    } else if (mutation == 2U) {
      changed.verifier_nonce[0] ^= 1U;
    } else {
      changed.recipient_kid[0] ^= 1U;
    }
    message_size = signed_challenge(&crypto, &changed, &expected, message);
    assert(accept(&crypto, (pbns_view){message, message_size}, &expected, &time,
                  &accepted) == PBNS_ERR_AUTHENTICATION);
  }

  message_size = signed_challenge(&crypto, &challenge, &expected, message);
  message[message_size - 1U] ^= 1U;
  assert(accept(&crypto, (pbns_view){message, message_size}, &expected, &time,
                &accepted) == PBNS_ERR_AUTHENTICATION);
  message_size = signed_challenge(&crypto, &challenge, &expected, message);
  const pbns_time_interval expired = {INT64_C(2000000001), INT64_C(2000000002)};
  assert(accept(&crypto, (pbns_view){message, message_size}, &expected, &expired,
                &accepted) == PBNS_ERR_TIMEOUT);

  uint8_t payload[4096] = {0};
  size_t payload_size = 0U;
  assert(pbns_attestation_challenge_encode(
             &challenge, (pbns_buffer){payload, 0U, sizeof(payload)},
             &payload_size) == PBNS_OK);
  assert(payload[0] == 0xa5U);
  payload[0] = 0xbfU;
  payload[payload_size] = 0xffU;
  payload_size += 1U;
  uint8_t aad[256] = {0};
  size_t aad_size = 0U;
  assert(pbns_attestation_challenge_aad(
             &expected, (pbns_buffer){aad, 0U, sizeof(aad)}, &aad_size) ==
         PBNS_OK);
  assert(pbns_sign1_sign_profile(
             &crypto, (pbns_view){payload, payload_size},
             (pbns_view){aad, aad_size}, expected.challenge_kid,
             (pbns_buffer){message, 0U, sizeof(message)}, &message_size) ==
         PBNS_OK);
  assert(accept(&crypto, (pbns_view){message, message_size}, &expected, &time,
                &accepted) == PBNS_ERR_FORMAT);

  message_size = signed_challenge(&crypto, &challenge, &expected, message);
  uint8_t alias_aad[PBNS_ATTESTATION_AAD_MAX_SIZE] = {0};
  pbns_attestation_challenge_workspace alias_workspace = {0};
  alias_workspace.canonical =
      (pbns_buffer){(uint8_t *)&alias_workspace, 0U,
                    PBNS_ATTESTATION_CHALLENGE_MAX_SIZE};
  alias_workspace.aad = (pbns_buffer){alias_aad, 0U, sizeof(alias_aad)};
  const pbns_attestation_challenge_workspace alias_workspace_before =
      alias_workspace;
  size_t verify_calls = 0U;
  const pbns_crypto_ops guard_ops = {.sign1_verify = unexpected_verify};
  const pbns_crypto guard = {.ops = &guard_ops, .context = &verify_calls};
  accepted = make_challenge(0xe1U, 0xe3U);
  const pbns_attestation_challenge accepted_before = accepted;
  assert(pbns_attestation_accept_challenge(
             &guard, (pbns_view){message, message_size}, &expected, &time,
             &alias_workspace, &accepted) == PBNS_ERR_ARGUMENT);
  assert(verify_calls == 0U);
  assert(memcmp(&alias_workspace, &alias_workspace_before,
                sizeof(alias_workspace)) == 0);
  assert(memcmp(&accepted, &accepted_before, sizeof(accepted)) == 0);
  EVP_PKEY_free(key);
}

static test_arenas arenas_new(void) {
  test_arenas arenas = {0};
#define ALLOC(field, size)                                                     \
  do {                                                                         \
    arenas.field = calloc(1U, (size));                                          \
    assert(arenas.field != NULL);                                               \
  } while (false)
  ALLOC(inventory, PBNS_INVENTORY_ENCODED_MAX_SIZE);
  ALLOC(selection, PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE);
  ALLOC(quote, PBNS_ATTESTATION_QUOTE_MAX_SIZE);
  ALLOC(signature, PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE);
  ALLOC(evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE);
  ALLOC(signed_evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE +
                             PBNS_ATTESTATION_SIGNED_OVERHEAD_MAX_SIZE);
  ALLOC(ciphertext, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  ALLOC(aad, PBNS_ATTESTATION_AAD_MAX_SIZE);
#undef ALLOC
  arenas.workspace = (pbns_attestation_workspace){
      .inventory = {arenas.inventory, 0U, PBNS_INVENTORY_ENCODED_MAX_SIZE},
      .selection = {arenas.selection, 0U,
                    PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE},
      .quote = {arenas.quote, 0U, PBNS_ATTESTATION_QUOTE_MAX_SIZE},
      .quote_signature = {arenas.signature, 0U,
                          PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE},
      .evidence = {arenas.evidence, 0U, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE},
      .signed_evidence = {
          arenas.signed_evidence, 0U,
          PBNS_ATTESTATION_EVIDENCE_MAX_SIZE +
              PBNS_ATTESTATION_SIGNED_OVERHEAD_MAX_SIZE},
      .ciphertext = {arenas.ciphertext, 0U,
                     PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE},
      .aad = {arenas.aad, 0U, PBNS_ATTESTATION_AAD_MAX_SIZE},
  };
  return arenas;
}

static void assert_zero(const uint8_t *bytes, size_t size) {
  for (size_t index = 0U; index < size; ++index) {
    assert(bytes[index] == 0U);
  }
}

static void arenas_assert_wiped(const test_arenas *arenas) {
  assert_zero(arenas->inventory, PBNS_INVENTORY_ENCODED_MAX_SIZE);
  assert_zero(arenas->selection,
              PBNS_ATTESTATION_SELECTION_WORKSPACE_SIZE);
  assert_zero(arenas->quote, PBNS_ATTESTATION_QUOTE_MAX_SIZE);
  assert_zero(arenas->signature,
              PBNS_ATTESTATION_QUOTE_SIGNATURE_MAX_SIZE);
  assert_zero(arenas->evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE);
  assert_zero(arenas->signed_evidence,
              PBNS_ATTESTATION_EVIDENCE_MAX_SIZE +
                  PBNS_ATTESTATION_SIGNED_OVERHEAD_MAX_SIZE);
  assert_zero(arenas->ciphertext, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  assert_zero(arenas->aad, PBNS_ATTESTATION_AAD_MAX_SIZE);
}

static void arenas_free(test_arenas *arenas) {
  free(arenas->inventory);
  free(arenas->selection);
  free(arenas->quote);
  free(arenas->signature);
  free(arenas->evidence);
  free(arenas->signed_evidence);
  free(arenas->ciphertext);
  free(arenas->aad);
  *arenas = (test_arenas){0};
}

static pbns_status consume_seam(void *context,
                                const pbns_request_id *request_id,
                                const uint8_t nonce[32]) {
  test_seams *seams = context;
  (void)nonce;
  ++seams->consume_calls;
  seams->request_id = *request_id;
  if (seams->fail_consume) {
    return PBNS_ERR_REPLAY;
  }
  return seams->consume_calls == 1U ? PBNS_OK : PBNS_ERR_REPLAY;
}

static pbns_status sha256_seam(void *context, pbns_view input,
                               uint8_t digest[32]) {
  test_seams *seams = context;
  ++seams->sha_calls;
  if (seams->sha_calls == seams->fail_sha_call) {
    return PBNS_ERR_CRYPTO;
  }
  return sha256(NULL, input, digest);
}

static pbns_status quote_seam(void *context,
                              pbns_measured_boot_selection selection,
                              const uint8_t qualifying_data[32],
                              pbns_buffer quote, size_t *quote_size,
                              pbns_buffer signature,
                              size_t *signature_size) {
  test_seams *seams = context;
  ++seams->quote_calls;
  if (seams->fail_quote) {
    return PBNS_ERR_CRYPTO;
  }
  seams->selection_count = selection.count;
  assert(selection.count <= ARRAY_COUNT(seams->selection));
  memcpy(seams->selection, selection.items,
         selection.count * sizeof(selection.items[0]));
  memcpy(seams->qualifying_data, qualifying_data,
         sizeof(seams->qualifying_data));
  static const uint8_t quote_a[] = "TPM2B_ATTEST-QUOTE-A";
  static const uint8_t quote_b[] = "TPM2B_ATTEST-QUOTE-B";
  static const uint8_t signature_a[] = "TPMT_SIGNATURE-A";
  static const uint8_t signature_b[] = "TPMT_SIGNATURE-B";
  const uint8_t *quote_value = seams->quote_variant ? quote_b : quote_a;
  const uint8_t *signature_value =
      seams->quote_variant ? signature_b : signature_a;
  assert(sizeof(quote_a) == sizeof(quote_b) &&
         sizeof(signature_a) == sizeof(signature_b));
  assert(quote.cap >= sizeof(quote_a) - 1U);
  assert(signature.cap >= sizeof(signature_a) - 1U);
  memcpy(quote.ptr, quote_value, sizeof(quote_a) - 1U);
  memcpy(signature.ptr, signature_value, sizeof(signature_a) - 1U);
  *quote_size = sizeof(quote_a) - 1U;
  *signature_size = sizeof(signature_a) - 1U;
  return PBNS_OK;
}

static pbns_status send_seam(void *context,
                             const pbns_request_id *request_id,
                             uint32_t sequence, pbns_view payload,
                             bool final_record) {
  test_seams *seams = context;
  assert(memcmp(request_id->bytes, seams->request_id.bytes,
                sizeof(request_id->bytes)) == 0);
  assert((size_t)sequence == seams->send_calls);
  assert(payload.len > 0U && payload.len <= PBNS_FRAME_V1_DATA_PAYLOAD_MAX);
  if (final_record) {
    ++seams->final_count;
  } else {
    assert(payload.len == PBNS_FRAME_V1_DATA_PAYLOAD_MAX);
    assert(seams->final_count == 0U);
  }
  if (seams->fail_send) {
    return PBNS_ERR_TRANSPORT;
  }
  assert(payload.len <= seams->message_capacity - seams->message_size);
  memcpy(&seams->message[seams->message_size], payload.ptr, payload.len);
  seams->message_size += payload.len;
  ++seams->send_calls;
  seams->final_seen = final_record;
  return PBNS_OK;
}

static pbns_inventory_report make_report(
    const pbns_attestation_challenge *challenge) {
  pbns_inventory_report report = {0};
  memcpy(report.host_fingerprint, challenge->host_fingerprint,
         sizeof(report.host_fingerprint));
  fill(report.board_model_digest, sizeof(report.board_model_digest), 0xb2U);
  report.tpm_present = true;
  report.tpm_active_banks[0] = PBNS_TPM_ALG_SHA256;
  report.tpm_active_bank_count = 1U;
  return report;
}

static pbns_measured_boot_evidence make_measured(
    const pbns_attestation_challenge *challenge, uint8_t *event_log,
    size_t event_log_size) {
  pbns_measured_boot_evidence measured = {0};
  measured.event_log = (pbns_view){event_log, event_log_size};
  measured.pcr_count = challenge->selection_count;
  for (size_t index = 0U; index < measured.pcr_count; ++index) {
    measured.pcrs[index].selection = challenge->selection_items[index];
    fill(measured.pcrs[index].digest, sizeof(measured.pcrs[index].digest),
         (uint8_t)(0x70U + index));
    measured.pcrs[index].digest_size = 32U;
  }
  uint8_t encoded[256] = {0};
  size_t encoded_size = 0U;
  assert(pbns_measured_boot_encode_canonical_selection(
             (pbns_measured_boot_selection){challenge->selection_items,
                                            challenge->selection_count},
             (pbns_buffer){encoded, 0U, sizeof(encoded)}, &encoded_size) ==
         PBNS_OK);
  assert(sha256(NULL, (pbns_view){encoded, encoded_size},
                measured.selection_digest) == PBNS_OK);
  assert(sha256(NULL, measured.event_log, measured.event_log_digest) ==
         PBNS_OK);
  return measured;
}

static size_t offset_of(pbns_view whole, UsefulBufC part) {
  const uintptr_t start = (uintptr_t)whole.ptr;
  const uintptr_t pointer = (uintptr_t)part.ptr;
  assert(pointer >= start && pointer < start + whole.len);
  return (size_t)(pointer - start);
}

static void reject_encryption_mutations(const pbns_crypto *recipient,
                                        uint8_t *message, size_t message_size,
                                        pbns_view kid, pbns_view aad) {
  QCBORDecodeContext decoder = {0};
  UsefulBufC body_protected = {0};
  UsefulBufC ciphertext = {0};
  UsefulBufC recipient_protected = {0};
  UsefulBufC found_kid = {0};
  UsefulBufC ephemeral_x = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){message, message_size},
                   QCBOR_DECODE_MODE_NORMAL);
  QCBORDecode_EnterArray(&decoder, NULL);
  QCBORDecode_GetByteString(&decoder, &body_protected);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_GetByteString(&decoder, &ciphertext);
  QCBORDecode_EnterArray(&decoder, NULL);
  QCBORDecode_EnterArray(&decoder, NULL);
  QCBORDecode_GetByteString(&decoder, &recipient_protected);
  QCBORDecode_EnterMap(&decoder, NULL);
  QCBORDecode_GetByteStringInMapN(&decoder, 4, &found_kid);
  QCBORDecode_EnterMapFromMapN(&decoder, -1);
  QCBORDecode_GetByteStringInMapN(&decoder, -2, &ephemeral_x);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_ExitMap(&decoder);
  QCBORDecode_ExitArray(&decoder);
  QCBORDecode_ExitArray(&decoder);
  QCBORDecode_ExitArray(&decoder);
  assert(QCBORDecode_Finish(&decoder) == QCBOR_SUCCESS);
  const size_t offsets[] = {offset_of((pbns_view){message, message_size},
                                     body_protected) +
                                body_protected.len - 1U,
                            offset_of((pbns_view){message, message_size},
                                      ciphertext),
                            offset_of((pbns_view){message, message_size},
                                      recipient_protected) +
                                recipient_protected.len - 1U,
                            offset_of((pbns_view){message, message_size},
                                      found_kid),
                            offset_of((pbns_view){message, message_size},
                                      ephemeral_x)};
  uint8_t *plaintext = malloc(PBNS_ENCRYPT_MAX_MESSAGE);
  assert(plaintext != NULL);
  for (size_t index = 0U; index < ARRAY_COUNT(offsets); ++index) {
    message[offsets[index]] ^= 1U;
    size_t written = SIZE_MAX;
    assert(pbns_decrypt_for_recipient(
               recipient, kid, (pbns_view){message, message_size}, aad,
               (pbns_buffer){plaintext, 0U,
                             PBNS_ENCRYPT_MAX_MESSAGE},
               &written) != PBNS_OK);
    assert(written == 0U);
    message[offsets[index]] ^= 1U;
  }
  free(plaintext);
}

static void test_one_envelope_and_rejections(void) {
  EVP_PKEY *host_key = new_p256_key();
  EVP_PKEY *recipient_key = new_p256_key();
  bounded_crypto_context host_context = {0};
  bounded_crypto_context recipient_context = {0};
  const pbns_crypto host = bounded_key(host_key, &host_context);
  const pbns_crypto recipient = bounded_key(recipient_key, &recipient_context);
  pbns_attestation_challenge challenge = make_challenge(0x11U, 0x33U);
  pbns_inventory_report report = make_report(&challenge);
  const size_t event_log_capacity = PBNS_FRAME_V1_DATA_PAYLOAD_MAX + 2048U;
  uint8_t *event_log = calloc(1U, event_log_capacity);
  assert(event_log != NULL);
  const size_t event_log_size =
      make_valid_event_log(event_log, event_log_capacity,
                           event_log_capacity - 119U);
  pbns_measured_boot_evidence measured =
      make_measured(&challenge, event_log, event_log_size);
  static const uint8_t ak_name[] = {0x00U, 0x0bU, 0xaaU, 0xaaU};
  static const uint8_t ak_reference[] = "AK-CERTIFICATE-REFERENCE-A";
  test_arenas arenas = arenas_new();
  test_seams seams = {0};
  seams.message_capacity = PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE;
  seams.message = calloc(1U, seams.message_capacity);
  assert(seams.message != NULL);
  uint8_t submitted_evidence_digest[32] = {0};
  fill(submitted_evidence_digest, sizeof(submitted_evidence_digest), 0xa5U);
  const pbns_attestation_submission submission = {
      .inventory_report = &report,
      .measured_boot = &measured,
      .ak_name = {ak_name, sizeof(ak_name)},
      .ak_reference = {ak_reference, sizeof(ak_reference) - 1U},
      .host_signer = &host,
      .recipient_encrypter = &recipient,
      .sha256 = sha256,
      .quote = quote_seam,
      .consume = consume_seam,
      .send_data = send_seam,
      .evidence_digest = {submitted_evidence_digest, 0U,
                          sizeof(submitted_evidence_digest)},
      .quote_context = &seams,
      .consume_context = &seams,
      .send_context = &seams,
      .host_signer_context_region = {
          (const uint8_t *)&host_context, sizeof(host_context)},
      .recipient_encrypter_context_region = {
          (const uint8_t *)&recipient_context, sizeof(recipient_context)},
      .quote_context_region = {(const uint8_t *)&seams, sizeof(seams)},
      .consume_context_region = {(const uint8_t *)&seams, sizeof(seams)},
      .send_context_region = {(const uint8_t *)&seams, sizeof(seams)},
  };
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &arenas.workspace) == PBNS_OK);
  assert(challenge.consumed && seams.consume_calls == 1U &&
         seams.quote_calls == 1U && seams.send_calls > 1U && seams.final_seen &&
         seams.final_count == 1U);
  assert(seams.selection_count == challenge.selection_count);
  assert(memcmp(seams.selection, challenge.selection_items,
                challenge.selection_count * sizeof(challenge.selection_items[0])) ==
         0);
  uint8_t report_encoding[PBNS_INVENTORY_ENCODED_MAX_SIZE] = {0};
  size_t report_size = 0U;
  uint8_t report_digest[32] = {0};
  uint8_t qualifying_scratch[256] = {0};
  uint8_t expected_qualifying[32] = {0};
  assert(pbns_inventory_encode(
             &report,
             (pbns_buffer){report_encoding, 0U, sizeof(report_encoding)},
             &report_size) == PBNS_OK);
  assert(sha256(NULL, (pbns_view){report_encoding, report_size},
                report_digest) == PBNS_OK);
  assert(pbns_attestation_qualifying_data(
             sha256, NULL, &challenge.request_id, challenge.verifier_nonce,
             report_digest, measured.selection_digest,
             measured.event_log_digest,
             (pbns_buffer){qualifying_scratch, 0U,
                           sizeof(qualifying_scratch)},
             expected_qualifying) == PBNS_OK);
  assert(memcmp(seams.qualifying_data, expected_qualifying,
                sizeof(expected_qualifying)) == 0);
  arenas_assert_wiped(&arenas);

  uint8_t encryption_aad[256] = {0};
  size_t encryption_aad_size = 0U;
  assert(pbns_attestation_encrypt_aad(
             &challenge,
             (pbns_buffer){encryption_aad, 0U, sizeof(encryption_aad)},
             &encryption_aad_size) == PBNS_OK);
  uint8_t *signed_object = calloc(
      1U, PBNS_ENCRYPT_MAX_MESSAGE);
  assert(signed_object != NULL);
  size_t signed_size = 0U;
  const pbns_view kid = {challenge.recipient_kid,
                         challenge.recipient_kid_len};
  assert(pbns_decrypt_for_recipient(
             &recipient, kid, (pbns_view){seams.message, seams.message_size},
             (pbns_view){encryption_aad, encryption_aad_size},
             (pbns_buffer){signed_object, 0U,
                           PBNS_ENCRYPT_MAX_MESSAGE},
             &signed_size) == PBNS_OK);
  uint8_t sign_aad[256] = {0};
  size_t sign_aad_size = 0U;
  assert(pbns_attestation_sign_aad(
             &challenge, (pbns_view){ak_name, sizeof(ak_name)},
             (pbns_buffer){sign_aad, 0U, sizeof(sign_aad)}, &sign_aad_size) ==
         PBNS_OK);
  pbns_view evidence = {0};
  assert(pbns_sign1_verify(&host, (pbns_view){signed_object, signed_size},
                           (pbns_view){sign_aad, sign_aad_size},
                           &evidence) == PBNS_OK);
  uint8_t independently_hashed_evidence[32] = {0};
  assert(sha256(NULL, (pbns_view){signed_object, signed_size},
                independently_hashed_evidence) == PBNS_OK);
  assert(memcmp(submitted_evidence_digest, independently_hashed_evidence,
                sizeof(submitted_evidence_digest)) == 0);
  assert(find_bytes(evidence.ptr, evidence.len, event_log,
                    event_log_size) != NULL);
  assert(find_bytes(evidence.ptr, evidence.len, ak_reference,
                    sizeof(ak_reference) - 1U) != NULL);
  assert(find_bytes(evidence.ptr, evidence.len,
                    (const uint8_t *)"TPM2B_ATTEST-QUOTE-A", 20U) != NULL);
  assert(find_bytes(evidence.ptr, evidence.len, report.board_model_digest,
                    sizeof(report.board_model_digest)) != NULL);
  for (size_t index = 0U; index < measured.pcr_count; ++index) {
    assert(find_bytes(evidence.ptr, evidence.len,
                      measured.pcrs[index].digest,
                      measured.pcrs[index].digest_size) != NULL);
  }

  uint8_t wrong_aad[256] = {0};
  memcpy(wrong_aad, encryption_aad, encryption_aad_size);
  wrong_aad[encryption_aad_size - 1U] ^= 1U;
  size_t rejected_size = SIZE_MAX;
  assert(pbns_decrypt_for_recipient(
             &recipient, kid, (pbns_view){seams.message, seams.message_size},
             (pbns_view){wrong_aad, encryption_aad_size},
             (pbns_buffer){signed_object, 0U,
                           PBNS_ENCRYPT_MAX_MESSAGE},
             &rejected_size) == PBNS_ERR_AUTHENTICATION);
  assert(rejected_size == 0U);
  static const uint8_t wrong_kid[] = "wrong-recipient";
  assert(pbns_decrypt_for_recipient(
             &recipient, (pbns_view){wrong_kid, sizeof(wrong_kid) - 1U},
             (pbns_view){seams.message, seams.message_size},
             (pbns_view){encryption_aad, encryption_aad_size},
             (pbns_buffer){signed_object, 0U,
                           PBNS_ENCRYPT_MAX_MESSAGE},
             &rejected_size) != PBNS_OK);
  reject_encryption_mutations(
      &recipient, seams.message, seams.message_size, kid,
      (pbns_view){encryption_aad, encryption_aad_size});

  sign_aad[sign_aad_size - 1U] ^= 1U;
  assert(pbns_sign1_verify(&host, (pbns_view){signed_object, signed_size},
                           (pbns_view){sign_aad, sign_aad_size},
                           &evidence) != PBNS_OK);
  sign_aad[sign_aad_size - 1U] ^= 1U;
  const uint8_t *needles[] = {report.board_model_digest,
                              measured.pcrs[0].digest, event_log,
                              (const uint8_t *)"TPM2B_ATTEST-QUOTE-A"};
  const size_t needle_sizes[] = {sizeof(report.board_model_digest), 32U,
                                 event_log_size, 20U};
  assert(pbns_decrypt_for_recipient(
             &recipient, kid, (pbns_view){seams.message, seams.message_size},
             (pbns_view){encryption_aad, encryption_aad_size},
             (pbns_buffer){signed_object, 0U,
                           PBNS_ENCRYPT_MAX_MESSAGE},
             &signed_size) == PBNS_OK);
  for (size_t index = 0U; index < ARRAY_COUNT(needles); ++index) {
    uint8_t *location = find_bytes(signed_object, signed_size,
                                   needles[index], needle_sizes[index]);
    assert(location != NULL);
    location[0] ^= 1U;
    assert(pbns_sign1_verify(&host, (pbns_view){signed_object, signed_size},
                             (pbns_view){sign_aad, sign_aad_size},
                             &evidence) != PBNS_OK);
    location[0] ^= 1U;
  }

  pbns_attestation_challenge challenge_b = make_challenge(0x11U, 0x33U);
  pbns_inventory_report report_b = make_report(&challenge_b);
  fill(report_b.board_model_digest, sizeof(report_b.board_model_digest), 0xc2U);
  uint8_t *event_log_b = malloc(event_log_size);
  assert(event_log_b != NULL);
  memcpy(event_log_b, event_log, event_log_size);
  event_log_b[event_log_size - 1U] ^= 1U;
  pbns_measured_boot_evidence measured_b =
      make_measured(&challenge_b, event_log_b, event_log_size);
  fill(measured_b.pcrs[0].digest, sizeof(measured_b.pcrs[0].digest), 0x99U);
  test_seams seams_b = {.quote_variant = true};
  seams_b.message_capacity = PBNS_ENCRYPT_MAX_MESSAGE;
  seams_b.message = calloc(1U, seams_b.message_capacity);
  assert(seams_b.message != NULL);
  uint8_t evidence_digest_b[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  const pbns_attestation_submission submission_b = {
      .inventory_report = &report_b,
      .measured_boot = &measured_b,
      .ak_name = {ak_name, sizeof(ak_name)},
      .ak_reference = {ak_name, sizeof(ak_name)},
      .host_signer = &host,
      .recipient_encrypter = &recipient,
      .sha256 = sha256,
      .quote = quote_seam,
      .consume = consume_seam,
      .send_data = send_seam,
      .evidence_digest = {evidence_digest_b, 0U, sizeof(evidence_digest_b)},
      .quote_context = &seams_b,
      .consume_context = &seams_b,
      .send_context = &seams_b,
      .host_signer_context_region = {
          (const uint8_t *)&host_context, sizeof(host_context)},
      .recipient_encrypter_context_region = {
          (const uint8_t *)&recipient_context, sizeof(recipient_context)},
      .quote_context_region = {(const uint8_t *)&seams_b, sizeof(seams_b)},
      .consume_context_region = {(const uint8_t *)&seams_b, sizeof(seams_b)},
      .send_context_region = {(const uint8_t *)&seams_b, sizeof(seams_b)},
  };
  assert(pbns_attestation_submit(&challenge_b, &submission_b,
                                 &arenas.workspace) == PBNS_OK);
  uint8_t *signed_b = calloc(1U, PBNS_ENCRYPT_MAX_MESSAGE);
  assert(signed_b != NULL);
  size_t signed_b_size = 0U;
  assert(pbns_decrypt_for_recipient(
             &recipient, kid,
             (pbns_view){seams_b.message, seams_b.message_size},
             (pbns_view){encryption_aad, encryption_aad_size},
             (pbns_buffer){signed_b, 0U, PBNS_ENCRYPT_MAX_MESSAGE},
             &signed_b_size) == PBNS_OK);
  const uint8_t *needles_b[] = {report_b.board_model_digest,
                                measured_b.pcrs[0].digest, event_log_b,
                                (const uint8_t *)"TPM2B_ATTEST-QUOTE-B"};
  for (size_t index = 0U; index < ARRAY_COUNT(needles); ++index) {
    uint8_t *location_a = find_bytes(signed_object, signed_size,
                                     needles[index], needle_sizes[index]);
    uint8_t *location_b = find_bytes(signed_b, signed_b_size,
                                     needles_b[index], needle_sizes[index]);
    assert(location_a != NULL && location_b != NULL);
    memcpy(location_a, location_b, needle_sizes[index]);
    assert(pbns_sign1_verify(&host, (pbns_view){signed_object, signed_size},
                             (pbns_view){sign_aad, sign_aad_size},
                             &evidence) != PBNS_OK);
    memcpy(location_a, needles[index], needle_sizes[index]);
  }
  free(signed_b);
  free(seams_b.message);
  free(event_log_b);

  fill(submitted_evidence_digest, sizeof(submitted_evidence_digest), 0xa5U);
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &arenas.workspace) == PBNS_ERR_ARGUMENT);
  assert_zero(submitted_evidence_digest, sizeof(submitted_evidence_digest));
  assert(seams.consume_calls == 1U);
  arenas_assert_wiped(&arenas);

  free(signed_object);
  free(seams.message);
  free(event_log);
  arenas_free(&arenas);
  EVP_PKEY_free(recipient_key);
  EVP_PKEY_free(host_key);
}

static void test_limits_and_failure_wiping(void) {
  EVP_PKEY *key = new_p256_key();
  bounded_crypto_context crypto_context = {0};
  const pbns_crypto crypto = bounded_key(key, &crypto_context);
  pbns_attestation_challenge challenge = make_challenge(0x41U, 0x43U);
  pbns_inventory_report report = make_report(&challenge);
  uint8_t event_log[256] = {0};
  const size_t event_log_size =
      make_valid_event_log(event_log, sizeof(event_log), 3U);
  pbns_measured_boot_evidence measured =
      make_measured(&challenge, event_log, event_log_size);
  test_arenas arenas = arenas_new();
  fill(arenas.evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE, 0xa5U);
  test_seams seams = {.fail_send = true};
  seams.message = calloc(1U, PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE);
  assert(seams.message != NULL);
  seams.message_capacity = PBNS_ATTESTATION_ENCRYPTED_MAX_SIZE;
  static const uint8_t ak_name[] = {0x00U, 0x0bU, 1U};
  static const uint8_t ak_reference[] = "AK-REF";
  uint8_t evidence_digest[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  const pbns_attestation_submission submission = {
      .inventory_report = &report,
      .measured_boot = &measured,
      .ak_name = {ak_name, sizeof(ak_name)},
      .ak_reference = {ak_reference, sizeof(ak_reference) - 1U},
      .host_signer = &crypto,
      .recipient_encrypter = &crypto,
      .sha256 = sha256,
      .quote = quote_seam,
      .consume = consume_seam,
      .send_data = send_seam,
      .evidence_digest = {evidence_digest, 0U, sizeof(evidence_digest)},
      .quote_context = &seams,
      .consume_context = &seams,
      .send_context = &seams,
      .host_signer_context_region = {
          (const uint8_t *)&crypto_context, sizeof(crypto_context)},
      .recipient_encrypter_context_region = {
          (const uint8_t *)&crypto_context, sizeof(crypto_context)},
      .quote_context_region = {(const uint8_t *)&seams, sizeof(seams)},
      .consume_context_region = {(const uint8_t *)&seams, sizeof(seams)},
      .send_context_region = {(const uint8_t *)&seams, sizeof(seams)},
  };
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &arenas.workspace) == PBNS_ERR_TRANSPORT);
  assert_zero(evidence_digest, sizeof(evidence_digest));
  arenas_assert_wiped(&arenas);

  pbns_attestation_submission failure_submission = submission;
  failure_submission.sha256 = sha256_seam;
  failure_submission.sha256_context = &seams;
  failure_submission.sha256_context_region =
      (pbns_view){(const uint8_t *)&seams, sizeof(seams)};
  seams.fail_send = false;
  for (size_t sha_call = 1U; sha_call <= 5U; ++sha_call) {
    challenge = make_challenge((uint8_t)(0x20U + sha_call), 0x23U);
    seams.consume_calls = 0U;
    seams.sha_calls = 0U;
    seams.fail_sha_call = sha_call;
    fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
    assert(pbns_attestation_submit(&challenge, &failure_submission,
                                   &arenas.workspace) == PBNS_ERR_CRYPTO);
    assert_zero(evidence_digest, sizeof(evidence_digest));
    arenas_assert_wiped(&arenas);
  }
  seams.fail_sha_call = 0U;

  challenge = make_challenge(0x31U, 0x33U);
  seams.consume_calls = 0U;
  seams.sha_calls = 0U;
  seams.fail_quote = true;
  fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
  assert(pbns_attestation_submit(&challenge, &failure_submission,
                                 &arenas.workspace) == PBNS_ERR_CRYPTO);
  assert_zero(evidence_digest, sizeof(evidence_digest));
  seams.fail_quote = false;

  challenge = make_challenge(0x35U, 0x37U);
  seams.consume_calls = 0U;
  seams.sha_calls = 0U;
  crypto_context.fail_sign = true;
  fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
  assert(pbns_attestation_submit(&challenge, &failure_submission,
                                 &arenas.workspace) == PBNS_ERR_CRYPTO);
  assert_zero(evidence_digest, sizeof(evidence_digest));
  crypto_context.fail_sign = false;

  const size_t invalid_sign_lengths[] = {
      0U, arenas.workspace.signed_evidence.cap + 1U, SIZE_MAX};
  crypto_context.override_sign_written = true;
  for (size_t index = 0U; index < ARRAY_COUNT(invalid_sign_lengths); ++index) {
    challenge = make_challenge((uint8_t)(0x70U + index), 0x38U);
    seams.consume_calls = 0U;
    seams.sha_calls = 0U;
    seams.send_calls = 0U;
    crypto_context.sign_calls = 0U;
    crypto_context.encrypt_calls = 0U;
    crypto_context.sign_written = invalid_sign_lengths[index];
    fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
    assert(pbns_attestation_submit(&challenge, &failure_submission,
                                   &arenas.workspace) == PBNS_ERR_LIMIT);
    assert(seams.sha_calls == 4U && crypto_context.sign_calls == 1U &&
           crypto_context.encrypt_calls == 0U && seams.send_calls == 0U);
    assert_zero(evidence_digest, sizeof(evidence_digest));
    arenas_assert_wiped(&arenas);
  }
  crypto_context.override_sign_written = false;

  challenge = make_challenge(0x39U, 0x3bU);
  seams.consume_calls = 0U;
  seams.sha_calls = 0U;
  crypto_context.fail_encrypt = true;
  fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
  assert(pbns_attestation_submit(&challenge, &failure_submission,
                                 &arenas.workspace) == PBNS_ERR_CRYPTO);
  assert_zero(evidence_digest, sizeof(evidence_digest));
  crypto_context.fail_encrypt = false;

  const size_t invalid_encrypt_lengths[] = {
      0U, arenas.workspace.ciphertext.cap + 1U, SIZE_MAX};
  crypto_context.override_encrypt_written = true;
  for (size_t index = 0U; index < ARRAY_COUNT(invalid_encrypt_lengths);
       ++index) {
    challenge = make_challenge((uint8_t)(0x80U + index), 0x3cU);
    seams.consume_calls = 0U;
    seams.sha_calls = 0U;
    seams.send_calls = 0U;
    crypto_context.sign_calls = 0U;
    crypto_context.encrypt_calls = 0U;
    crypto_context.encrypt_written = invalid_encrypt_lengths[index];
    fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
    assert(pbns_attestation_submit(&challenge, &failure_submission,
                                   &arenas.workspace) == PBNS_ERR_LIMIT);
    assert(seams.sha_calls == 5U && crypto_context.sign_calls == 1U &&
           crypto_context.encrypt_calls == 1U && seams.send_calls == 0U);
    assert_zero(evidence_digest, sizeof(evidence_digest));
    arenas_assert_wiped(&arenas);
  }
  crypto_context.override_encrypt_written = false;

  challenge = make_challenge(0x3dU, 0x3fU);
  seams.consume_calls = 0U;
  seams.sha_calls = 0U;
  seams.fail_consume = true;
  fill(evidence_digest, sizeof(evidence_digest), 0xa5U);
  assert(pbns_attestation_submit(&challenge, &failure_submission,
                                 &arenas.workspace) == PBNS_ERR_REPLAY);
  assert_zero(evidence_digest, sizeof(evidence_digest));
  seams.fail_consume = false;

  challenge = make_challenge(0x51U, 0x53U);
  measured.event_log.len = PBNS_MEASURED_BOOT_EVENT_LOG_MAX_SIZE + 1U;
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &arenas.workspace) == PBNS_ERR_ARGUMENT);
  assert(!challenge.consumed);
  arenas_assert_wiped(&arenas);

  measured.event_log.len = event_log_size;
  challenge = make_challenge(0x61U, 0x63U);
  pbns_attestation_workspace too_small = arenas.workspace;
  too_small.inventory.cap = PBNS_INVENTORY_ENCODED_MAX_SIZE - 1U;
  assert(pbns_attestation_submit(&challenge, &submission, &too_small) ==
         PBNS_ERR_ARGUMENT);
  assert(!challenge.consumed);
  arenas_assert_wiped(&arenas);

  measured.event_log = (pbns_view){event_log, event_log_size - 1U};
  assert(sha256(NULL, measured.event_log, measured.event_log_digest) == PBNS_OK);
  challenge = make_challenge(0x71U, 0x73U);
  seams.consume_calls = 0U;
  seams.quote_calls = 0U;
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &arenas.workspace) == PBNS_ERR_FORMAT);
  assert(challenge.consumed && seams.consume_calls == 1U &&
         seams.quote_calls == 0U);
  arenas_assert_wiped(&arenas);

  static const uint8_t non_event[] = "not an Event2 log";
  measured.event_log = (pbns_view){non_event, sizeof(non_event) - 1U};
  assert(sha256(NULL, measured.event_log, measured.event_log_digest) == PBNS_OK);
  challenge = make_challenge(0x81U, 0x83U);
  seams.consume_calls = 0U;
  seams.quote_calls = 0U;
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &arenas.workspace) == PBNS_ERR_FORMAT);
  assert(challenge.consumed && seams.consume_calls == 1U &&
         seams.quote_calls == 0U);
  arenas_assert_wiped(&arenas);

  measured.event_log = (pbns_view){event_log, event_log_size};
  assert(sha256(NULL, measured.event_log, measured.event_log_digest) == PBNS_OK);
  challenge = make_challenge(0x91U, 0x93U);
  seams.consume_calls = 0U;
  pbns_attestation_workspace aliased = arenas.workspace;
  aliased.inventory.ptr = (uint8_t *)&challenge;
  assert(pbns_attestation_submit(&challenge, &submission, &aliased) ==
         PBNS_ERR_ARGUMENT);
  assert(!challenge.consumed && seams.consume_calls == 0U &&
         challenge.request_id.bytes[0] == 0x91U);

  challenge = make_challenge(0xa1U, 0xa3U);
  pbns_attestation_workspace oversized = arenas.workspace;
  oversized.inventory.cap = PBNS_INVENTORY_ENCODED_MAX_SIZE + 1U;
  assert(pbns_attestation_submit(&challenge, &submission, &oversized) ==
         PBNS_ERR_ARGUMENT);
  assert(!challenge.consumed && seams.consume_calls == 0U);
  arenas_assert_wiped(&arenas);

  challenge = make_challenge(0xb1U, 0xb3U);
  seams.consume_calls = 0U;
  seams.quote_calls = 0U;
  seams.send_calls = 0U;
  fill(arenas.evidence, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE, 0xa5U);
  pbns_attestation_workspace descriptor_aliased = arenas.workspace;
  descriptor_aliased.inventory.ptr = (uint8_t *)&descriptor_aliased;
  const pbns_attestation_workspace descriptor_aliased_before =
      descriptor_aliased;
  assert(pbns_attestation_submit(&challenge, &submission,
                                 &descriptor_aliased) == PBNS_ERR_ARGUMENT);
  assert(!challenge.consumed && seams.consume_calls == 0U &&
         seams.quote_calls == 0U && seams.send_calls == 0U);
  assert(memcmp(&descriptor_aliased, &descriptor_aliased_before,
                sizeof(descriptor_aliased)) == 0);
  for (size_t index = 0U; index < PBNS_ATTESTATION_EVIDENCE_MAX_SIZE;
       ++index) {
    assert(arenas.evidence[index] == 0xa5U);
  }
  memset(arenas.evidence, 0, PBNS_ATTESTATION_EVIDENCE_MAX_SIZE);

  challenge = make_challenge(0xc1U, 0xc3U);
  uint8_t digest_alias_storage[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  pbns_attestation_submission digest_alias = submission;
  digest_alias.evidence_digest =
      (pbns_buffer){arenas.inventory, 0U, PBNS_ATTESTATION_DIGEST_SIZE};
  fill(arenas.inventory, PBNS_ATTESTATION_DIGEST_SIZE, 0xa5U);
  uint8_t inventory_before[PBNS_ATTESTATION_DIGEST_SIZE] = {0};
  memcpy(inventory_before, arenas.inventory, sizeof(inventory_before));
  assert(pbns_attestation_submit(&challenge, &digest_alias,
                                 &arenas.workspace) == PBNS_ERR_ARGUMENT);
  assert(memcmp(arenas.inventory, inventory_before,
                sizeof(inventory_before)) == 0);
  challenge = make_challenge(0xd1U, 0xd3U);
  const pbns_attestation_challenge challenge_before = challenge;
  digest_alias.evidence_digest =
      (pbns_buffer){challenge.request_id.bytes, 0U,
                    PBNS_ATTESTATION_DIGEST_SIZE};
  assert(pbns_attestation_submit(&challenge, &digest_alias,
                                 &arenas.workspace) == PBNS_ERR_ARGUMENT);
  assert(memcmp(&challenge, &challenge_before, sizeof(challenge)) == 0);
  digest_alias.evidence_digest =
      (pbns_buffer){digest_alias_storage, 0U,
                    PBNS_ATTESTATION_DIGEST_SIZE - 1U};
  fill(digest_alias_storage, sizeof(digest_alias_storage), 0xa5U);
  assert(pbns_attestation_submit(&challenge, &digest_alias,
                                 &arenas.workspace) == PBNS_ERR_ARGUMENT);
  assert(digest_alias_storage[0] == 0xa5U);

  challenge = make_challenge(0xe1U, 0xe3U);
  digest_alias = submission;
  digest_alias.quote_context_region =
      (pbns_view){(const uint8_t *)&seams, sizeof(seams)};
  digest_alias.evidence_digest =
      (pbns_buffer){(uint8_t *)&seams, 0U, PBNS_ATTESTATION_DIGEST_SIZE};
  const test_seams seams_before = seams;
  assert(pbns_attestation_submit(&challenge, &digest_alias,
                                 &arenas.workspace) == PBNS_ERR_ARGUMENT);
  assert(memcmp(&seams, &seams_before, sizeof(seams)) == 0);
  free(seams.message);
  arenas_free(&arenas);
  EVP_PKEY_free(key);
}

int main(void) {
  test_rejects_invalid_encrypt_callback_lengths();
  test_cose_message_profiles();
  test_exact_aad_and_qualifying_data();
  test_complete_challenge_profile_mutants();
  test_genuine_go_challenge_vector();
  test_challenge_binding_and_canonicality();
  test_one_envelope_and_rejections();
  test_limits_and_failure_wiping();
  return EXIT_SUCCESS;
}
