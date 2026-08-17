#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "pbns/recovery_manifest.h"

static const uint8_t policy_authorization[] = {0xa1U, 0x01U, 0x02U};
static const uint8_t recovery_key_id[] = "recovery-key-2026";
static const uint8_t policy_key_id[] = "policy-key-2026";

static void fill_nonzero(uint8_t *output, size_t length, uint8_t first) {
  for (size_t index = 0U; index < length; ++index) {
    output[index] = (uint8_t)(first + (uint8_t)index);
  }
}

static pbns_recovery_manifest valid_manifest(void) {
  pbns_recovery_manifest manifest = {0};
  fill_nonzero(manifest.request_id, sizeof(manifest.request_id), 0x10U);
  fill_nonzero(manifest.host_binding, sizeof(manifest.host_binding), 0x20U);
  fill_nonzero(manifest.nonce, sizeof(manifest.nonce), 0x40U);
  fill_nonzero(manifest.artifact_digest, sizeof(manifest.artifact_digest),
               0x60U);
  manifest.artifact_version = 7U;
  manifest.image_size = 16385U;
  manifest.chunk_size = PBNS_RECOVERY_MANIFEST_CHUNK_SIZE;
  manifest.minimum_version = 5U;
  manifest.not_before_ns = 1000;
  manifest.not_after_ns = 2000;
  manifest.policy_authorization =
      (pbns_view){policy_authorization, sizeof(policy_authorization)};
  manifest.policy_key_id =
      (pbns_view){policy_key_id, sizeof(policy_key_id) - 1U};
  return manifest;
}

static pbns_recovery_manifest_expectation
valid_expectation(const pbns_recovery_manifest *manifest) {
  pbns_recovery_manifest_expectation expectation = {0};
  memcpy(expectation.request_id, manifest->request_id,
         sizeof(expectation.request_id));
  memcpy(expectation.host_binding, manifest->host_binding,
         sizeof(expectation.host_binding));
  memcpy(expectation.nonce, manifest->nonce, sizeof(expectation.nonce));
  expectation.recovery_signing_key_id =
      (pbns_view){recovery_key_id, sizeof(recovery_key_id) - 1U};
  expectation.expected_policy_key_id = manifest->policy_key_id;
  expectation.current_version = 6U;
  expectation.trusted_time = (pbns_time_interval){1100, 1900};
  return expectation;
}

static size_t encode_manifest(const pbns_recovery_manifest *manifest,
                              uint8_t *output, size_t capacity) {
  size_t written = 0U;
  assert(pbns_recovery_manifest_encode(manifest,
                                       (pbns_buffer){output, 0U, capacity},
                                       &written) == PBNS_OK);
  assert(written > 0U);
  return written;
}

static void assert_same_manifest(const pbns_recovery_manifest *left,
                                 const pbns_recovery_manifest *right) {
  assert(memcmp(left->request_id, right->request_id,
                sizeof(left->request_id)) == 0);
  assert(memcmp(left->host_binding, right->host_binding,
                sizeof(left->host_binding)) == 0);
  assert(memcmp(left->nonce, right->nonce, sizeof(left->nonce)) == 0);
  assert(memcmp(left->artifact_digest, right->artifact_digest,
                sizeof(left->artifact_digest)) == 0);
  assert(left->artifact_version == right->artifact_version);
  assert(left->image_size == right->image_size);
  assert(left->chunk_size == right->chunk_size);
  assert(left->minimum_version == right->minimum_version);
  assert(left->not_before_ns == right->not_before_ns);
  assert(left->not_after_ns == right->not_after_ns);
  assert(left->policy_authorization.len == right->policy_authorization.len);
  assert(memcmp(left->policy_authorization.ptr, right->policy_authorization.ptr,
                left->policy_authorization.len) == 0);
  assert(left->policy_key_id.len == right->policy_key_id.len);
  assert(memcmp(left->policy_key_id.ptr, right->policy_key_id.ptr,
                left->policy_key_id.len) == 0);
}

static void test_canonical_round_trip_and_policy(void) {
  pbns_recovery_manifest original = valid_manifest();
  pbns_recovery_manifest_expectation expectation = valid_expectation(&original);
  uint8_t encoded[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t scratch[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  const size_t encoded_size =
      encode_manifest(&original, encoded, sizeof(encoded));
  pbns_recovery_manifest decoded = {0};
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)}, &decoded) == PBNS_OK);
  assert_same_manifest(&original, &decoded);

  expectation.request_id[0] ^= 1U;
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_AUTHENTICATION);
  expectation = valid_expectation(&original);
  expectation.host_binding[0] ^= 1U;
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_AUTHENTICATION);
  expectation = valid_expectation(&original);
  expectation.nonce[0] ^= 1U;
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_AUTHENTICATION);
  expectation = valid_expectation(&original);
  uint8_t wrong_policy_key[sizeof(policy_key_id) - 1U] = {0};
  memcpy(wrong_policy_key, policy_key_id, sizeof(wrong_policy_key));
  wrong_policy_key[0] ^= 1U;
  expectation.expected_policy_key_id =
      (pbns_view){wrong_policy_key, sizeof(wrong_policy_key)};
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_AUTHENTICATION);
  expectation = valid_expectation(&original);
  expectation.current_version = 8U;
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_REPLAY);
  expectation = valid_expectation(&original);
  expectation.trusted_time = (pbns_time_interval){900, 1900};
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_REPLAY);
  expectation.trusted_time = (pbns_time_interval){1100, 2100};
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_REPLAY);
}

static void test_encode_rejects_invalid_profile(void) {
  pbns_recovery_manifest manifest = valid_manifest();
  uint8_t encoded[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  size_t written = SIZE_MAX;

  manifest.image_size = 0U;
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  manifest = valid_manifest();
  manifest.image_size = PBNS_RECOVERY_MANIFEST_IMAGE_MAX + 1U;
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  manifest = valid_manifest();
  manifest.chunk_size = PBNS_RECOVERY_MANIFEST_CHUNK_SIZE - 1U;
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  manifest = valid_manifest();
  manifest.artifact_version = manifest.minimum_version - 1U;
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  manifest = valid_manifest();
  memset(manifest.artifact_digest, 0, sizeof(manifest.artifact_digest));
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  manifest = valid_manifest();
  manifest.not_after_ns = manifest.not_before_ns;
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  manifest = valid_manifest();
  manifest.policy_authorization = (pbns_view){NULL, 0U};
  assert(pbns_recovery_manifest_encode(
             &manifest, (pbns_buffer){encoded, 0U, sizeof(encoded)},
             &written) == PBNS_ERR_FORMAT);
  assert(written == 0U);
}

static size_t read_vector(const char *name, uint8_t *output, size_t capacity) {
  char path[256] = {0};
  const int path_size = snprintf(path, sizeof(path),
                                 "tests/vectors/recovery-manifest-v1/%s", name);
  assert(path_size > 0);
  assert((size_t)path_size < sizeof(path));
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  const size_t received = fread(output, 1U, capacity, file);
  assert(ferror(file) == 0);
  assert(received > 0U);
  assert(received < capacity);
  assert(fclose(file) == 0);
  return received;
}

static EVP_PKEY *load_key(const char *path, int private_key) {
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  EVP_PKEY *key = private_key != 0 ? PEM_read_PrivateKey(file, NULL, NULL, NULL)
                                   : PEM_read_PUBKEY(file, NULL, NULL, NULL);
  assert(fclose(file) == 0);
  assert(key != NULL);
  return key;
}

static void test_signed_manifest_verification(void) {
  pbns_recovery_manifest manifest = valid_manifest();
  pbns_recovery_manifest_expectation expectation = valid_expectation(&manifest);
  uint8_t payload[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t signed_manifest[PBNS_RECOVERY_MANIFEST_SIGNED_MAX_SIZE] = {0};
  uint8_t canonical[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t aad[PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE] = {0};
  const size_t payload_size =
      encode_manifest(&manifest, payload, sizeof(payload));
  size_t aad_size = 0U;
  assert(pbns_recovery_manifest_aad(&expectation,
                                    (pbns_buffer){aad, 0U, sizeof(aad)},
                                    &aad_size) == PBNS_OK);

  EVP_PKEY *private_key =
      load_key("tests/fixtures/keys/service-signing-test-private.pem", 1);
  EVP_PKEY *public_key =
      load_key("tests/fixtures/keys/service-signing-test-public.pem", 0);
  pbns_crypto signer = {0};
  pbns_crypto verifier = {0};
  assert(pbns_crypto_openssl_wrap(&signer, private_key) == PBNS_OK);
  assert(pbns_crypto_openssl_wrap(&verifier, public_key) == PBNS_OK);
  size_t signed_size = 0U;
  assert(pbns_sign1_sign(
             &signer, (pbns_view){payload, payload_size},
             (pbns_view){aad, aad_size},
             (pbns_buffer){signed_manifest, 0U, sizeof(signed_manifest)},
             &signed_size) == PBNS_OK);

  pbns_recovery_manifest decoded = {0};
  assert(pbns_recovery_manifest_verify_signed(
             &verifier, (pbns_view){signed_manifest, signed_size}, &expectation,
             (pbns_buffer){canonical, 0U, sizeof(canonical)},
             (pbns_buffer){aad, 0U, sizeof(aad)},
             &decoded) == PBNS_ERR_AUTHENTICATION);

  signed_manifest[signed_size - 1U] ^= 1U;
  assert(pbns_recovery_manifest_verify_signed(
             &verifier, (pbns_view){signed_manifest, signed_size}, &expectation,
             (pbns_buffer){canonical, 0U, sizeof(canonical)},
             (pbns_buffer){aad, 0U, sizeof(aad)},
             &decoded) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_recovery_manifest_verify_signed(
             &verifier, (pbns_view){payload, payload_size}, &expectation,
             (pbns_buffer){canonical, 0U, sizeof(canonical)},
             (pbns_buffer){aad, 0U, sizeof(aad)}, &decoded) != PBNS_OK);

  pbns_crypto_reset(&signer);
  pbns_crypto_reset(&verifier);
  EVP_PKEY_free(private_key);
  EVP_PKEY_free(public_key);
}

static void test_go_vector_matches_c_and_verifies(void) {
  pbns_recovery_manifest manifest = valid_manifest();
  pbns_recovery_manifest_expectation expectation = valid_expectation(&manifest);
  uint8_t encoded[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t vector_payload[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t signed_vector[PBNS_RECOVERY_MANIFEST_SIGNED_MAX_SIZE] = {0};
  uint8_t canonical[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t aad[PBNS_RECOVERY_MANIFEST_AAD_MAX_SIZE] = {0};
  const size_t encoded_size =
      encode_manifest(&manifest, encoded, sizeof(encoded));
  const size_t payload_size =
      read_vector("payload.cbor", vector_payload, sizeof(vector_payload));
  assert(payload_size == encoded_size);
  assert(memcmp(vector_payload, encoded, encoded_size) == 0);
  const size_t signed_size =
      read_vector("signed.cbor", signed_vector, sizeof(signed_vector));

  EVP_PKEY *public_key =
      load_key("tests/fixtures/keys/service-signing-test-public.pem", 0);
  pbns_crypto verifier = {0};
  assert(pbns_crypto_openssl_wrap(&verifier, public_key) == PBNS_OK);
  pbns_recovery_manifest decoded = {0};
  assert(pbns_recovery_manifest_verify_signed(
             &verifier, (pbns_view){signed_vector, signed_size}, &expectation,
             (pbns_buffer){canonical, 0U, sizeof(canonical)},
             (pbns_buffer){aad, 0U, sizeof(aad)}, &decoded) == PBNS_OK);
  assert_same_manifest(&manifest, &decoded);
  pbns_crypto_reset(&verifier);
  EVP_PKEY_free(public_key);
}

static void test_rejects_noncanonical_and_wrong_literals(void) {
  pbns_recovery_manifest manifest = valid_manifest();
  pbns_recovery_manifest_expectation expectation = valid_expectation(&manifest);
  uint8_t encoded[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t scratch[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  const size_t encoded_size =
      encode_manifest(&manifest, encoded, sizeof(encoded));
  pbns_recovery_manifest decoded = {0};

  const uint8_t architecture[] = PBNS_RECOVERY_ARCHITECTURE;
  const uint8_t format[] = PBNS_RECOVERY_FORMAT;
  uint8_t *architecture_at = NULL;
  uint8_t *format_at = NULL;
  for (size_t index = 0U; index + sizeof(architecture) - 1U <= encoded_size;
       ++index) {
    if (memcmp(encoded + index, architecture, sizeof(architecture) - 1U) == 0) {
      architecture_at = encoded + index;
    }
  }
  for (size_t index = 0U; index + sizeof(format) - 1U <= encoded_size;
       ++index) {
    if (memcmp(encoded + index, format, sizeof(format) - 1U) == 0) {
      format_at = encoded + index;
    }
  }
  assert(architecture_at != NULL);
  architecture_at[0] = 'a';
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_FORMAT);

  encode_manifest(&manifest, encoded, sizeof(encoded));
  format_at = NULL;
  for (size_t index = 0U; index + sizeof(format) - 1U <= encoded_size;
       ++index) {
    if (memcmp(encoded + index, format, sizeof(format) - 1U) == 0) {
      format_at = encoded + index;
    }
  }
  assert(format_at != NULL);
  format_at[0] = 'x';
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_FORMAT);
}

static void test_rejects_duplicate_key(void) {
  pbns_recovery_manifest manifest = valid_manifest();
  pbns_recovery_manifest_expectation expectation = valid_expectation(&manifest);
  uint8_t encoded[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  uint8_t scratch[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  const size_t encoded_size =
      encode_manifest(&manifest, encoded, sizeof(encoded));
  assert(encoded[0] == 0xacU);
  encoded[0] = 0xadU;
  encoded[encoded_size] = 0x0fU;
  encoded[encoded_size + 1U] = 0x19U;
  encoded[encoded_size + 2U] = 0x40U;
  encoded[encoded_size + 3U] = 0x00U;
  pbns_recovery_manifest decoded = {0};
  assert(pbns_recovery_manifest_decode_verified(
             (pbns_view){encoded, encoded_size + 4U}, &expectation,
             (pbns_buffer){scratch, 0U, sizeof(scratch)},
             &decoded) == PBNS_ERR_FORMAT);
}

static void test_invalid_arguments(void) {
  pbns_recovery_manifest manifest = valid_manifest();
  pbns_recovery_manifest_expectation expectation = valid_expectation(&manifest);
  uint8_t output[PBNS_RECOVERY_MANIFEST_ENCODED_MAX_SIZE] = {0};
  size_t written = SIZE_MAX;
  assert(pbns_recovery_manifest_encode(
             NULL, (pbns_buffer){output, 0U, sizeof(output)}, &written) ==
         PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  expectation.recovery_signing_key_id = (pbns_view){NULL, 0U};
  assert(pbns_recovery_manifest_aad(&expectation,
                                    (pbns_buffer){output, 0U, sizeof(output)},
                                    &written) == PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_canonical_round_trip_and_policy();
  test_encode_rejects_invalid_profile();
  test_signed_manifest_verification();
  test_go_vector_matches_c_and_verifies();
  test_rejects_noncanonical_and_wrong_literals();
  test_rejects_duplicate_key();
  test_invalid_arguments();
  return 0;
}
