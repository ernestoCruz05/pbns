#include "pbns/attestation_receipt.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

static size_t read_vector(const char *name, uint8_t *output, size_t capacity) {
  char path[256] = {0};
  const int length = snprintf(path, sizeof(path),
                              "tests/vectors/attestation-receipt-v1/%s", name);
  assert(length > 0 && (size_t)length < sizeof(path));
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  const size_t received = fread(output, 1U, capacity, file);
  assert(ferror(file) == 0 && received > 0U && received < capacity);
  assert(fclose(file) == 0);
  return received;
}

static EVP_PKEY *load_public(const char *path) {
  FILE *file = fopen(path, "rb");
  assert(file != NULL);
  EVP_PKEY *key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
  assert(fclose(file) == 0 && key != NULL);
  return key;
}

static pbns_attestation_receipt_expectation expectation(void) {
  static const uint8_t key_id[] = "receipt-vector-1";
  pbns_attestation_receipt_expectation value = {0};
  value.request_id[0] = 1U;
  value.verifier_nonce[0] = 2U;
  value.host_fingerprint[0] = 3U;
  value.evidence_digest[0] = 4U;
  value.baseline_id[0] = 5U;
  value.key_id = (pbns_view){key_id, sizeof(key_id) - 1U};
  return value;
}

static void test_go_receipt_and_binding_mutants(void) {
  uint8_t signed_receipt[PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE] = {0};
  uint8_t canonical[PBNS_ATTESTATION_RECEIPT_MAX_PAYLOAD_SIZE] = {0};
  uint8_t canonical_cose[PBNS_ATTESTATION_RECEIPT_MAX_SIGNED_SIZE] = {0};
  uint8_t aad[PBNS_ATTESTATION_RECEIPT_MAX_AAD_SIZE] = {0};
  const size_t signed_size =
      read_vector("receipt.cose", signed_receipt, sizeof(signed_receipt));
  EVP_PKEY *public_key = load_public(
      "tests/vectors/attestation-receipt-v1/public.pem");
  pbns_crypto verifier = {0};
  assert(pbns_crypto_openssl_wrap(&verifier, public_key) == PBNS_OK);
  pbns_attestation_receipt_workspace workspace = {
      .canonical_payload = {canonical, 0U, sizeof(canonical)},
      .canonical_cose = {canonical_cose, 0U, sizeof(canonical_cose)},
      .aad = {aad, 0U, sizeof(aad)}};
  pbns_attestation_receipt_result decoded = {
      .verdict = PBNS_ATTESTATION_RECEIPT_FAILURE,
      .display_state = PBNS_ATTESTATION_DISPLAY_FAILURE};
  pbns_attestation_receipt_expectation expected = expectation();
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, signed_size}, &expected,
             &workspace, &decoded) == PBNS_OK);
  assert(decoded.verdict == PBNS_ATTESTATION_RECEIPT_FULL);
  assert(decoded.reason_count == 0U);
  assert(decoded.display_state == PBNS_ATTESTATION_DISPLAY_FULL);
  const pbns_buffer saved_cose = workspace.canonical_cose;
  workspace.canonical_cose =
      (pbns_buffer){signed_receipt, 0U, sizeof(signed_receipt)};
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, signed_size}, &expected,
             &workspace, &decoded) == PBNS_ERR_ARGUMENT);
  workspace.canonical_cose = saved_cose;

  for (size_t mutant = 0U; mutant < 5U; ++mutant) {
    expected = expectation();
    uint8_t *bindings[] = {expected.request_id, expected.verifier_nonce,
                           expected.host_fingerprint, expected.evidence_digest,
                           expected.baseline_id};
    bindings[mutant][0] ^= 0x80U;
    assert(pbns_attestation_receipt_verify(
               &verifier, (pbns_view){signed_receipt, signed_size}, &expected,
               &workspace, &decoded) == PBNS_ERR_AUTHENTICATION);
  }
  expected = expectation();
  static const uint8_t wrong_kid[] = "receipt-vector-x";
  expected.key_id = (pbns_view){wrong_kid, sizeof(wrong_kid) - 1U};
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, signed_size}, &expected,
             &workspace, &decoded) == PBNS_ERR_AUTHENTICATION);

  EVP_PKEY *wrong_public =
      load_public("tests/fixtures/keys/service-signing-test-public.pem");
  pbns_crypto wrong_verifier = {0};
  assert(pbns_crypto_openssl_wrap(&wrong_verifier, wrong_public) == PBNS_OK);
  expected = expectation();
  assert(pbns_attestation_receipt_verify(
             &wrong_verifier, (pbns_view){signed_receipt, signed_size},
             &expected, &workspace, &decoded) == PBNS_ERR_AUTHENTICATION);
  pbns_crypto_reset(&wrong_verifier);
  EVP_PKEY_free(wrong_public);

  static const char *invalid_vectors[] = {
      "wrong-domain.cose",          "wrong-version.cose",
      "wrong-service.cose",         "wrong-algorithm.cose",
      "wrong-protected-kid.cose",   "unknown-protected.cose",
      "noncanonical-protected.cose", "duplicate-protected.cose",
      "nonempty-unprotected.cose",  "duplicate-reasons.cose",
      "unsorted-reasons.cose",      "duplicate-field.cose",
      "unknown-field.cose"};
  for (size_t index = 0U;
       index < sizeof(invalid_vectors) / sizeof(invalid_vectors[0]); ++index) {
    const size_t invalid_size = read_vector(
        invalid_vectors[index], signed_receipt, sizeof(signed_receipt));
    decoded.display_state = PBNS_ATTESTATION_DISPLAY_FULL;
    assert(pbns_attestation_receipt_verify(
               &verifier, (pbns_view){signed_receipt, invalid_size}, &expected,
               &workspace, &decoded) != PBNS_OK);
    assert(decoded.display_state == PBNS_ATTESTATION_DISPLAY_FAILURE);
  }
  const size_t reduced_size =
      read_vector("reduced.cose", signed_receipt, sizeof(signed_receipt));
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, reduced_size}, &expected,
             &workspace, &decoded) == PBNS_OK);
  assert(decoded.display_state == PBNS_ATTESTATION_DISPLAY_REDUCED);
  const size_t failure_size =
      read_vector("failure.cose", signed_receipt, sizeof(signed_receipt));
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, failure_size}, &expected,
             &workspace, &decoded) == PBNS_OK);
  assert(decoded.display_state == PBNS_ATTESTATION_DISPLAY_FAILURE);

  const size_t restored_size =
      read_vector("receipt.cose", signed_receipt, sizeof(signed_receipt));
  assert(restored_size == signed_size);
  signed_receipt[signed_size] = 0U;
  expected = expectation();
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, signed_size + 1U},
             &expected, &workspace, &decoded) != PBNS_OK);
  signed_receipt[signed_size - 1U] ^= 1U;
  assert(pbns_attestation_receipt_verify(
             &verifier, (pbns_view){signed_receipt, signed_size}, &expected,
             &workspace, &decoded) == PBNS_ERR_AUTHENTICATION);

  pbns_crypto_reset(&verifier);
  EVP_PKEY_free(public_key);
}

static void test_fabricated_result_has_no_display_authority(void) {
  pbns_attestation_receipt_result fabricated = {
      .verdict = PBNS_ATTESTATION_RECEIPT_FULL,
      .display_state = PBNS_ATTESTATION_DISPLAY_FAILURE};
  assert(fabricated.display_state == PBNS_ATTESTATION_DISPLAY_FAILURE);
  fabricated.verdict = PBNS_ATTESTATION_RECEIPT_REDUCED;
  assert(fabricated.display_state == PBNS_ATTESTATION_DISPLAY_FAILURE);
}

int main(void) {
  test_go_receipt_and_binding_mutants();
  test_fabricated_result_has_no_display_authority();
  puts("attestation receipt tests passed");
  return 0;
}
