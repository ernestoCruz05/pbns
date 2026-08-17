#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "PbnsRandomPolicy.h"
#include "pbns/identity.h"
#include "pbns/random.h"
#include "qcbor/qcbor.h"

typedef struct test_identity_backend {
  EVP_PKEY *key;
  size_t close_count;
  size_t public_count;
  size_t fingerprint_count;
  size_t sign_count;
  size_t random_count;
  pbns_status forced_status;
  bool report_oversized_public;
  bool report_oversized_signature;
} test_identity_backend;

static bool bn_to_fixed(const BIGNUM *value, uint8_t output[32]) {
  return value != NULL && BN_num_bytes(value) <= 32 &&
         BN_bn2binpad(value, output, 32) == 32;
}

static EVP_PKEY *make_p256_key(void) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  EVP_PKEY *key = NULL;
  assert(context != NULL);
  assert(EVP_PKEY_keygen_init(context) == 1);
  assert(EVP_PKEY_CTX_set_group_name(context, "prime256v1") == 1);
  assert(EVP_PKEY_generate(context, &key) == 1);
  EVP_PKEY_CTX_free(context);
  return key;
}

static bool public_coordinates(EVP_PKEY *key, uint8_t x[32], uint8_t y[32]) {
  BIGNUM *x_value = NULL;
  BIGNUM *y_value = NULL;
  const bool ok =
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x_value) == 1 &&
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y_value) == 1 &&
      bn_to_fixed(x_value, x) && bn_to_fixed(y_value, y);
  BN_clear_free(x_value);
  BN_clear_free(y_value);
  return ok;
}

static bool private_scalar(EVP_PKEY *key, uint8_t output[32]) {
  BIGNUM *value = NULL;
  const bool ok =
      EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &value) == 1 &&
      bn_to_fixed(value, output);
  BN_clear_free(value);
  return ok;
}

static bool contains_bytes(pbns_view haystack, pbns_view needle) {
  if (needle.len == 0U || needle.len > haystack.len) {
    return false;
  }
  for (size_t offset = 0U; offset <= haystack.len - needle.len; ++offset) {
    if (memcmp(haystack.ptr + offset, needle.ptr, needle.len) == 0) {
      return true;
    }
  }
  return false;
}

static pbns_status encode_public_key(EVP_PKEY *key, pbns_buffer output,
                                     size_t *written) {
  uint8_t x[32] = {0};
  uint8_t y[32] = {0};
  if (!public_coordinates(key, x, y)) {
    return PBNS_ERR_CRYPTO;
  }
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddInt64ToMapN(&encoder, 1, 2);
  QCBOREncode_AddInt64ToMapN(&encoder, -1, 1);
  QCBOREncode_AddBytesToMapN(&encoder, -2, (UsefulBufC){x, sizeof(x)});
  QCBOREncode_AddBytesToMapN(&encoder, -3, (UsefulBufC){y, sizeof(y)});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  OPENSSL_cleanse(x, sizeof(x));
  OPENSSL_cleanse(y, sizeof(y));
  if (error != QCBOR_SUCCESS) {
    return PBNS_ERR_LIMIT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

static pbns_status backend_public(void *context, pbns_buffer output,
                                  size_t *written) {
  test_identity_backend *backend = context;
  backend->public_count++;
  if (backend->forced_status != PBNS_OK) {
    return backend->forced_status;
  }
  const pbns_status status = encode_public_key(backend->key, output, written);
  if (status == PBNS_OK && backend->report_oversized_public) {
    *written = output.cap + 1U;
  }
  return status;
}

static pbns_status backend_fingerprint(void *context, pbns_buffer output) {
  test_identity_backend *backend = context;
  backend->fingerprint_count++;
  if (backend->forced_status != PBNS_OK) {
    return backend->forced_status;
  }
  uint8_t public_key[128] = {0};
  size_t public_length = 0U;
  if (encode_public_key(backend->key,
                        (pbns_buffer){public_key, 0U, sizeof(public_key)},
                        &public_length) != PBNS_OK) {
    return PBNS_ERR_CRYPTO;
  }
  unsigned int digest_length = 0U;
  const int ok = EVP_Digest(public_key, public_length, output.ptr,
                            &digest_length, EVP_sha256(), NULL);
  OPENSSL_cleanse(public_key, sizeof(public_key));
  return ok == 1 && digest_length == 32U ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static pbns_status backend_sign(void *context, pbns_view digest,
                                pbns_buffer signature, size_t *written) {
  test_identity_backend *backend = context;
  backend->sign_count++;
  if (backend->forced_status != PBNS_OK) {
    return backend->forced_status;
  }
  EVP_PKEY_CTX *signer = EVP_PKEY_CTX_new(backend->key, NULL);
  uint8_t der[80] = {0};
  size_t der_length = sizeof(der);
  if (signer == NULL || EVP_PKEY_sign_init(signer) != 1 ||
      EVP_PKEY_CTX_set_signature_md(signer, EVP_sha256()) != 1 ||
      EVP_PKEY_sign(signer, der, &der_length, digest.ptr, digest.len) != 1) {
    EVP_PKEY_CTX_free(signer);
    OPENSSL_cleanse(der, sizeof(der));
    return PBNS_ERR_CRYPTO;
  }
  const unsigned char *cursor = der;
  ECDSA_SIG *parsed = d2i_ECDSA_SIG(NULL, &cursor, (long)der_length);
  const BIGNUM *r = NULL;
  const BIGNUM *s = NULL;
  if (parsed == NULL || cursor != der + der_length) {
    ECDSA_SIG_free(parsed);
    EVP_PKEY_CTX_free(signer);
    OPENSSL_cleanse(der, sizeof(der));
    return PBNS_ERR_CRYPTO;
  }
  ECDSA_SIG_get0(parsed, &r, &s);
  const bool ok =
      bn_to_fixed(r, signature.ptr) && bn_to_fixed(s, signature.ptr + 32U);
  ECDSA_SIG_free(parsed);
  EVP_PKEY_CTX_free(signer);
  OPENSSL_cleanse(der, sizeof(der));
  if (!ok) {
    return PBNS_ERR_CRYPTO;
  }
  *written = backend->report_oversized_signature ? signature.cap + 1U : 64U;
  return PBNS_OK;
}

static pbns_status backend_random(void *context, pbns_buffer output) {
  test_identity_backend *backend = context;
  backend->random_count++;
  if (backend->forced_status != PBNS_OK) {
    return backend->forced_status;
  }
  for (size_t index = 0U; index < output.cap; ++index) {
    output.ptr[index] = (uint8_t)(index + 1U);
  }
  return PBNS_OK;
}

static void backend_close(void *context) {
  test_identity_backend *backend = context;
  backend->close_count++;
  EVP_PKEY_free(backend->key);
  backend->key = NULL;
}

static const pbns_identity_ops test_ops = {
    .public_cose_key = backend_public,
    .fingerprint = backend_fingerprint,
    .sign_digest = backend_sign,
    .random = backend_random,
    .close = backend_close,
};

static bool verify_raw_signature(EVP_PKEY *key, pbns_view digest,
                                 pbns_view signature) {
  if (signature.len != 64U) {
    return false;
  }
  BIGNUM *r = BN_bin2bn(signature.ptr, 32, NULL);
  BIGNUM *s = BN_bin2bn(signature.ptr + 32U, 32, NULL);
  ECDSA_SIG *ecdsa = ECDSA_SIG_new();
  if (r == NULL || s == NULL || ecdsa == NULL ||
      ECDSA_SIG_set0(ecdsa, r, s) != 1) {
    BN_clear_free(r);
    BN_clear_free(s);
    ECDSA_SIG_free(ecdsa);
    return false;
  }
  r = NULL;
  s = NULL;
  const int der_length = i2d_ECDSA_SIG(ecdsa, NULL);
  uint8_t der[80] = {0};
  unsigned char *cursor = der;
  const bool encoded = der_length > 0 && (size_t)der_length <= sizeof(der) &&
                       i2d_ECDSA_SIG(ecdsa, &cursor) == der_length;
  EVP_PKEY_CTX *verifier = encoded ? EVP_PKEY_CTX_new(key, NULL) : NULL;
  const bool valid =
      verifier != NULL && EVP_PKEY_verify_init(verifier) == 1 &&
      EVP_PKEY_CTX_set_signature_md(verifier, EVP_sha256()) == 1 &&
      EVP_PKEY_verify(verifier, der, (size_t)der_length, digest.ptr,
                      digest.len) == 1;
  EVP_PKEY_CTX_free(verifier);
  ECDSA_SIG_free(ecdsa);
  OPENSSL_cleanse(der, sizeof(der));
  return valid;
}

static test_identity_backend make_backend(void) {
  return (test_identity_backend){.key = make_p256_key()};
}

static void test_identity_round_trip(void) {
  test_identity_backend backend = make_backend();
  EVP_PKEY *verification_key = backend.key;
  pbns_identity identity = {0};
  assert(pbns_identity_open(&identity, &test_ops, &backend,
                            PBNS_IDENTITY_SOFTWARE) == PBNS_OK);
  assert(pbns_identity_assurance_level(&identity) == PBNS_IDENTITY_SOFTWARE);

  uint8_t public_key[128] = {0};
  uint8_t repeated_public[128] = {0};
  size_t public_length = 0U;
  size_t repeated_length = 0U;
  assert(pbns_identity_public_cose_key(
             &identity, (pbns_buffer){public_key, 0U, sizeof(public_key)},
             &public_length) == PBNS_OK);
  assert(pbns_identity_public_cose_key(
             &identity,
             (pbns_buffer){repeated_public, 0U, sizeof(repeated_public)},
             &repeated_length) == PBNS_OK);
  assert(public_length > 0U && public_length == repeated_length);
  assert(memcmp(public_key, repeated_public, public_length) == 0);

  uint8_t fingerprint[32] = {0};
  uint8_t expected_fingerprint[32] = {0};
  unsigned int expected_length = 0U;
  assert(pbns_identity_fingerprint(
             &identity, (pbns_buffer){fingerprint, 0U, sizeof(fingerprint)}) ==
         PBNS_OK);
  assert(EVP_Digest(public_key, public_length, expected_fingerprint,
                    &expected_length, EVP_sha256(), NULL) == 1);
  assert(expected_length == sizeof(expected_fingerprint));
  assert(memcmp(fingerprint, expected_fingerprint, sizeof(fingerprint)) == 0);

  uint8_t digest_bytes[32] = {0};
  uint8_t wrong_digest_bytes[32] = {0};
  digest_bytes[0] = UINT8_C(1);
  wrong_digest_bytes[0] = UINT8_C(2);
  uint8_t signature[64] = {0};
  size_t signature_length = 0U;
  assert(pbns_identity_sign(&identity,
                            (pbns_view){digest_bytes, sizeof(digest_bytes)},
                            (pbns_buffer){signature, 0U, sizeof(signature)},
                            &signature_length) == PBNS_OK);
  assert(signature_length == sizeof(signature));
  assert(verify_raw_signature(verification_key,
                              (pbns_view){digest_bytes, sizeof(digest_bytes)},
                              (pbns_view){signature, signature_length}));
  assert(!verify_raw_signature(
      verification_key,
      (pbns_view){wrong_digest_bytes, sizeof(wrong_digest_bytes)},
      (pbns_view){signature, signature_length}));

  uint8_t private_bytes[32] = {0};
  assert(private_scalar(verification_key, private_bytes));
  assert(!contains_bytes((pbns_view){public_key, public_length},
                         (pbns_view){private_bytes, sizeof(private_bytes)}));
  assert(!contains_bytes((pbns_view){fingerprint, sizeof(fingerprint)},
                         (pbns_view){private_bytes, sizeof(private_bytes)}));

  uint8_t random_bytes[16] = {0};
  assert(pbns_identity_random(&identity, (pbns_buffer){random_bytes, 0U,
                                                       sizeof(random_bytes)}) ==
         PBNS_OK);
  for (size_t index = 0U; index < sizeof(random_bytes); ++index) {
    assert(random_bytes[index] == (uint8_t)(index + 1U));
  }
  assert(backend.public_count == 2U);
  assert(backend.fingerprint_count == 1U);
  assert(backend.sign_count == 1U);
  assert(backend.random_count == 1U);
  OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
  pbns_identity_close(&identity);
  assert(backend.close_count == 1U);
  assert(pbns_identity_assurance_level(&identity) == PBNS_IDENTITY_INVALID);
  assert(pbns_identity_public_cose_key(
             &identity, (pbns_buffer){public_key, 0U, sizeof(public_key)},
             &public_length) == PBNS_ERR_STATE);
  pbns_identity_close(&identity);
  assert(backend.close_count == 1U);
}

static void test_identity_rejects_invalid_contracts(void) {
  test_identity_backend backend = make_backend();
  pbns_identity identity = {0};
  pbns_identity_ops incomplete = test_ops;
  incomplete.sign_digest = NULL;
  assert(pbns_identity_open(NULL, &test_ops, &backend,
                            PBNS_IDENTITY_SOFTWARE) == PBNS_ERR_ARGUMENT);
  assert(pbns_identity_open(&identity, &incomplete, &backend,
                            PBNS_IDENTITY_SOFTWARE) == PBNS_ERR_ARGUMENT);
  assert(pbns_identity_open(&identity, &test_ops, NULL,
                            PBNS_IDENTITY_SOFTWARE) == PBNS_ERR_ARGUMENT);
  assert(pbns_identity_open(&identity, &test_ops, &backend,
                            PBNS_IDENTITY_INVALID) == PBNS_ERR_ARGUMENT);
  assert(pbns_identity_open(&identity, &test_ops, &backend,
                            PBNS_IDENTITY_SOFTWARE) == PBNS_OK);
  assert(pbns_identity_open(&identity, &test_ops, &backend,
                            PBNS_IDENTITY_SOFTWARE) == PBNS_ERR_STATE);

  uint8_t bytes[128] = {0};
  size_t written = 99U;
  assert(pbns_identity_public_cose_key(&identity,
                                       (pbns_buffer){bytes, 1U, sizeof(bytes)},
                                       &written) == PBNS_ERR_ARGUMENT);
  assert(written == 0U);
  assert(pbns_identity_fingerprint(&identity, (pbns_buffer){bytes, 0U, 31U}) ==
         PBNS_ERR_LIMIT);
  assert(pbns_identity_sign(&identity, (pbns_view){bytes, 31U},
                            (pbns_buffer){bytes, 0U, 64U},
                            &written) == PBNS_ERR_ARGUMENT);
  assert(pbns_identity_sign(&identity, (pbns_view){bytes, 32U},
                            (pbns_buffer){bytes, 0U, 63U},
                            &written) == PBNS_ERR_LIMIT);

  backend.report_oversized_public = true;
  assert(pbns_identity_public_cose_key(&identity,
                                       (pbns_buffer){bytes, 0U, sizeof(bytes)},
                                       &written) == PBNS_ERR_IO);
  backend.report_oversized_public = false;
  backend.report_oversized_signature = true;
  assert(pbns_identity_sign(&identity, (pbns_view){bytes, 32U},
                            (pbns_buffer){bytes, 0U, 64U},
                            &written) == PBNS_ERR_IO);
  backend.report_oversized_signature = false;
  backend.forced_status = PBNS_ERR_CRYPTO;
  assert(pbns_identity_fingerprint(&identity, (pbns_buffer){bytes, 0U, 32U}) ==
         PBNS_ERR_CRYPTO);
  pbns_identity_close(&identity);
}

typedef struct random_fixture {
  size_t calls;
  pbns_status status;
} random_fixture;

static pbns_status random_fill(void *context, pbns_buffer output) {
  random_fixture *fixture = context;
  fixture->calls++;
  if (fixture->status != PBNS_OK) {
    return fixture->status;
  }
  memset(output.ptr, 0xa5, output.cap);
  return PBNS_OK;
}

static void test_generic_random_contract(void) {
  random_fixture fixture = {0};
  const pbns_random_ops ops = {.fill = random_fill};
  const pbns_random random = {.ops = &ops, .context = &fixture};
  uint8_t bytes[8] = {0};
  assert(pbns_random_fill(&random, (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_OK);
  assert(fixture.calls == 1U);
  for (size_t index = 0U; index < sizeof(bytes); ++index) {
    assert(bytes[index] == UINT8_C(0xa5));
  }
  assert(pbns_random_fill(NULL, (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_random_fill(&random, (pbns_buffer){bytes, 1U, sizeof(bytes)}) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_random_fill(&random, (pbns_buffer){NULL, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ARGUMENT);
  fixture.status = PBNS_ERR_ENTROPY;
  assert(pbns_random_fill(&random, (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ENTROPY);
  assert(fixture.calls == 2U);
}

typedef struct priority_source_fixture {
  size_t calls;
  pbns_status status;
  uint8_t byte;
} priority_source_fixture;

static pbns_status priority_source_fill(void *context, pbns_buffer output) {
  priority_source_fixture *fixture = context;
  fixture->calls++;
  memset(output.ptr, fixture->byte, output.cap);
  return fixture->status;
}

static void assert_all_zero(const uint8_t *bytes, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    assert(bytes[index] == 0U);
  }
}

static void test_random_priority_policy(void) {
  uint8_t bytes[16] = {0};
  priority_source_fixture primary = {.status = PBNS_OK, .byte = 0x11};
  priority_source_fixture fallback = {.status = PBNS_OK, .byte = 0x22};
  pbns_random_source primary_source = {.fill = priority_source_fill,
                                       .context = &primary};
  pbns_random_source fallback_source = {.fill = priority_source_fill,
                                        .context = &fallback};

  assert(pbns_random_priority_fill(&primary_source, &fallback_source,
                                   (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_OK);
  assert(primary.calls == 1U && fallback.calls == 0U);
  assert(bytes[0] == 0x11);

  primary.status = PBNS_ERR_UNSUPPORTED;
  assert(pbns_random_priority_fill(&primary_source, &fallback_source,
                                   (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_OK);
  assert(primary.calls == 2U && fallback.calls == 1U);
  assert(bytes[0] == 0x22);

  assert(pbns_random_priority_fill(NULL, &fallback_source,
                                   (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_OK);
  assert(primary.calls == 2U && fallback.calls == 2U);

  memset(bytes, 0xa5, sizeof(bytes));
  assert(pbns_random_priority_fill(NULL, NULL,
                                   (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ENTROPY);
  assert_all_zero(bytes, sizeof(bytes));

  primary.status = PBNS_ERR_ENTROPY;
  memset(bytes, 0xa5, sizeof(bytes));
  assert(pbns_random_priority_fill(&primary_source, &fallback_source,
                                   (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ENTROPY);
  assert(primary.calls == 3U && fallback.calls == 2U);
  assert_all_zero(bytes, sizeof(bytes));

  primary.status = PBNS_ERR_UNSUPPORTED;
  fallback.status = PBNS_ERR_IO;
  memset(bytes, 0xa5, sizeof(bytes));
  assert(pbns_random_priority_fill(&primary_source, &fallback_source,
                                   (pbns_buffer){bytes, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ENTROPY);
  assert(primary.calls == 4U && fallback.calls == 3U);
  assert_all_zero(bytes, sizeof(bytes));

  assert(pbns_random_priority_fill(&primary_source, &fallback_source,
                                   (pbns_buffer){NULL, 0U, sizeof(bytes)}) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_random_priority_fill(&primary_source, &fallback_source,
                                   (pbns_buffer){bytes, 1U, sizeof(bytes)}) ==
         PBNS_ERR_ARGUMENT);
  assert(primary.calls == 4U && fallback.calls == 3U);
}

int main(void) {
  test_identity_round_trip();
  test_identity_rejects_invalid_contracts();
  test_generic_random_contract();
  test_random_priority_policy();
  return 0;
}
