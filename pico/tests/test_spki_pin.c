#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/x509_crt.h"
#include "pbns_proxy/tls_client.h"

#define CERTIFICATE_CAPACITY 4096U

static const uint8_t expected_pin[PBNS_TLS_SPKI_SHA256_SIZE] = {
    0xa0, 0xd2, 0x19, 0x23, 0xdd, 0xfc, 0xcb, 0xa1, 0x2d, 0x0a, 0x7b,
    0xbd, 0x74, 0x08, 0x65, 0x0c, 0xb8, 0xc5, 0x4f, 0x1b, 0xe5, 0x37,
    0xfe, 0x3a, 0x7e, 0x69, 0xad, 0xb1, 0x37, 0x6d, 0xa1, 0x06,
};

static size_t read_fixture(const char *path,
                           uint8_t output[CERTIFICATE_CAPACITY]) {
  FILE *const stream = fopen(path, "rb");
  assert(stream != NULL);
  const size_t length = fread(output, 1U, CERTIFICATE_CAPACITY, stream);
  assert(ferror(stream) == 0);
  assert(length < CERTIFICATE_CAPACITY);
  assert(feof(stream) != 0);
  assert(fclose(stream) == 0);
  return length;
}

static void
test_extracts_subject_public_key_info(const char *certificate_path) {
  uint8_t certificate[CERTIFICATE_CAPACITY] = {0};
  uint8_t digest[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  const size_t certificate_len = read_fixture(certificate_path, certificate);
  size_t written = SIZE_MAX;
  assert(pbns_tls_certificate_spki_sha256(
             (pbns_view){certificate, certificate_len},
             (pbns_buffer){digest, 0U, sizeof(digest)}, &written) == PBNS_OK);
  assert(written == sizeof(digest));
  assert(memcmp(digest, expected_pin, sizeof(digest)) == 0);
}

static void test_accepts_reissued_certificate_and_allowed_flags(
    const char *certificate_path) {
  uint8_t certificate[CERTIFICATE_CAPACITY] = {0};
  const size_t certificate_len = read_fixture(certificate_path, certificate);
  const uint32_t allowed_flags = PBNS_TLS_VERIFY_NOT_TRUSTED |
                                 PBNS_TLS_VERIFY_EXPIRED |
                                 PBNS_TLS_VERIFY_FUTURE;
  assert(pbns_tls_verify_certificate(
             (pbns_view){certificate, certificate_len}, allowed_flags,
             (pbns_view){expected_pin, sizeof(expected_pin)}) == PBNS_OK);
}

static void test_rejects_wrong_key_and_key_profile(const char *wrong_key_path,
                                                   const char *rsa_path) {
  uint8_t certificate[CERTIFICATE_CAPACITY] = {0};
  size_t certificate_len = read_fixture(wrong_key_path, certificate);
  assert(pbns_tls_verify_certificate(
             (pbns_view){certificate, certificate_len}, 0U,
             (pbns_view){expected_pin, sizeof(expected_pin)}) ==
         PBNS_ERR_AUTHENTICATION);

  certificate_len = read_fixture(rsa_path, certificate);
  assert(pbns_tls_verify_certificate(
             (pbns_view){certificate, certificate_len}, 0U,
             (pbns_view){expected_pin, sizeof(expected_pin)}) ==
         PBNS_ERR_UNSUPPORTED);
}

static void test_rejects_malformed_certificate_and_unapproved_flags(
    const char *certificate_path, const char *malformed_path) {
  uint8_t certificate[CERTIFICATE_CAPACITY] = {0};
  size_t certificate_len = read_fixture(malformed_path, certificate);
  assert(pbns_tls_verify_certificate(
             (pbns_view){certificate, certificate_len}, 0U,
             (pbns_view){expected_pin, sizeof(expected_pin)}) ==
         PBNS_ERR_FORMAT);

  certificate_len = read_fixture(certificate_path, certificate);
  assert(pbns_tls_verify_certificate(
             (pbns_view){certificate, certificate_len},
             PBNS_TLS_VERIFY_CN_MISMATCH,
             (pbns_view){expected_pin, sizeof(expected_pin)}) ==
         PBNS_ERR_AUTHENTICATION);
}

static void test_runtime_callback_requires_leaf_pin_and_rejects_other_flags(
    const char *certificate_path, const char *intermediate_path) {
  uint8_t encoded[CERTIFICATE_CAPACITY] = {0};
  size_t encoded_len = read_fixture(intermediate_path, encoded);
  mbedtls_x509_crt intermediate;
  mbedtls_x509_crt_init(&intermediate);
  assert(mbedtls_x509_crt_parse_der(&intermediate, encoded, encoded_len) == 0);

  pbns_tls_pin_verifier verifier = {0};
  assert(pbns_tls_pin_verifier_init(
             &verifier, (pbns_view){expected_pin, sizeof(expected_pin)}) ==
         PBNS_OK);
  uint32_t flags = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
  assert(pbns_tls_certificate_verify_callback(&verifier, &intermediate, 1,
                                              &flags) == 0);
  assert(flags == 0U);
  assert(!verifier.matched);
  mbedtls_x509_crt_free(&intermediate);

  encoded_len = read_fixture(certificate_path, encoded);
  mbedtls_x509_crt leaf;
  mbedtls_x509_crt_init(&leaf);
  assert(mbedtls_x509_crt_parse_der(&leaf, encoded, encoded_len) == 0);
  flags = MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_EXPIRED |
          MBEDTLS_X509_BADCERT_FUTURE;
  assert(pbns_tls_certificate_verify_callback(&verifier, &leaf, 0, &flags) ==
         0);
  assert(flags == 0U);
  assert(verifier.matched);

  assert(pbns_tls_pin_verifier_init(
             &verifier, (pbns_view){expected_pin, sizeof(expected_pin)}) ==
         PBNS_OK);
  flags = MBEDTLS_X509_BADCERT_CN_MISMATCH;
  assert(pbns_tls_certificate_verify_callback(&verifier, &leaf, 0, &flags) !=
         0);
  assert(verifier.status == PBNS_ERR_AUTHENTICATION);
  assert(!verifier.matched);
  mbedtls_x509_crt_free(&leaf);
}

static void test_rejects_weak_or_unapproved_tls_profile(void) {
  assert(pbns_tls_validate_profile(
             UINT16_C(0x0302), PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             PBNS_TLS_ALPN_PROTOCOL) == PBNS_ERR_UNSUPPORTED);
  assert(pbns_tls_validate_profile(PBNS_TLS_VERSION_1_2,
                                   PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
                                   PBNS_TLS_ALPN_PROTOCOL) == PBNS_OK);
  assert(pbns_tls_validate_profile(PBNS_TLS_VERSION_1_2, UINT16_C(0xc02f),
                                   PBNS_TLS_ALPN_PROTOCOL) ==
         PBNS_ERR_UNSUPPORTED);
  static const char *const invalid_alpn[] = {
      NULL, "", "pbns/1x", "PBNS/1", "h2",
  };
  for (size_t index = 0U;
       index < sizeof(invalid_alpn) / sizeof(invalid_alpn[0]); ++index) {
    assert(pbns_tls_validate_profile(
               PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
               invalid_alpn[index]) == PBNS_ERR_UNSUPPORTED);
  }
}

int main(int argc, char **argv) {
  assert(argc == 6);
  test_extracts_subject_public_key_info(argv[1]);
  test_accepts_reissued_certificate_and_allowed_flags(argv[2]);
  test_rejects_wrong_key_and_key_profile(argv[3], argv[4]);
  test_rejects_malformed_certificate_and_unapproved_flags(argv[1], argv[5]);
  test_runtime_callback_requires_leaf_pin_and_rejects_other_flags(argv[1],
                                                                  argv[3]);
  test_rejects_weak_or_unapproved_tls_profile();
  return 0;
}
