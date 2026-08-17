#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/x509_crt.h>

#include "pbns/tls_policy.h"

#define CERTIFICATE_CAPACITY 4096U

static const uint8_t expected_pin[PBNS_TLS_SPKI_SHA256_SIZE] = {
    0xa0, 0xd2, 0x19, 0x23, 0xdd, 0xfc, 0xcb, 0xa1, 0x2d, 0x0a, 0x7b,
    0xbd, 0x74, 0x08, 0x65, 0x0c, 0xb8, 0xc5, 0x4f, 0x1b, 0xe5, 0x37,
    0xfe, 0x3a, 0x7e, 0x69, 0xad, 0xb1, 0x37, 0x6d, 0xa1, 0x06,
};
static const uint8_t dns_name[] = "pbns-gateway.test";
static const uint8_t ipv4_name[] = "192.168.1.180";
static const uint8_t ipv6_name[] = "2001:db8::180";

static size_t read_fixture(const char *path,
                           uint8_t output[CERTIFICATE_CAPACITY]) {
  FILE *const stream = fopen(path, "rb");
  assert(stream != NULL);
  const size_t length = fread(output, 1U, CERTIFICATE_CAPACITY, stream);
  assert(ferror(stream) == 0);
  assert(feof(stream) != 0);
  assert(fclose(stream) == 0);
  return length;
}

static pbns_view view_from_cstr(const char *text) {
  return (pbns_view){(const uint8_t *)text, strlen(text)};
}

static void assert_certificate_status(const char *path, pbns_view endpoint,
                                      pbns_status expected) {
  uint8_t encoded[CERTIFICATE_CAPACITY] = {0};
  const size_t length = read_fixture(path, encoded);
  const pbns_status status = pbns_tls_validate_certificate_der(
      (pbns_view){encoded, length}, endpoint,
      (pbns_view){expected_pin, sizeof(expected_pin)}, 0U);
  if (status != expected) {
    (void)fprintf(stderr, "%s: got %d expected %d\n", path, (int)status,
                  (int)expected);
  }
  assert(status == expected);
}

static void test_negotiated_profile(void) {
  assert(pbns_tls_validate_negotiated_profile(
             PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             PBNS_TLS_ALPN_PROTOCOL) == PBNS_OK);
  assert(pbns_tls_validate_negotiated_profile(
             UINT16_C(0x0302), PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             PBNS_TLS_ALPN_PROTOCOL) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_negotiated_profile(
             UINT16_C(0x0304), PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             PBNS_TLS_ALPN_PROTOCOL) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_negotiated_profile(
             PBNS_TLS_VERSION_1_2, UINT16_C(0xc02f), PBNS_TLS_ALPN_PROTOCOL) ==
         PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_negotiated_profile(
             PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             NULL) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_negotiated_profile(
             PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             "") == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_negotiated_profile(
             PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             "pbns/") == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_negotiated_profile(
             PBNS_TLS_VERSION_1_2, PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256,
             "pbns/1x") == PBNS_ERR_AUTHENTICATION);
}

static void test_endpoint_arguments(void) {
  pbns_tls_certificate_policy policy = {0};
  const pbns_view pin = {expected_pin, sizeof(expected_pin)};
  assert(pbns_tls_certificate_policy_init(
             &policy, (pbns_view){dns_name, sizeof(dns_name) - 1U}, pin) ==
         PBNS_OK);
  pbns_tls_certificate_policy_wipe(&policy);
  assert(pbns_tls_certificate_policy_init(
             &policy, (pbns_view){ipv4_name, sizeof(ipv4_name) - 1U}, pin) ==
         PBNS_OK);
  pbns_tls_certificate_policy_wipe(&policy);
  assert(pbns_tls_certificate_policy_init(
             &policy, (pbns_view){ipv6_name, sizeof(ipv6_name) - 1U}, pin) ==
         PBNS_OK);
  const uint8_t embedded_nul[] = {'p', 'b', 0U, 'n', 's'};
  const char *const invalid[] = {
      "",
      "*.pbns-gateway.test",
      "-bad.test",
      "bad-.test",
      "bad..test",
      "192.168.1.999",
      "192.168.01.1",
      "2001:db8:::180",
      "2001:db8::1::2",
      "2001:db8::gg",
      "a:bad.test",
  };
  for (size_t index = 0U; index < sizeof(invalid) / sizeof(invalid[0]);
       ++index) {
    assert(pbns_tls_certificate_policy_init(&policy,
                                            view_from_cstr(invalid[index]),
                                            pin) == PBNS_ERR_ARGUMENT);
  }
  assert(pbns_tls_certificate_policy_init(
             &policy, (pbns_view){embedded_nul, sizeof(embedded_nul)}, pin) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_tls_certificate_policy_init(NULL, view_from_cstr("valid.test"),
                                          pin) == PBNS_ERR_ARGUMENT);
  assert(pbns_tls_certificate_policy_init(
             &policy, view_from_cstr("valid.test"),
             (pbns_view){expected_pin, sizeof(expected_pin) - 1U}) ==
         PBNS_ERR_ARGUMENT);
}

static void test_callback_flags(const char *path) {
  uint8_t encoded[CERTIFICATE_CAPACITY] = {0};
  const size_t length = read_fixture(path, encoded);
  mbedtls_x509_crt certificate;
  mbedtls_x509_crt_init(&certificate);
  assert(mbedtls_x509_crt_parse_der(&certificate, encoded, length) == 0);
  const uint32_t allowed[] = {
      MBEDTLS_X509_BADCERT_NOT_TRUSTED,
      MBEDTLS_X509_BADCERT_EXPIRED,
      MBEDTLS_X509_BADCERT_FUTURE,
      MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_EXPIRED |
          MBEDTLS_X509_BADCERT_FUTURE,
  };
  for (size_t index = 0U; index < sizeof(allowed) / sizeof(allowed[0]);
       ++index) {
    pbns_tls_certificate_policy policy = {0};
    assert(pbns_tls_certificate_policy_init(
               &policy, (pbns_view){dns_name, sizeof(dns_name) - 1U},
               (pbns_view){expected_pin, sizeof(expected_pin)}) == PBNS_OK);
    uint32_t flags = allowed[index];
    assert(pbns_tls_certificate_verify_callback(&policy, &certificate, 0,
                                                &flags) == 0);
    assert(flags == 0U);
    assert(policy.matched);
    assert(policy.mbedtls_verify_flags == allowed[index]);
    pbns_tls_certificate_policy_wipe(&policy);
  }
  const uint32_t disallowed[] = {
      MBEDTLS_X509_BADCERT_REVOKED,       MBEDTLS_X509_BADCERT_CN_MISMATCH,
      MBEDTLS_X509_BADCERT_MISSING,       MBEDTLS_X509_BADCERT_SKIP_VERIFY,
      MBEDTLS_X509_BADCERT_OTHER,         MBEDTLS_X509_BADCERT_KEY_USAGE,
      MBEDTLS_X509_BADCERT_EXT_KEY_USAGE, MBEDTLS_X509_BADCERT_NS_CERT_TYPE,
      MBEDTLS_X509_BADCERT_BAD_MD,        MBEDTLS_X509_BADCERT_BAD_PK,
      MBEDTLS_X509_BADCERT_BAD_KEY,
  };
  for (size_t index = 0U; index < sizeof(disallowed) / sizeof(disallowed[0]);
       ++index) {
    pbns_tls_certificate_policy policy = {0};
    assert(pbns_tls_certificate_policy_init(
               &policy, (pbns_view){dns_name, sizeof(dns_name) - 1U},
               (pbns_view){expected_pin, sizeof(expected_pin)}) == PBNS_OK);
    uint32_t flags = disallowed[index];
    assert(pbns_tls_certificate_verify_callback(&policy, &certificate, 0,
                                                &flags) != 0);
    assert(flags == disallowed[index]);
    assert(!policy.matched);
    pbns_tls_certificate_policy_wipe(&policy);
  }
  pbns_tls_certificate_policy policy = {0};
  assert(pbns_tls_certificate_policy_init(
             &policy, (pbns_view){dns_name, sizeof(dns_name) - 1U},
             (pbns_view){expected_pin, sizeof(expected_pin)}) == PBNS_OK);
  uint32_t flags = 0U;
  assert(pbns_tls_certificate_verify_callback(&policy, &certificate, 1,
                                              &flags) != 0);
  assert(!policy.matched);
  pbns_tls_certificate_policy_wipe(&policy);
  mbedtls_x509_crt_free(&certificate);
}

static void test_certificates(char **paths) {
  const pbns_view dns = {dns_name, sizeof(dns_name) - 1U};
  const pbns_view ipv4 = {ipv4_name, sizeof(ipv4_name) - 1U};
  const pbns_view ipv6 = {ipv6_name, sizeof(ipv6_name) - 1U};
  assert_certificate_status(paths[1], dns, PBNS_OK);
  assert_certificate_status(paths[2], ipv4, PBNS_OK);
  assert_certificate_status(paths[3], ipv6, PBNS_OK);
  assert_certificate_status(paths[1], view_from_cstr("pbns-gateway.testx"),
                            PBNS_ERR_AUTHENTICATION);
  assert_certificate_status(paths[2], view_from_cstr("192.168.1.181"),
                            PBNS_ERR_AUTHENTICATION);
  assert_certificate_status(paths[3], view_from_cstr("2001:db8::181"),
                            PBNS_ERR_AUTHENTICATION);
  for (size_t index = 4U; index <= 16U; ++index) {
    assert_certificate_status(paths[index], dns, PBNS_ERR_AUTHENTICATION);
  }
  assert_certificate_status(paths[17], dns, PBNS_ERR_FORMAT);

  uint8_t wrong_pin[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  uint8_t encoded[CERTIFICATE_CAPACITY] = {0};
  const size_t length = read_fixture(paths[1], encoded);
  assert(pbns_tls_validate_certificate_der(
             (pbns_view){encoded, length}, dns,
             (pbns_view){wrong_pin, sizeof(wrong_pin)},
             0U) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_certificate_der(
             (pbns_view){encoded, length}, dns,
             (pbns_view){expected_pin, sizeof(expected_pin)},
             PBNS_TLS_VERIFY_NOT_TRUSTED | PBNS_TLS_VERIFY_EXPIRED |
                 PBNS_TLS_VERIFY_FUTURE) == PBNS_OK);
  assert(pbns_tls_validate_certificate_der(
             (pbns_view){encoded, length}, dns,
             (pbns_view){expected_pin, sizeof(expected_pin)},
             MBEDTLS_X509_BADCERT_OTHER) == PBNS_ERR_AUTHENTICATION);
  assert(pbns_tls_validate_certificate_der(
             (pbns_view){NULL, 0U}, dns,
             (pbns_view){expected_pin, sizeof(expected_pin)},
             0U) == PBNS_ERR_ARGUMENT);
  uint8_t oversized[PBNS_TLS_CERTIFICATE_DER_MAX + 1U] = {0};
  assert(pbns_tls_validate_certificate_der(
             (pbns_view){oversized, sizeof(oversized)}, dns,
             (pbns_view){expected_pin, sizeof(expected_pin)},
             0U) == PBNS_ERR_ARGUMENT);
}

int main(int argc, char **argv) {
  assert(argc == 18);
  test_negotiated_profile();
  test_endpoint_arguments();
  test_callback_flags(argv[1]);
  test_certificates(argv);
  return 0;
}
