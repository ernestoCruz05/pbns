#include "pbns/tls_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/asn1.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>

#define PBNS_TLS_SPKI_DER_MAX 256U
#define PBNS_TLS_ALLOWED_MBEDTLS_FLAGS                                         \
  (MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_EXPIRED |           \
   MBEDTLS_X509_BADCERT_FUTURE)

typedef enum pbns_tls_endpoint_kind {
  PBNS_TLS_ENDPOINT_DNS,
  PBNS_TLS_ENDPOINT_IPV4,
  PBNS_TLS_ENDPOINT_IPV6,
} pbns_tls_endpoint_kind;

static void wipe_bytes(void *bytes, size_t length) {
  volatile uint8_t *cursor = bytes;
  while (length > 0U) {
    *cursor++ = 0U;
    --length;
  }
}

static bool view_is_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool ascii_equal_folded(const uint8_t *left, const uint8_t *right,
                               size_t length) {
  uint8_t different = 0U;
  for (size_t index = 0U; index < length; ++index) {
    uint8_t a = left[index];
    uint8_t b = right[index];
    if (a >= (uint8_t)'A' && a <= (uint8_t)'Z') {
      a = (uint8_t)(a + ((uint8_t)'a' - (uint8_t)'A'));
    }
    if (b >= (uint8_t)'A' && b <= (uint8_t)'Z') {
      b = (uint8_t)(b + ((uint8_t)'a' - (uint8_t)'A'));
    }
    different |= (uint8_t)(a ^ b);
  }
  return different == 0U;
}

static bool parse_ipv4(pbns_view text, uint8_t output[4]) {
  size_t cursor = 0U;
  for (size_t part = 0U; part < 4U; ++part) {
    if (cursor >= text.len || text.ptr[cursor] < (uint8_t)'0' ||
        text.ptr[cursor] > (uint8_t)'9') {
      return false;
    }
    const size_t first = cursor;
    unsigned int value = 0U;
    while (cursor < text.len && text.ptr[cursor] >= (uint8_t)'0' &&
           text.ptr[cursor] <= (uint8_t)'9') {
      if (cursor - first == 3U) {
        return false;
      }
      value = value * 10U + (unsigned int)(text.ptr[cursor] - (uint8_t)'0');
      if (value > 255U) {
        return false;
      }
      ++cursor;
    }
    if (cursor - first > 1U && text.ptr[first] == (uint8_t)'0') {
      return false;
    }
    output[part] = (uint8_t)value;
    if (part != 3U) {
      if (cursor >= text.len || text.ptr[cursor] != (uint8_t)'.') {
        return false;
      }
      ++cursor;
    }
  }
  return cursor == text.len;
}

static int hexadecimal_value(uint8_t value) {
  if (value >= (uint8_t)'0' && value <= (uint8_t)'9') {
    return (int)(value - (uint8_t)'0');
  }
  if (value >= (uint8_t)'a' && value <= (uint8_t)'f') {
    return (int)(value - (uint8_t)'a') + 10;
  }
  if (value >= (uint8_t)'A' && value <= (uint8_t)'F') {
    return (int)(value - (uint8_t)'A') + 10;
  }
  return -1;
}

static bool parse_ipv6(pbns_view text, uint8_t output[16]) {
  uint16_t groups[8] = {0};
  size_t cursor = 0U;
  size_t group_count = 0U;
  size_t compressed_at = SIZE_MAX;
  if (text.len < 2U) {
    return false;
  }
  if (text.ptr[cursor] == (uint8_t)':') {
    if (text.ptr[cursor + 1U] != (uint8_t)':') {
      return false;
    }
    compressed_at = 0U;
    cursor += 2U;
  }
  while (cursor < text.len) {
    if (group_count == 8U) {
      return false;
    }
    uint16_t group = 0U;
    size_t digits = 0U;
    while (cursor < text.len && text.ptr[cursor] != (uint8_t)':') {
      const int digit = hexadecimal_value(text.ptr[cursor]);
      if (digit < 0 || digits == 4U) {
        return false;
      }
      group = (uint16_t)((group << 4U) | (uint16_t)digit);
      ++digits;
      ++cursor;
    }
    if (digits == 0U) {
      return false;
    }
    groups[group_count++] = group;
    if (cursor == text.len) {
      break;
    }
    ++cursor;
    if (cursor < text.len && text.ptr[cursor] == (uint8_t)':') {
      if (compressed_at != SIZE_MAX) {
        return false;
      }
      compressed_at = group_count;
      ++cursor;
      if (cursor == text.len) {
        break;
      }
    }
  }
  if (compressed_at == SIZE_MAX) {
    if (group_count != 8U) {
      return false;
    }
  } else {
    if (group_count >= 8U) {
      return false;
    }
    const size_t missing = 8U - group_count;
    for (size_t index = group_count; index > compressed_at; --index) {
      groups[index + missing - 1U] = groups[index - 1U];
    }
    for (size_t index = 0U; index < missing; ++index) {
      groups[compressed_at + index] = 0U;
    }
  }
  for (size_t index = 0U; index < 8U; ++index) {
    output[index * 2U] = (uint8_t)(groups[index] >> 8U);
    output[index * 2U + 1U] = (uint8_t)groups[index];
  }
  wipe_bytes(groups, sizeof(groups));
  return true;
}

static bool is_decimal_or_dot(pbns_view text) {
  bool has_dot = false;
  for (size_t index = 0U; index < text.len; ++index) {
    if (text.ptr[index] == (uint8_t)'.') {
      has_dot = true;
    } else if (text.ptr[index] < (uint8_t)'0' ||
               text.ptr[index] > (uint8_t)'9') {
      return false;
    }
  }
  return has_dot;
}

static bool validate_dns_name(pbns_view text) {
  if (text.len == 0U || text.len > PBNS_TLS_SERVER_NAME_MAX) {
    return false;
  }
  size_t label_length = 0U;
  for (size_t index = 0U; index < text.len; ++index) {
    const uint8_t value = text.ptr[index];
    if (value == 0U || value == (uint8_t)'*') {
      return false;
    }
    if (value == (uint8_t)'.') {
      if (label_length == 0U || label_length > 63U ||
          text.ptr[index - 1U] == (uint8_t)'-') {
        return false;
      }
      label_length = 0U;
      continue;
    }
    if (!((value >= (uint8_t)'a' && value <= (uint8_t)'z') ||
          (value >= (uint8_t)'A' && value <= (uint8_t)'Z') ||
          (value >= (uint8_t)'0' && value <= (uint8_t)'9') ||
          value == (uint8_t)'-') ||
        (label_length == 0U && value == (uint8_t)'-')) {
      return false;
    }
    ++label_length;
  }
  return label_length > 0U && label_length <= 63U &&
         text.ptr[text.len - 1U] != (uint8_t)'-';
}

static bool classify_endpoint(pbns_view text, pbns_tls_endpoint_kind *kind,
                              uint8_t address[16]) {
  if (!view_is_valid(text) || kind == NULL || text.len == 0U ||
      text.len > PBNS_TLS_SERVER_NAME_MAX ||
      memchr(text.ptr, 0, text.len) != NULL) {
    return false;
  }
  if (memchr(text.ptr, (int)':', text.len) != NULL) {
    *kind = PBNS_TLS_ENDPOINT_IPV6;
    return parse_ipv6(text, address);
  }
  if (is_decimal_or_dot(text)) {
    *kind = PBNS_TLS_ENDPOINT_IPV4;
    return parse_ipv4(text, address);
  }
  *kind = PBNS_TLS_ENDPOINT_DNS;
  return validate_dns_name(text);
}

static bool certificate_san_matches(const mbedtls_x509_crt *certificate,
                                    pbns_view expected_name) {
  uint8_t expected_address[16] = {0};
  pbns_tls_endpoint_kind kind = PBNS_TLS_ENDPOINT_DNS;
  if (!classify_endpoint(expected_name, &kind, expected_address)) {
    return false;
  }
  const size_t address_length = kind == PBNS_TLS_ENDPOINT_IPV4 ? 4U : 16U;
  const mbedtls_x509_sequence *entry = &certificate->subject_alt_names;
  for (; entry != NULL && entry->buf.p != NULL; entry = entry->next) {
    const mbedtls_x509_buf *raw = &entry->buf;
    const bool matches =
        (kind == PBNS_TLS_ENDPOINT_DNS &&
         raw->tag ==
             (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_DNS_NAME) &&
         raw->len == expected_name.len &&
         ascii_equal_folded(raw->p, expected_name.ptr, expected_name.len)) ||
        (kind != PBNS_TLS_ENDPOINT_DNS &&
         raw->tag ==
             (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_X509_SAN_IP_ADDRESS) &&
         raw->len == address_length &&
         mbedtls_ct_memcmp(raw->p, expected_address, address_length) == 0);
    if (matches) {
      mbedtls_platform_zeroize(expected_address, sizeof(expected_address));
      return true;
    }
  }
  mbedtls_platform_zeroize(expected_address, sizeof(expected_address));
  return false;
}

static bool
basic_constraints_are_critical(const mbedtls_x509_crt *certificate) {
  if (certificate->v3_ext.p == NULL || certificate->v3_ext.len == 0U) {
    return false;
  }
  unsigned char *cursor = certificate->v3_ext.p;
  const unsigned char *const end = cursor + certificate->v3_ext.len;
  size_t sequence_length = 0U;
  if (mbedtls_asn1_get_tag(&cursor, end, &sequence_length,
                           MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) !=
          0 ||
      cursor + sequence_length != end) {
    return false;
  }
  while (cursor < end) {
    size_t extension_length = 0U;
    if (mbedtls_asn1_get_tag(&cursor, end, &extension_length,
                             MBEDTLS_ASN1_CONSTRUCTED |
                                 MBEDTLS_ASN1_SEQUENCE) != 0 ||
        extension_length > (size_t)(end - cursor)) {
      return false;
    }
    unsigned char *const extension_end = cursor + extension_length;
    size_t oid_length = 0U;
    if (mbedtls_asn1_get_tag(&cursor, extension_end, &oid_length,
                             MBEDTLS_ASN1_OID) != 0 ||
        oid_length > (size_t)(extension_end - cursor)) {
      return false;
    }
    const bool is_basic_constraints =
        oid_length == MBEDTLS_OID_SIZE(MBEDTLS_OID_BASIC_CONSTRAINTS) &&
        mbedtls_ct_memcmp(cursor, MBEDTLS_OID_BASIC_CONSTRAINTS, oid_length) ==
            0;
    cursor += oid_length;
    int critical = 0;
    const int bool_status =
        mbedtls_asn1_get_bool(&cursor, extension_end, &critical);
    if (bool_status != 0 && bool_status != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
      return false;
    }
    size_t value_length = 0U;
    if (mbedtls_asn1_get_tag(&cursor, extension_end, &value_length,
                             MBEDTLS_ASN1_OCTET_STRING) != 0 ||
        value_length > (size_t)(extension_end - cursor) ||
        cursor + value_length != extension_end) {
      return false;
    }
    if (is_basic_constraints) {
      return critical == 1;
    }
    cursor = extension_end;
  }
  return false;
}

static pbns_status
validate_public_key_profile(const mbedtls_x509_crt *certificate) {
  if (mbedtls_pk_get_type(&certificate->pk) != MBEDTLS_PK_ECKEY ||
      certificate->MBEDTLS_PRIVATE(sig_pk) != MBEDTLS_PK_ECDSA ||
      certificate->MBEDTLS_PRIVATE(sig_md) != MBEDTLS_MD_SHA256) {
    return PBNS_ERR_AUTHENTICATION;
  }
  mbedtls_ecp_keypair *const key = mbedtls_pk_ec(certificate->pk);
  if (key == NULL ||
      mbedtls_ecp_keypair_get_group_id(key) != MBEDTLS_ECP_DP_SECP256R1) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return PBNS_OK;
}

static pbns_status validate_signature(mbedtls_x509_crt *certificate) {
  uint8_t digest[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  const bool issuer_matches_subject =
      certificate->issuer_raw.len == certificate->subject_raw.len &&
      certificate->issuer_raw.len > 0U &&
      mbedtls_ct_memcmp(certificate->issuer_raw.p, certificate->subject_raw.p,
                        certificate->issuer_raw.len) == 0;
  const int status =
      issuer_matches_subject && certificate->tbs.p != NULL &&
              certificate->MBEDTLS_PRIVATE(sig).p != NULL &&
              mbedtls_sha256(certificate->tbs.p, certificate->tbs.len, digest,
                             0) == 0
          ? mbedtls_pk_verify(&certificate->pk, MBEDTLS_MD_SHA256, digest,
                              sizeof(digest),
                              certificate->MBEDTLS_PRIVATE(sig).p,
                              certificate->MBEDTLS_PRIVATE(sig).len)
          : -1;
  mbedtls_platform_zeroize(digest, sizeof(digest));
  return status == 0 ? PBNS_OK : PBNS_ERR_AUTHENTICATION;
}

static pbns_status
validate_spki_pin(const mbedtls_x509_crt *certificate,
                  const uint8_t expected[PBNS_TLS_SPKI_SHA256_SIZE]) {
  uint8_t der[PBNS_TLS_SPKI_DER_MAX] = {0};
  uint8_t digest[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  const int encoded =
      mbedtls_pk_write_pubkey_der(&certificate->pk, der, sizeof(der));
  pbns_status status = PBNS_ERR_AUTHENTICATION;
  if (encoded > 0 && (size_t)encoded <= sizeof(der) &&
      mbedtls_sha256(der + sizeof(der) - (size_t)encoded, (size_t)encoded,
                     digest, 0) == 0 &&
      mbedtls_ct_memcmp(digest, expected, sizeof(digest)) == 0) {
    status = PBNS_OK;
  }
  mbedtls_platform_zeroize(digest, sizeof(digest));
  mbedtls_platform_zeroize(der, sizeof(der));
  return status;
}

static pbns_status validate_leaf(const pbns_tls_certificate_policy *policy,
                                 mbedtls_x509_crt *certificate) {
  const int required_extensions =
      MBEDTLS_X509_EXT_BASIC_CONSTRAINTS | MBEDTLS_X509_EXT_KEY_USAGE |
      MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE | MBEDTLS_X509_EXT_SUBJECT_ALT_NAME;
  if (policy == NULL || !policy->initialized || certificate == NULL ||
      certificate->next != NULL || certificate->version != 3 ||
      (certificate->MBEDTLS_PRIVATE(ext_types) & required_extensions) !=
          (int)required_extensions ||
      mbedtls_x509_crt_get_ca_istrue(certificate) != 0 ||
      !basic_constraints_are_critical(certificate) ||
      !certificate_san_matches(certificate,
                               (pbns_view){policy->expected_server_name,
                                           policy->expected_server_name_len}) ||
      validate_public_key_profile(certificate) != PBNS_OK ||
      validate_signature(certificate) != PBNS_OK ||
      certificate->MBEDTLS_PRIVATE(key_usage) !=
          MBEDTLS_X509_KU_DIGITAL_SIGNATURE ||
      mbedtls_x509_crt_check_extended_key_usage(
          certificate, MBEDTLS_OID_SERVER_AUTH,
          MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return validate_spki_pin(certificate, policy->pinned_leaf_spki_sha256);
}

pbns_status
pbns_tls_certificate_policy_init(pbns_tls_certificate_policy *policy,
                                 pbns_view expected_server_name,
                                 pbns_view pinned_leaf_spki_sha256) {
  uint8_t address[16] = {0};
  pbns_tls_endpoint_kind kind = PBNS_TLS_ENDPOINT_DNS;
  const bool endpoint_is_valid =
      classify_endpoint(expected_server_name, &kind, address);
  mbedtls_platform_zeroize(address, sizeof(address));
  if (policy == NULL || !endpoint_is_valid ||
      !view_is_valid(pinned_leaf_spki_sha256) ||
      pinned_leaf_spki_sha256.len != PBNS_TLS_SPKI_SHA256_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  *policy = (pbns_tls_certificate_policy){0};
  memcpy(policy->expected_server_name, expected_server_name.ptr,
         expected_server_name.len);
  memcpy(policy->pinned_leaf_spki_sha256, pinned_leaf_spki_sha256.ptr,
         sizeof(policy->pinned_leaf_spki_sha256));
  policy->expected_server_name_len = expected_server_name.len;
  policy->status = PBNS_OK;
  policy->initialized = true;
  return PBNS_OK;
}

void pbns_tls_certificate_policy_wipe(pbns_tls_certificate_policy *policy) {
  if (policy != NULL) {
    wipe_bytes(policy, sizeof(*policy));
  }
}

int pbns_tls_certificate_verify_callback(void *context,
                                         mbedtls_x509_crt *certificate,
                                         int certificate_depth,
                                         uint32_t *verification_flags) {
  pbns_tls_certificate_policy *const policy = context;
  if (policy == NULL || !policy->initialized || certificate == NULL ||
      verification_flags == NULL || certificate_depth != 0) {
    if (policy != NULL) {
      policy->status = PBNS_ERR_AUTHENTICATION;
    }
    return MBEDTLS_ERR_X509_FATAL_ERROR;
  }
  policy->status = validate_leaf(policy, certificate);
  if (policy->status != PBNS_OK ||
      (*verification_flags & ~((uint32_t)PBNS_TLS_ALLOWED_MBEDTLS_FLAGS)) !=
          0U) {
    policy->status = PBNS_ERR_AUTHENTICATION;
    return MBEDTLS_ERR_X509_FATAL_ERROR;
  }
  policy->mbedtls_verify_flags = *verification_flags;
  *verification_flags &= ~((uint32_t)PBNS_TLS_ALLOWED_MBEDTLS_FLAGS);
  policy->matched = true;
  return 0;
}

pbns_status pbns_tls_validate_negotiated_profile(uint16_t protocol_version,
                                                 uint16_t cipher_suite,
                                                 const char *alpn_protocol) {
  if (protocol_version != PBNS_TLS_VERSION_1_2 ||
      cipher_suite != PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256 ||
      alpn_protocol == NULL ||
      strcmp(alpn_protocol, PBNS_TLS_ALPN_PROTOCOL) != 0) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return PBNS_OK;
}

pbns_status pbns_tls_validate_certificate_der(pbns_view certificate_der,
                                              pbns_view expected_server_name,
                                              pbns_view pinned_leaf_spki_sha256,
                                              uint32_t verification_flags) {
  if (!view_is_valid(certificate_der) || certificate_der.len == 0U ||
      certificate_der.len > PBNS_TLS_CERTIFICATE_DER_MAX) {
    return PBNS_ERR_ARGUMENT;
  }
  mbedtls_x509_crt certificate;
  mbedtls_x509_crt_init(&certificate);
  const int parse_status = mbedtls_x509_crt_parse_der(
      &certificate, certificate_der.ptr, certificate_der.len);
  if (parse_status != 0) {
    const uint32_t category =
        (uint32_t)(-(int64_t)parse_status) & ((uint32_t)0xff80U);
    mbedtls_x509_crt_free(&certificate);
    if (category == ((uint32_t)(-(int64_t)MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) &
                     ((uint32_t)0xff80U)) ||
        category ==
            ((uint32_t)(-(int64_t)MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) &
             ((uint32_t)0xff80U)) ||
        category == ((uint32_t)(-(int64_t)MBEDTLS_ERR_PK_UNKNOWN_PK_ALG) &
                     ((uint32_t)0xff80U)) ||
        category == ((uint32_t)(-(int64_t)MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE) &
                     ((uint32_t)0xff80U)) ||
        category == ((uint32_t)(-(int64_t)MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE) &
                     ((uint32_t)0xff80U)) ||
        category == ((uint32_t)(-(int64_t)MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE) &
                     ((uint32_t)0xff80U))) {
      return PBNS_ERR_AUTHENTICATION;
    }
    return PBNS_ERR_FORMAT;
  }
  pbns_tls_certificate_policy policy = {0};
  pbns_status status = pbns_tls_certificate_policy_init(
      &policy, expected_server_name, pinned_leaf_spki_sha256);
  uint32_t flags = 0U;
  if ((verification_flags &
       ~(PBNS_TLS_VERIFY_NOT_TRUSTED | PBNS_TLS_VERIFY_EXPIRED |
         PBNS_TLS_VERIFY_FUTURE)) != 0U) {
    status = PBNS_ERR_AUTHENTICATION;
  } else {
    if ((verification_flags & PBNS_TLS_VERIFY_NOT_TRUSTED) != 0U) {
      flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    }
    if ((verification_flags & PBNS_TLS_VERIFY_EXPIRED) != 0U) {
      flags |= MBEDTLS_X509_BADCERT_EXPIRED;
    }
    if ((verification_flags & PBNS_TLS_VERIFY_FUTURE) != 0U) {
      flags |= MBEDTLS_X509_BADCERT_FUTURE;
    }
  }
  if (status == PBNS_OK && pbns_tls_certificate_verify_callback(
                               &policy, &certificate, 0, &flags) != 0) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK && flags != 0U) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  pbns_tls_certificate_policy_wipe(&policy);
  mbedtls_x509_crt_free(&certificate);
  return status;
}
