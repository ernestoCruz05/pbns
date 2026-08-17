#include "pbns_proxy/tls_client.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mbedtls/constant_time.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

#if defined(PBNS_PICO_FIRMWARE)
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/ssl.h"
#endif

#if defined(PBNS_TLS_REPLAY_OBSERVER)
#include "pbns_tls_replay/observer.h"
#define PBNS_TLS_REPLAY_MARK(milestone)                                        \
  ((void)pbns_tls_replay_observe_milestone((milestone)))
#define PBNS_TLS_REPLAY_TERMINAL(terminal)                                     \
  ((void)pbns_tls_replay_observe_terminal((terminal)))
#define PBNS_TLS_REPLAY_HANDSHAKE_ERROR(error, endpoint_failure)               \
  pbns_tls_replay_observe_handshake_error((error), (endpoint_failure))
#define PBNS_TLS_REPLAY_SELECTED_VERSION(ssl_context, version)                 \
  pbns_tls_replay_observe_selected_version(                                    \
      mbedtls_ssl_is_handshake_over((ssl_context)) != 0,                       \
      (version) == MBEDTLS_SSL_VERSION_UNKNOWN,                                \
      (version) == MBEDTLS_SSL_VERSION_TLS1_2,                                 \
      (version) == MBEDTLS_SSL_VERSION_TLS1_3,                                 \
      (uint16_t)(version) == PBNS_TLS_VERSION_1_2)
#define PBNS_TLS_REPLAY_SELECTED_PROFILE(version, cipher)                      \
  pbns_tls_replay_observe_selected_profile((uint16_t)(version), (cipher))
#define PBNS_TLS_REPLAY_SELECTED_ALPN(selected)                                \
  pbns_tls_replay_observe_selected_alpn((selected))
#else
#define PBNS_TLS_REPLAY_MARK(milestone) ((void)0)
#define PBNS_TLS_REPLAY_TERMINAL(terminal) ((void)0)
#define PBNS_TLS_REPLAY_HANDSHAKE_ERROR(error, endpoint_failure) ((void)0)
#define PBNS_TLS_REPLAY_SELECTED_VERSION(ssl_context, version) ((void)0)
#define PBNS_TLS_REPLAY_SELECTED_PROFILE(version, cipher) ((void)0)
#define PBNS_TLS_REPLAY_SELECTED_ALPN(selected) ((void)0)
#endif

#define SPKI_DER_CAPACITY 128U
#define ALLOWED_VERIFY_FLAGS                                                   \
  (PBNS_TLS_VERIFY_EXPIRED | PBNS_TLS_VERIFY_FUTURE |                          \
   PBNS_TLS_VERIFY_NOT_TRUSTED)
#define ALLOWED_MBEDTLS_VERIFY_FLAGS                                           \
  (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE |                \
   MBEDTLS_X509_BADCERT_NOT_TRUSTED)

static bool view_is_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool output_is_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static pbns_status
validate_public_key_profile(const mbedtls_pk_context *public_key) {
  if (mbedtls_pk_get_type(public_key) != MBEDTLS_PK_ECKEY) {
    return PBNS_ERR_UNSUPPORTED;
  }
  mbedtls_ecp_keypair *const ec = mbedtls_pk_ec(*public_key);
  if (ec == NULL ||
      mbedtls_ecp_keypair_get_group_id(ec) != MBEDTLS_ECP_DP_SECP256R1) {
    return PBNS_ERR_UNSUPPORTED;
  }
  return PBNS_OK;
}

static pbns_status
parsed_spki_sha256(mbedtls_x509_crt *certificate,
                   uint8_t digest[PBNS_TLS_SPKI_SHA256_SIZE]) {
  const pbns_status profile_status =
      validate_public_key_profile(&certificate->pk);
  if (profile_status != PBNS_OK) {
    return profile_status;
  }

  uint8_t encoded[SPKI_DER_CAPACITY] = {0};
  const int encoded_len =
      mbedtls_pk_write_pubkey_der(&certificate->pk, encoded, sizeof(encoded));
  if (encoded_len <= 0 || (size_t)encoded_len > sizeof(encoded)) {
    mbedtls_platform_zeroize(encoded, sizeof(encoded));
    return PBNS_ERR_CRYPTO;
  }
  const size_t length = (size_t)encoded_len;
  const uint8_t *const start = encoded + sizeof(encoded) - length;
  const int hash_status = mbedtls_sha256(start, length, digest, 0);
  mbedtls_platform_zeroize(encoded, sizeof(encoded));
  return hash_status == 0 ? PBNS_OK : PBNS_ERR_CRYPTO;
}

static pbns_status verify_parsed_certificate(mbedtls_x509_crt *certificate,
                                             pbns_view expected_spki,
                                             uint32_t verification_flags) {
  if (certificate == NULL || !view_is_valid(expected_spki) ||
      expected_spki.len != PBNS_TLS_SPKI_SHA256_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  uint8_t actual[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  pbns_status status = parsed_spki_sha256(certificate, actual);
  if (status == PBNS_OK &&
      mbedtls_ct_memcmp(actual, expected_spki.ptr, sizeof(actual)) != 0) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  if (status == PBNS_OK &&
      (verification_flags & ~((uint32_t)ALLOWED_VERIFY_FLAGS)) != 0U) {
    status = PBNS_ERR_AUTHENTICATION;
  }
  mbedtls_platform_zeroize(actual, sizeof(actual));
  return status;
}

static uint32_t mbedtls_error_category(int error) {
  return (uint32_t)(-(int64_t)error) & UINT32_C(0xff80);
}

static pbns_status parse_certificate(pbns_view encoded,
                                     mbedtls_x509_crt *certificate) {
  if (!view_is_valid(encoded) || encoded.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (encoded.len > PBNS_TLS_CERTIFICATE_DER_MAX) {
    return PBNS_ERR_LIMIT;
  }
  mbedtls_x509_crt_init(certificate);
  const int parse_status =
      mbedtls_x509_crt_parse_der(certificate, encoded.ptr, encoded.len);
  if (parse_status != 0) {
    mbedtls_x509_crt_free(certificate);
    const uint32_t category = mbedtls_error_category(parse_status);
    if (category == mbedtls_error_category(MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG) ||
        category ==
            mbedtls_error_category(MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) ||
        category == mbedtls_error_category(MBEDTLS_ERR_PK_UNKNOWN_PK_ALG) ||
        category ==
            mbedtls_error_category(MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE)) {
      return PBNS_ERR_UNSUPPORTED;
    }
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

pbns_status pbns_tls_certificate_spki_sha256(pbns_view certificate_der,
                                             pbns_buffer output,
                                             size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (!output_is_valid(output)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (output.cap < PBNS_TLS_SPKI_SHA256_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  mbedtls_x509_crt certificate;
  const pbns_status parse_status =
      parse_certificate(certificate_der, &certificate);
  if (parse_status != PBNS_OK) {
    return parse_status;
  }
  uint8_t digest[PBNS_TLS_SPKI_SHA256_SIZE] = {0};
  const pbns_status status = parsed_spki_sha256(&certificate, digest);
  if (status == PBNS_OK) {
    memcpy(output.ptr, digest, sizeof(digest));
    *written = sizeof(digest);
  }
  mbedtls_platform_zeroize(digest, sizeof(digest));
  mbedtls_x509_crt_free(&certificate);
  return status;
}

pbns_status pbns_tls_verify_certificate(pbns_view certificate_der,
                                        uint32_t verification_flags,
                                        pbns_view expected_spki) {
  if (!view_is_valid(expected_spki) ||
      expected_spki.len != PBNS_TLS_SPKI_SHA256_SIZE) {
    return PBNS_ERR_ARGUMENT;
  }
  mbedtls_x509_crt certificate;
  const pbns_status parse_status =
      parse_certificate(certificate_der, &certificate);
  if (parse_status != PBNS_OK) {
    return parse_status;
  }
  const pbns_status status = verify_parsed_certificate(
      &certificate, expected_spki, verification_flags);
  mbedtls_x509_crt_free(&certificate);
  return status;
}

pbns_status pbns_tls_validate_profile(uint16_t protocol_version,
                                      uint16_t cipher_suite,
                                      const char *alpn_protocol) {
  return protocol_version == PBNS_TLS_VERSION_1_2 &&
                 cipher_suite == PBNS_TLS_ECDHE_ECDSA_AES128_GCM_SHA256 &&
                 alpn_protocol != NULL &&
                 strcmp(alpn_protocol, PBNS_TLS_ALPN_PROTOCOL) == 0
             ? PBNS_OK
             : PBNS_ERR_UNSUPPORTED;
}

pbns_status pbns_tls_pin_verifier_init(pbns_tls_pin_verifier *verifier,
                                       pbns_view expected_spki) {
  if (verifier != NULL) {
    *verifier = (pbns_tls_pin_verifier){0};
  }
  if (verifier == NULL || !view_is_valid(expected_spki) ||
      expected_spki.len != sizeof(verifier->expected_spki)) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(verifier->expected_spki, expected_spki.ptr,
         sizeof(verifier->expected_spki));
  verifier->status = PBNS_OK;
  verifier->initialized = true;
  return PBNS_OK;
}

int pbns_tls_certificate_verify_callback(void *context,
                                         mbedtls_x509_crt *certificate,
                                         int certificate_depth,
                                         uint32_t *verification_flags) {
  pbns_tls_pin_verifier *const verifier = context;
  if (verifier == NULL || !verifier->initialized || certificate == NULL ||
      verification_flags == NULL || certificate_depth < 0) {
    if (verifier != NULL) {
      verifier->status = PBNS_ERR_AUTHENTICATION;
    }
    return MBEDTLS_ERR_X509_FATAL_ERROR;
  }
  PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_CERTIFICATE_VERIFIER_ENTERED);
  if ((*verification_flags & ~((uint32_t)ALLOWED_MBEDTLS_VERIFY_FLAGS)) != 0U) {
    verifier->status = PBNS_ERR_AUTHENTICATION;
    PBNS_TLS_REPLAY_TERMINAL(PBNS_TLS_REPLAY_HANDSHAKE_CERTIFICATE_FLAGS);
    return MBEDTLS_ERR_X509_FATAL_ERROR;
  }
  *verification_flags = 0U;
  if (certificate_depth > 0) {
    return 0;
  }
  verifier->status = verify_parsed_certificate(
      certificate,
      (pbns_view){verifier->expected_spki, sizeof(verifier->expected_spki)},
      0U);
  if (verifier->status != PBNS_OK) {
    PBNS_TLS_REPLAY_TERMINAL(verifier->status == PBNS_ERR_AUTHENTICATION
                                 ? PBNS_TLS_REPLAY_HANDSHAKE_PIN
                                 : PBNS_TLS_REPLAY_UNKNOWN);
    return MBEDTLS_ERR_X509_FATAL_ERROR;
  }
  verifier->matched = true;
  PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_LEAF_SPKI_MATCHED);
  return 0;
}

#if defined(PBNS_PICO_FIRMWARE)
static bool allocator_in_use;
static const int approved_cipher_suites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    0,
};
static const char *approved_alpn_protocols[] = {
    PBNS_TLS_ALPN_PROTOCOL,
    NULL,
};

static int encrypted_send(void *context, const unsigned char *buffer,
                          size_t length) {
  pbns_tls_client *const client = context;
  size_t written = 0U;
  const pbns_status status = client->encrypted.write(
      client->encrypted.context, (pbns_view){buffer, length}, &written);
  if (status == PBNS_ERR_WOULD_BLOCK) {
    if (written == 0U) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    client->failure = PBNS_ERR_STATE;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  if (status != PBNS_OK || written == 0U || written > length ||
      written > (size_t)INT_MAX) {
    client->failure = status == PBNS_OK ? PBNS_ERR_STATE : status;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_FIRST_CLIENT_BYTES_WRITTEN);
  return (int)written;
}

static int encrypted_receive(void *context, unsigned char *buffer,
                             size_t length) {
  pbns_tls_client *const client = context;
  size_t received = 0U;
  const pbns_status status = client->encrypted.read(
      client->encrypted.context, (pbns_buffer){buffer, 0U, length}, &received);
  if (status == PBNS_ERR_WOULD_BLOCK) {
    if (received == 0U) {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }
    client->failure = PBNS_ERR_STATE;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  if (status != PBNS_OK || received > length || received > (size_t)INT_MAX) {
    client->failure = status == PBNS_OK ? PBNS_ERR_STATE : status;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  if (received > 0U) {
    PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_FIRST_SERVER_BYTES_RECEIVED);
  }
  return (int)received;
}

static pbns_status validate_handshake(pbns_tls_client *client) {
  if (!client->pin_verifier.matched || client->pin_verifier.status != PBNS_OK ||
      mbedtls_ssl_get_verify_result(&client->ssl) != 0U) {
    return client->pin_verifier.status == PBNS_OK ? PBNS_ERR_AUTHENTICATION
                                                  : client->pin_verifier.status;
  }
  const mbedtls_ssl_protocol_version version =
      mbedtls_ssl_get_version_number(&client->ssl);
  PBNS_TLS_REPLAY_SELECTED_VERSION(&client->ssl, version);
  const int cipher_suite =
      mbedtls_ssl_get_ciphersuite_id_from_ssl(&client->ssl);
  PBNS_TLS_REPLAY_SELECTED_PROFILE(version, cipher_suite);
  if (cipher_suite < 0 || cipher_suite > UINT16_MAX) {
    return PBNS_ERR_UNSUPPORTED;
  }
  const char *const selected_alpn = mbedtls_ssl_get_alpn_protocol(&client->ssl);
  PBNS_TLS_REPLAY_SELECTED_ALPN(selected_alpn != NULL &&
                                strcmp(selected_alpn, PBNS_TLS_ALPN_PROTOCOL) ==
                                    0);
  return pbns_tls_validate_profile((uint16_t)version, (uint16_t)cipher_suite,
                                   selected_alpn);
}

static void release_client(pbns_tls_client *client, bool send_close_notify) {
  if (send_close_notify && client->initialized) {
    (void)mbedtls_ssl_close_notify(&client->ssl);
  }
  mbedtls_ssl_free(&client->ssl);
  mbedtls_ssl_config_free(&client->config);
  mbedtls_ctr_drbg_free(&client->random);
  mbedtls_entropy_free(&client->entropy);
  mbedtls_memory_buffer_alloc_free();
  mbedtls_platform_zeroize(client, sizeof(*client));
  allocator_in_use = false;
}

pbns_status pbns_tls_client_init(pbns_tls_client *client, pbns_view hostname,
                                 pbns_view expected_spki,
                                 pbns_pump_endpoint encrypted) {
  if (client == NULL || allocator_in_use || !view_is_valid(hostname) ||
      hostname.len == 0U || hostname.len > 253U ||
      memchr(hostname.ptr, 0, hostname.len) != NULL ||
      !view_is_valid(expected_spki) ||
      expected_spki.len != PBNS_TLS_SPKI_SHA256_SIZE ||
      encrypted.read == NULL || encrypted.write == NULL) {
    PBNS_TLS_REPLAY_TERMINAL(PBNS_TLS_REPLAY_INIT_CONTRACT);
    return allocator_in_use ? PBNS_ERR_BUSY : PBNS_ERR_ARGUMENT;
  }
  *client = (pbns_tls_client){0};
  allocator_in_use = true;
#if defined(PBNS_TLS_REPLAY_OBSERVER)
  const size_t heap_bytes = pbns_tls_replay_heap_bytes(sizeof(client->heap));
  if (heap_bytes == 0U) {
    allocator_in_use = false;
    PBNS_TLS_REPLAY_TERMINAL(PBNS_TLS_REPLAY_INIT_CONTRACT);
    return PBNS_ERR_ARGUMENT;
  }
  mbedtls_memory_buffer_alloc_init((unsigned char *)client->heap, heap_bytes);
#else
  mbedtls_memory_buffer_alloc_init((unsigned char *)client->heap,
                                   sizeof(client->heap));
#endif
  PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_ALLOCATOR_INSTALLED);
  mbedtls_ssl_init(&client->ssl);
  mbedtls_ssl_config_init(&client->config);
  mbedtls_ctr_drbg_init(&client->random);
  mbedtls_entropy_init(&client->entropy);
  client->initialized = true;
  client->failure = PBNS_OK;
  client->encrypted = encrypted;

  pbns_status status =
      pbns_tls_pin_verifier_init(&client->pin_verifier, expected_spki);
  if (status == PBNS_OK) {
    PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_PIN_VERIFIER_INITIALIZED);
  }
  static const unsigned char personalization[] = "PBNS-PICO-TLS-v1";
  if (status == PBNS_OK) {
    if (mbedtls_ctr_drbg_seed(&client->random, mbedtls_entropy_func,
                              &client->entropy, personalization,
                              sizeof(personalization) - 1U) != 0) {
      status = PBNS_ERR_ENTROPY;
    } else {
      PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_DRBG_SEEDED);
    }
  }
  if (status == PBNS_OK) {
    if (mbedtls_ssl_config_defaults(&client->config, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
      status = PBNS_ERR_RESOURCE;
    } else {
      PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_TLS_DEFAULTS_CONFIGURED);
    }
  }
  if (status == PBNS_OK) {
    mbedtls_ssl_conf_authmode(&client->config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&client->config,
                            pbns_tls_certificate_verify_callback,
                            &client->pin_verifier);
    mbedtls_ssl_conf_rng(&client->config, mbedtls_ctr_drbg_random,
                         &client->random);
    mbedtls_ssl_conf_min_tls_version(&client->config,
                                     MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_max_tls_version(&client->config,
                                     MBEDTLS_SSL_VERSION_TLS1_2);
    mbedtls_ssl_conf_ciphersuites(&client->config, approved_cipher_suites);
    if (mbedtls_ssl_conf_alpn_protocols(&client->config,
                                        approved_alpn_protocols) != 0 ||
        mbedtls_ssl_setup(&client->ssl, &client->config) != 0) {
      status = PBNS_ERR_RESOURCE;
    } else {
      PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_SSL_CONTEXT_CONFIGURED);
    }
  }
  char hostname_string[254] = {0};
  if (status == PBNS_OK) {
    memcpy(hostname_string, hostname.ptr, hostname.len);
    if (mbedtls_ssl_set_hostname(&client->ssl, hostname_string) != 0) {
      status = PBNS_ERR_RESOURCE;
    } else {
      PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_HOSTNAME_INSTALLED);
    }
  }
  mbedtls_platform_zeroize(hostname_string, sizeof(hostname_string));
  if (status == PBNS_OK) {
    mbedtls_ssl_set_bio(&client->ssl, client, encrypted_send, encrypted_receive,
                        NULL);
    PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_ENCRYPTED_BIO_INSTALLED);
    return PBNS_OK;
  }
  PBNS_TLS_REPLAY_TERMINAL(
      status == PBNS_ERR_ENTROPY ? PBNS_TLS_REPLAY_INIT_ENTROPY
      : status == PBNS_ERR_ARGUMENT || status == PBNS_ERR_BUSY
          ? PBNS_TLS_REPLAY_INIT_CONTRACT
          : PBNS_TLS_REPLAY_INIT_RESOURCE);
  release_client(client, false);
  return status;
}

pbns_status pbns_tls_client_step(pbns_tls_client *client) {
  if (client == NULL || !client->initialized) {
    return PBNS_ERR_ARGUMENT;
  }
  if (client->failure != PBNS_OK) {
    return client->failure;
  }
  if (client->ready) {
    return PBNS_OK;
  }
  const int status = mbedtls_ssl_handshake(&client->ssl);
  if (status == MBEDTLS_ERR_SSL_WANT_READ ||
      status == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (status != 0) {
    PBNS_TLS_REPLAY_HANDSHAKE_ERROR(status, client->failure);
    if (client->failure == PBNS_OK) {
      client->failure = client->pin_verifier.status != PBNS_OK
                            ? client->pin_verifier.status
                            : PBNS_ERR_AUTHENTICATION;
    }
    return client->failure;
  }
  PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_HANDSHAKE_COMPLETED);
  client->failure = validate_handshake(client);
  if (client->failure == PBNS_OK) {
    PBNS_TLS_REPLAY_MARK(PBNS_TLS_REPLAY_PROFILE_VALIDATED);
    PBNS_TLS_REPLAY_TERMINAL(PBNS_TLS_REPLAY_READY);
    client->ready = true;
  } else {
    PBNS_TLS_REPLAY_TERMINAL(client->failure == PBNS_ERR_UNSUPPORTED
                                 ? PBNS_TLS_REPLAY_PROFILE_UNSUPPORTED
                                 : PBNS_TLS_REPLAY_UNKNOWN);
  }
  return client->failure;
}

void pbns_tls_client_free(pbns_tls_client *client) {
  if (client == NULL || !client->initialized) {
    return;
  }
  release_client(client, client->ready);
}

static pbns_status plaintext_read(void *context, pbns_buffer destination,
                                  size_t *received) {
  pbns_tls_client *const client = context;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (client == NULL || !client->initialized || !client->ready ||
      destination.len != 0U || destination.ptr == NULL ||
      destination.cap == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  const int result =
      mbedtls_ssl_read(&client->ssl, destination.ptr, destination.cap);
  if (result > 0) {
    *received = (size_t)result;
    return PBNS_OK;
  }
  if (result == MBEDTLS_ERR_SSL_WANT_READ ||
      result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (result == 0 || result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
    client->failure = PBNS_ERR_TRANSPORT;
    return PBNS_OK;
  }
  client->failure = PBNS_ERR_TRANSPORT;
  return client->failure;
}

static pbns_status plaintext_write(void *context, pbns_view source,
                                   size_t *written) {
  pbns_tls_client *const client = context;
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (client == NULL || !client->initialized || !client->ready ||
      source.ptr == NULL || source.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  const int result = mbedtls_ssl_write(&client->ssl, source.ptr, source.len);
  if (result > 0) {
    *written = (size_t)result;
    return PBNS_OK;
  }
  if (result == MBEDTLS_ERR_SSL_WANT_READ ||
      result == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  client->failure = PBNS_ERR_TRANSPORT;
  return client->failure;
}

pbns_pump_endpoint pbns_tls_client_plaintext_endpoint(pbns_tls_client *client) {
  return (pbns_pump_endpoint){
      .read = plaintext_read,
      .write = plaintext_write,
      .context = client,
  };
}
#endif
