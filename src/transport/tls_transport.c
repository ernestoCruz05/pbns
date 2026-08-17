#ifdef PBNS_EDK2
#include <CrtLibSupport.h>
#endif

#include "pbns/tls_transport.h"

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>

#include "pbns/tls_handshake_observer.h"
#include "pbns/tls_policy.h"

#define PBNS_TLS_STAGNATION_MAX 16U
#define PBNS_TLS_STEP_MAX 4096U

static const int approved_cipher_suites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    0,
};
static const char *approved_alpn_protocols[] = {
    PBNS_TLS_ALPN_PROTOCOL,
    NULL,
};

typedef enum pbns_tls_state {
  PBNS_TLS_STATE_CREATED,
  PBNS_TLS_STATE_OPENING,
  PBNS_TLS_STATE_READY,
} pbns_tls_state;

struct pbns_tls_transport {
  pbns_transport lower;
  pbns_tls_platform platform;
  pbns_tls_certificate_policy immutable_policy;
  pbns_tls_certificate_policy certificate_policy;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config configuration;
  mbedtls_ctr_drbg_context drbg;
  pbns_tls_handshake_observer certificate_observer;
  uint64_t deadline_ms;
  uint64_t last_now_ms;
  uint64_t bio_progress_generation;
  uint32_t handshake_timeout_ms;
  pbns_status failure;
  pbns_tls_state state;
  bool deadline_active;
  bool have_last_now;
  bool lower_open;
  bool mbedtls_initialized;
};

static void wipe_bytes(void *bytes, size_t length) {
  volatile uint8_t *cursor = bytes;
  while (length > 0U) {
    *cursor++ = 0U;
    --length;
  }
}

static bool lower_is_valid(pbns_transport lower) {
  return lower.ops != NULL && lower.ops->open != NULL &&
         lower.ops->close != NULL && lower.ops->send != NULL &&
         lower.ops->receive != NULL && lower.ops->cancel != NULL &&
         lower.ops->limits != NULL;
}

static bool platform_is_valid(pbns_tls_platform platform) {
  return platform.ops != NULL && platform.ops->random != NULL &&
         platform.ops->monotonic_ms != NULL && platform.ops->allocate != NULL &&
         platform.ops->release != NULL;
}

static void end_deadline(pbns_tls_transport *transport) {
  transport->deadline_ms = 0U;
  transport->last_now_ms = 0U;
  transport->deadline_active = false;
  transport->have_last_now = false;
}

static pbns_status begin_deadline(pbns_tls_transport *transport,
                                  uint32_t timeout_ms) {
  if (transport->deadline_active) {
    return PBNS_OK;
  }
  if (timeout_ms == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  uint64_t now_ms = 0U;
  const pbns_status status = transport->platform.ops->monotonic_ms(
      transport->platform.context, &now_ms);
  if (status != PBNS_OK) {
    return status;
  }
  transport->deadline_ms = UINT64_MAX - now_ms < (uint64_t)timeout_ms
                               ? UINT64_MAX
                               : now_ms + (uint64_t)timeout_ms;
  transport->last_now_ms = now_ms;
  transport->have_last_now = true;
  transport->deadline_active = true;
  return PBNS_OK;
}

static pbns_status deadline_remaining(pbns_tls_transport *transport,
                                      uint32_t *remaining_ms) {
  if (remaining_ms == NULL || !transport->deadline_active) {
    return PBNS_ERR_STATE;
  }
  uint64_t now_ms = 0U;
  const pbns_status status = transport->platform.ops->monotonic_ms(
      transport->platform.context, &now_ms);
  if (status != PBNS_OK) {
    return status;
  }
  if (transport->have_last_now && now_ms < transport->last_now_ms) {
    return PBNS_ERR_STATE;
  }
  transport->last_now_ms = now_ms;
  transport->have_last_now = true;
  if (now_ms >= transport->deadline_ms) {
    return PBNS_ERR_TIMEOUT;
  }
  const uint64_t remaining = transport->deadline_ms - now_ms;
  *remaining_ms =
      remaining > (uint64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
  return *remaining_ms == 0U ? PBNS_ERR_TIMEOUT : PBNS_OK;
}

static int random_callback(void *context, unsigned char *output,
                           size_t length) {
  pbns_tls_transport *const transport = context;
  if (transport == NULL || output == NULL || length == 0U) {
    return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
  }
  const pbns_status status = transport->platform.ops->random(
      transport->platform.context, (pbns_buffer){output, 0U, length});
  if (status != PBNS_OK) {
    transport->failure = PBNS_ERR_ENTROPY;
    return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
  }
  return 0;
}

static int encrypted_send(void *context, const unsigned char *bytes,
                          size_t length) {
  pbns_tls_transport *const transport = context;
  uint32_t remaining_ms = 0U;
  if (transport == NULL || bytes == NULL || length == 0U ||
      length > (size_t)INT_MAX) {
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  const pbns_status time_status = deadline_remaining(transport, &remaining_ms);
  if (time_status != PBNS_OK) {
    transport->failure = time_status;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  const pbns_status status = transport->lower.ops->send(
      transport->lower.context, (pbns_view){bytes, length}, remaining_ms);
  if (status == PBNS_OK) {
    ++transport->bio_progress_generation;
    return (int)length;
  }
  if (status == PBNS_ERR_WOULD_BLOCK) {
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  }
  transport->failure = status;
  return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int encrypted_receive(void *context, unsigned char *bytes,
                             size_t length) {
  pbns_tls_transport *const transport = context;
  uint32_t remaining_ms = 0U;
  size_t received = 0U;
  if (transport == NULL || bytes == NULL || length == 0U ||
      length > (size_t)INT_MAX) {
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  const pbns_status time_status = deadline_remaining(transport, &remaining_ms);
  if (time_status != PBNS_OK) {
    transport->failure = time_status;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  const pbns_status status = transport->lower.ops->receive(
      transport->lower.context, (pbns_buffer){bytes, 0U, length}, remaining_ms,
      &received);
  if (status == PBNS_ERR_WOULD_BLOCK && received == 0U) {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  if (status != PBNS_OK || received == 0U || received > length ||
      received > (size_t)INT_MAX) {
    transport->failure = status == PBNS_OK ? PBNS_ERR_TRANSPORT : status;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  const pbns_status observer_status = pbns_tls_handshake_observer_observe(
      &transport->certificate_observer, (pbns_view){bytes, received});
  if (observer_status != PBNS_OK) {
    transport->failure = observer_status;
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
  }
  ++transport->bio_progress_generation;
  return (int)received;
}

static void release_mbedtls(pbns_tls_transport *transport) {
  if (!transport->mbedtls_initialized) {
    return;
  }
  mbedtls_ssl_free(&transport->ssl);
  mbedtls_ssl_config_free(&transport->configuration);
  mbedtls_ctr_drbg_free(&transport->drbg);
  wipe_bytes(&transport->ssl, sizeof(transport->ssl));
  wipe_bytes(&transport->configuration, sizeof(transport->configuration));
  wipe_bytes(&transport->drbg, sizeof(transport->drbg));
  transport->mbedtls_initialized = false;
}

static pbns_status reset_session(pbns_tls_transport *transport,
                                 pbns_status requested_status) {
  pbns_status status = requested_status;
  if (transport->lower_open) {
    const pbns_status close_status =
        transport->lower.ops->close(transport->lower.context);
    if (status == PBNS_OK && close_status != PBNS_OK) {
      status = close_status;
    }
    transport->lower_open = false;
  }
  release_mbedtls(transport);
  pbns_tls_certificate_policy_wipe(&transport->certificate_policy);
  wipe_bytes(&transport->certificate_observer,
             sizeof(transport->certificate_observer));
  end_deadline(transport);
  transport->state = PBNS_TLS_STATE_CREATED;
  transport->failure = PBNS_OK;
  return status;
}

static pbns_status fail_session(pbns_tls_transport *transport,
                                pbns_status requested_status) {
  const pbns_status status =
      transport->failure == PBNS_OK ? requested_status : transport->failure;
  return reset_session(transport, status);
}

static pbns_status configure_mbedtls(pbns_tls_transport *transport) {
  static const unsigned char personalization[] = "PBNS-UEFI-TLS-v1";
  mbedtls_ssl_init(&transport->ssl);
  mbedtls_ssl_config_init(&transport->configuration);
  mbedtls_ctr_drbg_init(&transport->drbg);
  transport->mbedtls_initialized = true;
  if (mbedtls_ctr_drbg_seed(&transport->drbg, random_callback, transport,
                            personalization,
                            sizeof(personalization) - 1U) != 0) {
    return PBNS_ERR_ENTROPY;
  }
  if (mbedtls_ssl_config_defaults(
          &transport->configuration, MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    return PBNS_ERR_RESOURCE;
  }
  transport->certificate_policy = transport->immutable_policy;
  // O Mbed TLS exige uma cadeia CA com VERIFY_REQUIRED; a validação PBNS é
  // obrigatória antes de expor texto simples e não aceita resultados opcionais.
  mbedtls_ssl_conf_authmode(&transport->configuration,
                            MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_verify(&transport->configuration,
                          pbns_tls_certificate_verify_callback,
                          &transport->certificate_policy);
  mbedtls_ssl_conf_rng(&transport->configuration, mbedtls_ctr_drbg_random,
                       &transport->drbg);
  mbedtls_ssl_conf_min_tls_version(&transport->configuration,
                                   MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&transport->configuration,
                                   MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_ciphersuites(&transport->configuration,
                                approved_cipher_suites);
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
  // O PBNS não reutiliza sessões nem depende do relógio local no bootstrap.
  mbedtls_ssl_conf_session_tickets(&transport->configuration,
                                   MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
#endif
  if (mbedtls_ssl_conf_alpn_protocols(&transport->configuration,
                                      approved_alpn_protocols) != 0 ||
      mbedtls_ssl_setup(&transport->ssl, &transport->configuration) != 0) {
    return PBNS_ERR_RESOURCE;
  }
  mbedtls_ssl_set_bio(&transport->ssl, transport, encrypted_send,
                      encrypted_receive, NULL);
  pbns_tls_handshake_observer_init(&transport->certificate_observer);
  return PBNS_OK;
}

static pbns_status validate_handshake(pbns_tls_transport *transport) {
  if (!transport->certificate_policy.matched ||
      transport->certificate_policy.status != PBNS_OK ||
      transport->certificate_policy.mbedtls_verify_flags !=
          (transport->certificate_policy.mbedtls_verify_flags &
           (MBEDTLS_X509_BADCERT_NOT_TRUSTED | MBEDTLS_X509_BADCERT_EXPIRED |
            MBEDTLS_X509_BADCERT_FUTURE)) ||
      mbedtls_ssl_get_verify_result(&transport->ssl) != 0U) {
    return PBNS_ERR_AUTHENTICATION;
  }
  const int cipher = mbedtls_ssl_get_ciphersuite_id_from_ssl(&transport->ssl);
  if (cipher < 0 || cipher > (int)UINT16_MAX) {
    return PBNS_ERR_AUTHENTICATION;
  }
  return pbns_tls_validate_negotiated_profile(
      (uint16_t)mbedtls_ssl_get_version_number(&transport->ssl),
      (uint16_t)cipher, mbedtls_ssl_get_alpn_protocol(&transport->ssl));
}

static bool is_want(int result) {
  return result == MBEDTLS_ERR_SSL_WANT_READ ||
         result == MBEDTLS_ERR_SSL_WANT_WRITE;
}

static pbns_status continue_after_want(pbns_tls_transport *transport,
                                       uint64_t before_progress,
                                       uint64_t before_now_ms,
                                       uint32_t *stagnation) {
  uint32_t ignored = 0U;
  const pbns_status status = deadline_remaining(transport, &ignored);
  if (status != PBNS_OK) {
    return status;
  }
  if (transport->bio_progress_generation != before_progress ||
      transport->last_now_ms > before_now_ms) {
    *stagnation = 0U;
    return PBNS_OK;
  }
  if (*stagnation == PBNS_TLS_STAGNATION_MAX) {
    return PBNS_ERR_TRANSPORT;
  }
  ++*stagnation;
  return PBNS_OK;
}

static pbns_status transport_open(void *context) {
  pbns_tls_transport *const transport = context;
  if (transport == NULL || transport->state != PBNS_TLS_STATE_CREATED) {
    return PBNS_ERR_STATE;
  }
  pbns_status status =
      begin_deadline(transport, transport->handshake_timeout_ms);
  if (status != PBNS_OK) {
    return fail_session(transport, status);
  }
  transport->failure = PBNS_OK;
  status = transport->lower.ops->open(transport->lower.context);
  if (status != PBNS_OK) {
    (void)transport->lower.ops->close(transport->lower.context);
    end_deadline(transport);
    return status;
  }
  transport->lower_open = true;
  transport->state = PBNS_TLS_STATE_OPENING;
  status = configure_mbedtls(transport);
  if (status != PBNS_OK) {
    return fail_session(transport, status);
  }
  uint32_t stagnation = 0U;
  for (uint32_t steps = 0U; steps < PBNS_TLS_STEP_MAX; ++steps) {
    const uint64_t before_progress = transport->bio_progress_generation;
    const uint64_t before_now_ms = transport->last_now_ms;
    const int result = mbedtls_ssl_handshake(&transport->ssl);
    if (result == 0) {
      status = validate_handshake(transport);
      if (status == PBNS_OK) {
        uint32_t remaining_ms = 0U;
        status = deadline_remaining(transport, &remaining_ms);
        if (status == PBNS_OK) {
          transport->state = PBNS_TLS_STATE_READY;
          end_deadline(transport);
          return PBNS_OK;
        }
      }
      return fail_session(transport, status);
    }
    if (!is_want(result)) {
      return fail_session(transport, transport->failure == PBNS_OK
                                         ? PBNS_ERR_AUTHENTICATION
                                         : transport->failure);
    }
    status = continue_after_want(transport, before_progress, before_now_ms,
                                 &stagnation);
    if (status != PBNS_OK) {
      return fail_session(transport, status);
    }
  }
  return fail_session(transport, PBNS_ERR_TRANSPORT);
}

static pbns_status transport_close(void *context) {
  pbns_tls_transport *const transport = context;
  if (transport == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (transport->state != PBNS_TLS_STATE_READY) {
    return reset_session(transport, PBNS_OK);
  }
  pbns_status status =
      begin_deadline(transport, transport->handshake_timeout_ms);
  if (status == PBNS_OK) {
    uint32_t stagnation = 0U;
    for (uint32_t steps = 0U; steps < PBNS_TLS_STEP_MAX; ++steps) {
      const uint64_t before_progress = transport->bio_progress_generation;
      const uint64_t before_now_ms = transport->last_now_ms;
      const int result = mbedtls_ssl_close_notify(&transport->ssl);
      if (result == 0) {
        break;
      }
      if (!is_want(result)) {
        status = transport->failure == PBNS_OK ? PBNS_ERR_TRANSPORT
                                               : transport->failure;
        break;
      }
      status = continue_after_want(transport, before_progress, before_now_ms,
                                   &stagnation);
      if (status != PBNS_OK) {
        break;
      }
      if (steps + 1U == PBNS_TLS_STEP_MAX) {
        status = PBNS_ERR_TRANSPORT;
      }
    }
  }
  return reset_session(transport, status);
}

static pbns_status transport_send(void *context, pbns_view bytes,
                                  uint32_t timeout_ms) {
  pbns_tls_transport *const transport = context;
  if (transport == NULL || bytes.ptr == NULL || bytes.len == 0U ||
      bytes.len > (size_t)INT_MAX || transport->state != PBNS_TLS_STATE_READY) {
    return PBNS_ERR_STATE;
  }
  pbns_status status = begin_deadline(transport, timeout_ms);
  if (status != PBNS_OK) {
    return fail_session(transport, status);
  }
  size_t offset = 0U;
  uint32_t stagnation = 0U;
  for (uint32_t steps = 0U; steps < PBNS_TLS_STEP_MAX && offset < bytes.len;
       ++steps) {
    const uint64_t before_progress = transport->bio_progress_generation;
    const uint64_t before_now_ms = transport->last_now_ms;
    const int result = mbedtls_ssl_write(&transport->ssl, bytes.ptr + offset,
                                         bytes.len - offset);
    if (result > 0) {
      if ((size_t)result > bytes.len - offset) {
        return fail_session(transport, PBNS_ERR_TRANSPORT);
      }
      offset += (size_t)result;
      stagnation = 0U;
      continue;
    }
    if (!is_want(result)) {
      return fail_session(transport, transport->failure == PBNS_OK
                                         ? PBNS_ERR_TRANSPORT
                                         : transport->failure);
    }
    status = continue_after_want(transport, before_progress, before_now_ms,
                                 &stagnation);
    if (status != PBNS_OK) {
      return fail_session(transport, status);
    }
  }
  if (offset != bytes.len) {
    return fail_session(transport, PBNS_ERR_TRANSPORT);
  }
  uint32_t remaining_ms = 0U;
  status = deadline_remaining(transport, &remaining_ms);
  if (status != PBNS_OK) {
    return fail_session(transport, status);
  }
  end_deadline(transport);
  return PBNS_OK;
}

static pbns_status transport_receive(void *context, pbns_buffer buffer,
                                     uint32_t timeout_ms, size_t *received) {
  pbns_tls_transport *const transport = context;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (transport == NULL || buffer.ptr == NULL || buffer.len != 0U ||
      buffer.cap == 0U || buffer.cap > (size_t)INT_MAX ||
      transport->state != PBNS_TLS_STATE_READY) {
    return PBNS_ERR_STATE;
  }
  pbns_status status = begin_deadline(transport, timeout_ms);
  if (status != PBNS_OK) {
    return fail_session(transport, status);
  }
  uint32_t stagnation = 0U;
  for (uint32_t steps = 0U; steps < PBNS_TLS_STEP_MAX; ++steps) {
    const uint64_t before_progress = transport->bio_progress_generation;
    const uint64_t before_now_ms = transport->last_now_ms;
    const int result =
        mbedtls_ssl_read(&transport->ssl, buffer.ptr, buffer.cap);
    if (result > 0) {
      uint32_t remaining_ms = 0U;
      status = deadline_remaining(transport, &remaining_ms);
      if (status != PBNS_OK) {
        return fail_session(transport, status);
      }
      *received = (size_t)result;
      end_deadline(transport);
      return PBNS_OK;
    }
    if (!is_want(result)) {
      return fail_session(transport, transport->failure == PBNS_OK
                                         ? PBNS_ERR_TRANSPORT
                                         : transport->failure);
    }
    status = continue_after_want(transport, before_progress, before_now_ms,
                                 &stagnation);
    if (status != PBNS_OK) {
      return fail_session(transport, status);
    }
  }
  return fail_session(transport, PBNS_ERR_TRANSPORT);
}

static pbns_status transport_cancel(void *context,
                                    const pbns_request_id *request_id) {
  pbns_tls_transport *const transport = context;
  if (transport == NULL || request_id == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status cancel_status =
      transport->lower.ops->cancel(transport->lower.context, request_id);
  const pbns_status close_status = reset_session(transport, PBNS_OK);
  return cancel_status != PBNS_OK ? cancel_status : close_status;
}

static pbns_status transport_limits(void *context, pbns_frame_limits *limits) {
  pbns_tls_transport *const transport = context;
  if (transport == NULL || limits == NULL ||
      transport->state != PBNS_TLS_STATE_READY) {
    return PBNS_ERR_STATE;
  }
  return transport->lower.ops->limits(transport->lower.context, limits);
}

static const pbns_transport_ops tls_transport_ops = {
    .open = transport_open,
    .close = transport_close,
    .send = transport_send,
    .receive = transport_receive,
    .cancel = transport_cancel,
    .limits = transport_limits,
};

pbns_status pbns_tls_transport_create(pbns_transport lower,
                                      const pbns_tls_client_config *config,
                                      pbns_tls_platform platform,
                                      pbns_tls_transport **result) {
  if (result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *result = NULL;
  if (!lower_is_valid(lower) || config == NULL ||
      config->handshake_timeout_ms == 0U || !platform_is_valid(platform)) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_tls_transport *transport =
      platform.ops->allocate(platform.context, sizeof(*transport));
  if (transport == NULL) {
    return PBNS_ERR_RESOURCE;
  }
  memset(transport, 0, sizeof(*transport));
  transport->lower = lower;
  transport->platform = platform;
  transport->state = PBNS_TLS_STATE_CREATED;
  const pbns_status status = pbns_tls_certificate_policy_init(
      &transport->immutable_policy, config->expected_server_name,
      config->pinned_leaf_spki_sha256);
  if (status != PBNS_OK) {
    wipe_bytes(transport, sizeof(*transport));
    platform.ops->release(platform.context, transport, sizeof(*transport));
    return status;
  }
  transport->handshake_timeout_ms = config->handshake_timeout_ms;
  *result = transport;
  return PBNS_OK;
}

void pbns_tls_transport_destroy(pbns_tls_transport *transport) {
  if (transport == NULL) {
    return;
  }
  pbns_tls_platform platform = transport->platform;
  (void)reset_session(transport, PBNS_OK);
  pbns_tls_certificate_policy_wipe(&transport->immutable_policy);
  wipe_bytes(transport, sizeof(*transport));
  platform.ops->release(platform.context, transport, sizeof(*transport));
}

pbns_transport pbns_tls_transport_as_transport(pbns_tls_transport *transport) {
  return (pbns_transport){.ops = &tls_transport_ops, .context = transport};
}
