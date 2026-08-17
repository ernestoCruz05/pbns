#include "pbns/tls_handshake_observer.h"

#include <string.h>

#include "pbns/tls_policy.h"

#if PBNS_TLS_OBSERVER_ACCEPTED_CERTIFICATE_COUNT != 1U
#error "The bounded TLS observer only implements one leaf certificate"
#endif

#define PBNS_TLS_RECORD_HANDSHAKE ((uint8_t)22)
#define PBNS_TLS_HANDSHAKE_CERTIFICATE ((uint8_t)11)
#define PBNS_TLS_PLAINTEXT_MAX 16384U

static uint32_t read_u24(const uint8_t input[3]) {
  return ((uint32_t)input[0] << 16U) | ((uint32_t)input[1] << 8U) |
         (uint32_t)input[2];
}

static pbns_status fail(pbns_tls_handshake_observer *observer) {
  observer->failed = true;
  return PBNS_ERR_AUTHENTICATION;
}

void pbns_tls_handshake_observer_init(pbns_tls_handshake_observer *observer) {
  if (observer != NULL) {
    memset(observer, 0, sizeof(*observer));
  }
}

static pbns_status begin_record(pbns_tls_handshake_observer *observer) {
  if (observer->record_header[0] != PBNS_TLS_RECORD_HANDSHAKE ||
      observer->record_header[1] != (uint8_t)3 ||
      observer->record_header[2] != (uint8_t)3) {
    return fail(observer);
  }
  observer->record_remaining =
      ((size_t)observer->record_header[3] << 8U) | observer->record_header[4];
  observer->record_header_used = 0U;
  if (observer->record_remaining == 0U ||
      observer->record_remaining > PBNS_TLS_PLAINTEXT_MAX) {
    return fail(observer);
  }
  return PBNS_OK;
}

static pbns_status begin_handshake(pbns_tls_handshake_observer *observer) {
  observer->handshake_length = read_u24(observer->handshake_header + 1U);
  observer->handshake_remaining = observer->handshake_length;
  observer->handshake_header_used = 0U;
  observer->certificate_active =
      observer->handshake_header[0] == PBNS_TLS_HANDSHAKE_CERTIFICATE;
  if (!observer->certificate_active) {
    if (observer->handshake_length == 0U) {
      observer->handshake_header_used = 0U;
    }
    return PBNS_OK;
  }
  if (observer->handshake_length < 6U) {
    return fail(observer);
  }
  observer->certificate_list_length_used = 0U;
  observer->certificate_entry_length_used = 0U;
  observer->certificate_body_used = 0U;
  observer->certificate_list_length_value = 0U;
  observer->certificate_entry_length_value = 0U;
  return PBNS_OK;
}

static pbns_status
observe_certificate_body(pbns_tls_handshake_observer *observer, uint8_t byte) {
  const size_t body_offset = observer->certificate_body_used;
  if (body_offset < sizeof(observer->certificate_list_length)) {
    observer
        ->certificate_list_length[observer->certificate_list_length_used++] =
        byte;
    if (observer->certificate_list_length_used ==
        sizeof(observer->certificate_list_length)) {
      observer->certificate_list_length_value =
          read_u24(observer->certificate_list_length);
      if (observer->certificate_list_length_value < 3U ||
          observer->handshake_length !=
              observer->certificate_list_length_value + 3U) {
        return fail(observer);
      }
    }
  } else if (body_offset < sizeof(observer->certificate_list_length) +
                               sizeof(observer->certificate_entry_length)) {
    observer
        ->certificate_entry_length[observer->certificate_entry_length_used++] =
        byte;
    if (observer->certificate_entry_length_used ==
        sizeof(observer->certificate_entry_length)) {
      observer->certificate_entry_length_value =
          read_u24(observer->certificate_entry_length);
      if (observer->certificate_entry_length_value == 0U ||
          observer->certificate_entry_length_value >
              PBNS_TLS_CERTIFICATE_DER_MAX ||
          observer->certificate_entry_length_value !=
              observer->certificate_list_length_value - 3U) {
        return fail(observer);
      }
    }
  }
  ++observer->certificate_body_used;
  return PBNS_OK;
}

static pbns_status observe_handshake_byte(pbns_tls_handshake_observer *observer,
                                          uint8_t byte) {
  if (observer->handshake_remaining == 0U) {
    observer->handshake_header[observer->handshake_header_used++] = byte;
    if (observer->handshake_header_used == sizeof(observer->handshake_header)) {
      return begin_handshake(observer);
    }
    return PBNS_OK;
  }

  if (observer->certificate_active) {
    const pbns_status status = observe_certificate_body(observer, byte);
    if (status != PBNS_OK) {
      return status;
    }
  }
  if (observer->handshake_remaining == 0U) {
    return fail(observer);
  }
  --observer->handshake_remaining;
  if (observer->handshake_remaining == 0U) {
    if (observer->certificate_active) {
      if (observer->certificate_body_used != observer->handshake_length ||
          observer->certificate_entry_length_used !=
              sizeof(observer->certificate_entry_length)) {
        return fail(observer);
      }
      observer->complete = true;
      observer->certificate_active = false;
      return PBNS_OK;
    }
    observer->handshake_header_used = 0U;
  }
  return PBNS_OK;
}

pbns_status
pbns_tls_handshake_observer_observe(pbns_tls_handshake_observer *observer,
                                    pbns_view encrypted_tls_bytes) {
  if (observer == NULL ||
      (encrypted_tls_bytes.ptr == NULL && encrypted_tls_bytes.len != 0U)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (observer->failed) {
    return PBNS_ERR_AUTHENTICATION;
  }
  if (observer->complete) {
    return PBNS_OK;
  }
  for (size_t index = 0U; index < encrypted_tls_bytes.len; ++index) {
    const uint8_t byte = encrypted_tls_bytes.ptr[index];
    if (observer->record_remaining == 0U) {
      observer->record_header[observer->record_header_used++] = byte;
      if (observer->record_header_used == sizeof(observer->record_header)) {
        const pbns_status status = begin_record(observer);
        if (status != PBNS_OK) {
          return status;
        }
      }
      continue;
    }
    const pbns_status status = observe_handshake_byte(observer, byte);
    if (status != PBNS_OK) {
      return status;
    }
    --observer->record_remaining;
    if (observer->complete) {
      return PBNS_OK;
    }
    if (observer->record_remaining == 0U) {
      observer->record_header_used = 0U;
    }
  }
  return PBNS_OK;
}

bool pbns_tls_handshake_observer_complete(
    const pbns_tls_handshake_observer *observer) {
  return observer != NULL && observer->complete && !observer->failed;
}
