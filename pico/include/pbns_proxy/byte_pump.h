#ifndef PBNS_PROXY_BYTE_PUMP_H
#define PBNS_PROXY_BYTE_PUMP_H

#include <stdbool.h>
#include <stddef.h>

#include "pbns/buffer.h"
#include "pbns/status.h"
#include "pbns_proxy/byte_ring.h"

#define PBNS_BYTE_PUMP_BATCH_MAX_STEPS 8U

/* PBNS_ERR_WOULD_BLOCK exige um contador a zero em ambas as operações. */
typedef pbns_status (*pbns_pump_read_fn)(void *context, pbns_buffer destination,
                                         size_t *received);
typedef pbns_status (*pbns_pump_write_fn)(void *context, pbns_view source,
                                          size_t *written);

typedef struct pbns_pump_endpoint {
  pbns_pump_read_fn read;
  pbns_pump_write_fn write;
  void *context;
} pbns_pump_endpoint;

typedef struct pbns_pump_session {
  bool connected;
  bool initialized;
} pbns_pump_session;

/* A zero minimum retains the normal step/batch behaviour.  The production
 * tunnel owns its clock and supplies force_usb_to_tls_write at its deadline. */
typedef struct pbns_byte_pump_policy {
  size_t usb_to_tls_minimum_write;
  size_t tls_to_usb_minimum_writable;
  bool force_usb_to_tls_write;
} pbns_byte_pump_policy;

typedef struct pbns_byte_pump {
  pbns_byte_ring usb_to_tls;
  pbns_byte_ring tls_to_usb;
  bool usb_source_closed;
  bool tls_source_closed;
  /* Increments after each successful nonzero USB source read or sink write. */
  size_t usb_to_tls_read_generation;
  size_t usb_to_tls_write_generation;
  bool initialized;
  bool cancelled;
  bool failed;
} pbns_byte_pump;

void pbns_pump_session_init(pbns_pump_session *session);
pbns_status pbns_pump_session_observe(pbns_pump_session *session,
                                      bool connected, bool *disconnected);

void pbns_byte_pump_init(pbns_byte_pump *pump, pbns_buffer usb_to_tls_storage,
                         pbns_buffer tls_to_usb_storage);
void pbns_byte_pump_reset(pbns_byte_pump *pump);
void pbns_byte_pump_cancel(pbns_byte_pump *pump);
bool pbns_byte_pump_is_complete(const pbns_byte_pump *pump);

/* PBNS_OK com zero bytes lidos fecha apenas a origem e deixa o anel pendente
 * escoar. */
pbns_status pbns_byte_pump_step(pbns_byte_pump *pump, pbns_pump_endpoint usb,
                                pbns_pump_endpoint tls, bool *made_progress);

/* Applies optional directional aggregation. USB-to-TLS writes wait for the
 * total ring size unless forced, closed, or full. TLS-to-USB source reads wait
 * for contiguous writable capacity unless that ring is empty. */
pbns_status pbns_byte_pump_step_with_policy(
    pbns_byte_pump *pump, pbns_pump_endpoint usb, pbns_pump_endpoint tls,
    const pbns_byte_pump_policy *policy, bool *made_progress);

/* Executa no máximo oito passos e termina ao não haver progresso, em erro ou
 * quando a transferência estiver completa. Em erro, steps inclui o passo que
 * falhou. */
pbns_status pbns_byte_pump_batch(pbns_byte_pump *pump, pbns_pump_endpoint usb,
                                 pbns_pump_endpoint tls, size_t *steps,
                                 bool *made_progress);
pbns_status pbns_byte_pump_batch_with_policy(
    pbns_byte_pump *pump, pbns_pump_endpoint usb, pbns_pump_endpoint tls,
    const pbns_byte_pump_policy *policy, size_t *steps,
    bool *made_progress);

#endif
