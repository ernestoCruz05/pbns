#include "pbns_proxy/pico_tls_diagnostic_baseline.h"

#if !defined(PBNS_PICO_FIRMWARE)
#error pico_tls_diagnostic_baseline.c is firmware-only
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "lwip/dns.h"
#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "pico/cyw43_arch.h"
#include "pico/rand.h"

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

static struct tcp_pcb *
connection(const pbns_pico_tls_diagnostic_baseline *network) {
  return network->connection;
}

static pbns_status
get_asynchronous_status(const pbns_pico_tls_diagnostic_baseline *network) {
  cyw43_arch_lwip_begin();
  const pbns_status status = network->asynchronous_status;
  cyw43_arch_lwip_end();
  return status;
}

static err_t encrypted_received(void *context, struct tcp_pcb *pcb,
                                struct pbuf *packet, err_t error) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized) {
    if (packet != NULL) {
      (void)pbuf_free(packet);
    }
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  if (error != ERR_OK) {
    network->asynchronous_status = PBNS_ERR_TRANSPORT;
    if (packet != NULL) {
      (void)pbuf_free(packet);
    }
    network->connection = NULL;
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  if (packet == NULL) {
    network->remote_closed = true;
    network->asynchronous_status = PBNS_ERR_TRANSPORT;
    return ERR_OK;
  }
  const size_t available = pbns_byte_ring_capacity(&network->encrypted_rx) -
                           pbns_byte_ring_size(&network->encrypted_rx);
  if ((size_t)packet->tot_len > available) {
    return ERR_MEM;
  }

  u16_t copied = 0U;
  while (copied < packet->tot_len) {
    pbns_buffer writable = {0};
    if (pbns_byte_ring_writable(&network->encrypted_rx, &writable) != PBNS_OK ||
        writable.cap == 0U) {
      network->asynchronous_status = PBNS_ERR_STATE;
      (void)pbuf_free(packet);
      network->connection = NULL;
      tcp_abort(pcb);
      return ERR_ABRT;
    }
    const size_t remaining = (size_t)packet->tot_len - (size_t)copied;
    const size_t amount = writable.cap < remaining ? writable.cap : remaining;
    const u16_t amount_u16 = (u16_t)amount;
    if (pbuf_copy_partial(packet, writable.ptr, amount_u16, copied) !=
            amount_u16 ||
        pbns_byte_ring_commit(&network->encrypted_rx, amount) != PBNS_OK) {
      network->asynchronous_status = PBNS_ERR_STATE;
      (void)pbuf_free(packet);
      network->connection = NULL;
      tcp_abort(pcb);
      return ERR_ABRT;
    }
    copied = (u16_t)(copied + amount_u16);
  }
  (void)pbuf_free(packet);
  return ERR_OK;
}

static void tcp_failed(void *context, err_t error) {
  (void)error;
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network != NULL && network->initialized) {
    network->connection = NULL;
    network->tcp_connected = false;
    network->asynchronous_status = PBNS_ERR_TRANSPORT;
  }
}

static err_t tcp_connected(void *context, struct tcp_pcb *pcb, err_t error) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized || error != ERR_OK ||
      pcb != connection(network)) {
    if (network != NULL) {
      network->connection = NULL;
      network->asynchronous_status = PBNS_ERR_TRANSPORT;
    }
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  network->tcp_connected = true;
  return ERR_OK;
}

static pbns_status
start_tcp_connection(pbns_pico_tls_diagnostic_baseline *network,
                     const ip_addr_t *address) {
  struct tcp_pcb *const pcb = tcp_new_ip_type(IP_GET_TYPE(address));
  if (pcb == NULL) {
    return PBNS_ERR_RESOURCE;
  }
  tcp_arg(pcb, network);
  tcp_recv(pcb, encrypted_received);
  tcp_err(pcb, tcp_failed);
  network->connection = pcb;
  network->tcp_started = true;
  if (tcp_connect(pcb, address, network->port, tcp_connected) != ERR_OK) {
    network->connection = NULL;
    network->tcp_started = false;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_abort(pcb);
    return PBNS_ERR_TRANSPORT;
  }
  return PBNS_OK;
}

static void dns_result(const char *hostname, const ip_addr_t *address,
                       void *context) {
  (void)hostname;
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized ||
      network->asynchronous_status != PBNS_OK) {
    return;
  }
  if (address == NULL) {
    network->asynchronous_status = PBNS_ERR_TRANSPORT;
    return;
  }
  ip_addr_copy(network->resolved_address, *address);
  network->dns_ready = true;
}

static pbns_status encrypted_read(void *context, pbns_buffer destination,
                                  size_t *received) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  if (network == NULL || !network->initialized || destination.len != 0U ||
      destination.ptr == NULL || destination.cap == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  cyw43_arch_lwip_begin();
  pbns_view readable = {0};
  pbns_status status =
      pbns_byte_ring_readable(&network->encrypted_rx, &readable);
  if (status == PBNS_OK && readable.len > 0U) {
    const size_t amount =
        readable.len < destination.cap ? readable.len : destination.cap;
    memcpy(destination.ptr, readable.ptr, amount);
    status = pbns_byte_ring_consume(&network->encrypted_rx, amount);
    if (status == PBNS_OK) {
      struct tcp_pcb *const pcb = connection(network);
      if (pcb == NULL || amount > UINT16_MAX) {
        status = PBNS_ERR_TRANSPORT;
      } else {
        tcp_recved(pcb, (u16_t)amount);
        *received = amount;
      }
    }
  } else if (status == PBNS_OK && network->remote_closed) {
    status = PBNS_ERR_TRANSPORT;
  } else if (status == PBNS_OK) {
    status = PBNS_ERR_WOULD_BLOCK;
  }
  cyw43_arch_lwip_end();
  return status;
}

static pbns_status encrypted_write(void *context, pbns_view source,
                                   size_t *written) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (network == NULL || !network->initialized || source.ptr == NULL ||
      source.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  cyw43_arch_lwip_begin();
  struct tcp_pcb *const pcb = connection(network);
  if (!network->tcp_connected || pcb == NULL) {
    cyw43_arch_lwip_end();
    return PBNS_ERR_WOULD_BLOCK;
  }
  const size_t send_capacity = (size_t)tcp_sndbuf(pcb);
  size_t amount = source.len < send_capacity ? source.len : send_capacity;
  if (amount > UINT16_MAX) {
    amount = UINT16_MAX;
  }
  if (amount == 0U) {
    cyw43_arch_lwip_end();
    return PBNS_ERR_WOULD_BLOCK;
  }
  const err_t write_status =
      tcp_write(pcb, source.ptr, (u16_t)amount, TCP_WRITE_FLAG_COPY);
  if (write_status == ERR_MEM) {
    cyw43_arch_lwip_end();
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (write_status != ERR_OK) {
    network->asynchronous_status = PBNS_ERR_TRANSPORT;
    cyw43_arch_lwip_end();
    return PBNS_ERR_TRANSPORT;
  }
  *written = amount;
  if (tcp_output(pcb) != ERR_OK) {
    network->asynchronous_status = PBNS_ERR_TRANSPORT;
  }
  cyw43_arch_lwip_end();
  return PBNS_OK;
}

static pbns_status pico_wifi_start(void *context) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized) {
    return PBNS_ERR_STATE;
  }
  cyw43_arch_lwip_begin();
  network->asynchronous_status = PBNS_OK;
  network->dns_started = false;
  network->dns_ready = false;
  network->tcp_started = false;
  network->tcp_connected = false;
  network->remote_closed = false;
  pbns_byte_ring_reset(&network->encrypted_rx);
  const int status = cyw43_arch_wifi_connect_async(network->ssid, network->psk,
                                                   CYW43_AUTH_WPA2_AES_PSK);
  cyw43_arch_lwip_end();
  return status == 0 ? PBNS_OK : PBNS_ERR_TRANSPORT;
}

static pbns_status pico_wifi_poll(void *context) {
  const pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized) {
    return PBNS_ERR_STATE;
  }
  cyw43_arch_lwip_begin();
  const int status = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);
  cyw43_arch_lwip_end();
  switch (status) {
  case CYW43_LINK_UP:
    return PBNS_OK;
  case CYW43_LINK_DOWN:
  case CYW43_LINK_JOIN:
  case CYW43_LINK_NOIP:
    return PBNS_ERR_WOULD_BLOCK;
  case CYW43_LINK_BADAUTH:
    return PBNS_ERR_AUTHENTICATION;
  case CYW43_LINK_FAIL:
  case CYW43_LINK_NONET:
  default:
    return PBNS_ERR_TRANSPORT;
  }
}

static pbns_status pico_tcp_poll(void *context) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized) {
    return PBNS_ERR_STATE;
  }
  const pbns_status pending_status = get_asynchronous_status(network);
  if (pending_status != PBNS_OK) {
    return pending_status;
  }
  cyw43_arch_lwip_begin();
  if (!network->dns_started) {
    network->dns_started = true;
    ip_addr_t address = {0};
    const err_t dns_status =
        dns_gethostbyname(network->hostname, &address, dns_result, network);
    if (dns_status == ERR_OK) {
      ip_addr_copy(network->resolved_address, address);
      network->dns_ready = true;
    } else if (dns_status != ERR_INPROGRESS) {
      network->asynchronous_status = PBNS_ERR_TRANSPORT;
    }
  }
  if (network->dns_ready && !network->tcp_started &&
      network->asynchronous_status == PBNS_OK) {
    network->asynchronous_status =
        start_tcp_connection(network, &network->resolved_address);
  }
  const bool connected = network->tcp_connected;
  const pbns_status status = network->asynchronous_status;
  cyw43_arch_lwip_end();
  if (status != PBNS_OK) {
    return status;
  }
  return connected ? PBNS_OK : PBNS_ERR_WOULD_BLOCK;
}

static pbns_status pico_tls_session_poll(void *context) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized) {
    return PBNS_ERR_STATE;
  }
  const pbns_status pending_status = get_asynchronous_status(network);
  if (pending_status != PBNS_OK) {
    return pending_status;
  }
  cyw43_arch_lwip_begin();
  const bool tcp_is_ready =
      network->tcp_connected && connection(network) != NULL;
  cyw43_arch_lwip_end();
  if (!tcp_is_ready) {
    return PBNS_ERR_WOULD_BLOCK;
  }
  if (!network->tls_initialized) {
    const pbns_pump_endpoint encrypted = {
        .read = encrypted_read,
        .write = encrypted_write,
        .context = network,
    };
    const pbns_status status = pbns_tls_client_init(
        &network->tls,
        (pbns_view){(const uint8_t *)network->hostname,
                    strlen(network->hostname)},
        (pbns_view){network->expected_spki, sizeof(network->expected_spki)},
        encrypted);
    if (status != PBNS_OK) {
      return status;
    }
    network->tls_initialized = true;
  }
  return pbns_tls_client_step(&network->tls);
}

static void pico_close(void *context) {
  pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized) {
    return;
  }
  if (network->tls_initialized) {
    pbns_tls_client_free(&network->tls);
    network->tls_initialized = false;
  }
  cyw43_arch_lwip_begin();
  if (network->connection != NULL) {
    struct tcp_pcb *const pcb = connection(network);
    network->connection = NULL;
    tcp_arg(pcb, NULL);
    tcp_recv(pcb, NULL);
    tcp_err(pcb, NULL);
    tcp_abort(pcb);
  }
  network->dns_started = false;
  network->dns_ready = false;
  network->tcp_started = false;
  network->tcp_connected = false;
  network->remote_closed = false;
  network->asynchronous_status = PBNS_OK;
  pbns_byte_ring_reset(&network->encrypted_rx);
  (void)cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
  cyw43_arch_lwip_end();
}

static pbns_status pico_random_u32(void *context, uint32_t *value) {
  const pbns_pico_tls_diagnostic_baseline *const network = context;
  if (network == NULL || !network->initialized || value == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *value = get_rand_32();
  return PBNS_OK;
}

pbns_status pbns_pico_tls_diagnostic_baseline_init(
    pbns_pico_tls_diagnostic_baseline *network,
    const pbns_credentials *credentials) {
  if (network != NULL) {
    *network = (pbns_pico_tls_diagnostic_baseline){0};
  }
  if (network == NULL || credentials == NULL || credentials->ssid_len == 0U ||
      credentials->ssid_len > PBNS_CREDENTIALS_SSID_MAX ||
      credentials->psk_len == 0U ||
      credentials->psk_len > PBNS_CREDENTIALS_PSK_MAX ||
      credentials->hostname_len == 0U ||
      credentials->hostname_len > PBNS_CREDENTIALS_HOSTNAME_MAX ||
      credentials->port == 0U ||
      memchr(credentials->ssid, 0, credentials->ssid_len) != NULL ||
      memchr(credentials->psk, 0, credentials->psk_len) != NULL ||
      memchr(credentials->hostname, 0, credentials->hostname_len) != NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(network->ssid, credentials->ssid, credentials->ssid_len);
  memcpy(network->psk, credentials->psk, credentials->psk_len);
  memcpy(network->hostname, credentials->hostname, credentials->hostname_len);
  memcpy(network->expected_spki, credentials->spki_sha256,
         sizeof(network->expected_spki));
  network->port = credentials->port;
  pbns_byte_ring_init(&network->encrypted_rx,
                      (pbns_buffer){network->encrypted_rx_storage, 0U,
                                    sizeof(network->encrypted_rx_storage)});
  if (pbns_byte_ring_capacity(&network->encrypted_rx) == 0U) {
    secure_zero(network, sizeof(*network));
    return PBNS_ERR_STATE;
  }
  if (cyw43_arch_init() != 0) {
    secure_zero(network, sizeof(*network));
    return PBNS_ERR_TRANSPORT;
  }
  network->cyw43_initialized = true;
  network->asynchronous_status = PBNS_OK;
  network->initialized = true;
  cyw43_arch_lwip_begin();
  cyw43_arch_enable_sta_mode();
  cyw43_arch_lwip_end();
  return PBNS_OK;
}

void pbns_pico_tls_diagnostic_baseline_deinit(
    pbns_pico_tls_diagnostic_baseline *network) {
  if (network == NULL) {
    return;
  }
  if (network->initialized) {
    pico_close(network);
  }
  if (network->cyw43_initialized) {
    cyw43_arch_deinit();
  }
  secure_zero(network, sizeof(*network));
}

pbns_network_ops pbns_pico_tls_diagnostic_baseline_operations(
    pbns_pico_tls_diagnostic_baseline *network) {
  return (pbns_network_ops){
      .wifi_start = pico_wifi_start,
      .wifi_poll = pico_wifi_poll,
      .tcp_poll = pico_tcp_poll,
      .session_poll = pico_tls_session_poll,
      .close = pico_close,
      .random_u32 = pico_random_u32,
      .context = network,
  };
}

pbns_pump_endpoint pbns_pico_tls_diagnostic_baseline_plaintext_endpoint(
    pbns_pico_tls_diagnostic_baseline *network) {
  return network == NULL ? (pbns_pump_endpoint){0}
                         : pbns_tls_client_plaintext_endpoint(&network->tls);
}

void pbns_pico_tls_diagnostic_baseline_fail(
    pbns_pico_tls_diagnostic_baseline *network, pbns_status status) {
  if (network == NULL || !network->initialized || status == PBNS_OK ||
      status == PBNS_ERR_WOULD_BLOCK) {
    return;
  }
  cyw43_arch_lwip_begin();
  if (network->asynchronous_status == PBNS_OK) {
    network->asynchronous_status = status;
  }
  cyw43_arch_lwip_end();
}
