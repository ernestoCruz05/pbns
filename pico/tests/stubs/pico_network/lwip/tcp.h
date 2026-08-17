#ifndef PBNS_TEST_LWIP_TCP_H
#define PBNS_TEST_LWIP_TCP_H

#include <stdint.h>

#include "lwip/err.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"

#define TCP_WRITE_FLAG_COPY UINT8_C(1)

struct tcp_pcb {
  uint32_t marker;
};

typedef err_t (*tcp_recv_fn)(void *context, struct tcp_pcb *pcb,
                             struct pbuf *packet, err_t error);
typedef void (*tcp_err_fn)(void *context, err_t error);
typedef err_t (*tcp_connected_fn)(void *context, struct tcp_pcb *pcb,
                                  err_t error);

struct tcp_pcb *tcp_new_ip_type(uint8_t type);
void tcp_arg(struct tcp_pcb *pcb, void *context);
void tcp_recv(struct tcp_pcb *pcb, tcp_recv_fn callback);
void tcp_err(struct tcp_pcb *pcb, tcp_err_fn callback);
err_t tcp_connect(struct tcp_pcb *pcb, const ip_addr_t *address, uint16_t port,
                  tcp_connected_fn callback);
void tcp_abort(struct tcp_pcb *pcb);
uint16_t tcp_sndbuf(const struct tcp_pcb *pcb);
err_t tcp_write(struct tcp_pcb *pcb, const void *source, uint16_t length,
                uint8_t flags);
err_t tcp_output(struct tcp_pcb *pcb);
void tcp_recved(struct tcp_pcb *pcb, uint16_t length);

#endif
