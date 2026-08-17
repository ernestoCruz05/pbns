#include "pbns_proxy/network.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BACKOFF_INITIAL_MS UINT64_C(250)
#define BACKOFF_MAX_MS UINT64_C(8000)
#define BACKOFF_MAX_SHIFT 5U

static bool ops_are_valid(const pbns_network_ops *ops) {
  return ops != NULL && ops->wifi_start != NULL && ops->wifi_poll != NULL &&
         ops->tcp_poll != NULL && ops->session_poll != NULL &&
         ops->close != NULL && ops->random_u32 != NULL;
}

static void close_active_connection(pbns_network *network,
                                    const pbns_network_ops *ops) {
  if (network->connection_active) {
    ops->close(ops->context);
    network->connection_active = false;
  }
}

static uint64_t state_timeout(pbns_network_state state) {
  switch (state) {
  case PBNS_NETWORK_WIFI_CONNECTING:
    return PBNS_NETWORK_WIFI_TIMEOUT_MS;
  case PBNS_NETWORK_TCP_CONNECTING:
    return PBNS_NETWORK_TCP_TIMEOUT_MS;
  case PBNS_NETWORK_SESSION_CONNECTING:
    return PBNS_NETWORK_SESSION_TIMEOUT_MS;
  default:
    return 0U;
  }
}

static uint64_t nominal_backoff(uint32_t failure_count) {
  const uint32_t shift =
      failure_count < BACKOFF_MAX_SHIFT ? failure_count : BACKOFF_MAX_SHIFT;
  return BACKOFF_INITIAL_MS << shift;
}

static pbns_status schedule_backoff(pbns_network *network, uint64_t now_ms,
                                    const pbns_network_ops *ops,
                                    pbns_status cause, bool *made_progress) {
  close_active_connection(network, ops);
  uint32_t random_value = 0U;
  const pbns_status random_status =
      ops->random_u32(ops->context, &random_value);
  if (random_status != PBNS_OK) {
    network->state = PBNS_NETWORK_DOWN;
    network->retry_deadline_ms = 0U;
    network->state_entered_ms = now_ms;
    network->failure = random_status;
    *made_progress = true;
    return random_status;
  }

  const uint64_t nominal = nominal_backoff(network->failure_count);
  const uint64_t jitter_span = nominal / UINT64_C(4) + UINT64_C(1);
  const uint64_t jitter = (uint64_t)random_value % jitter_span;
  const uint64_t delay =
      jitter > BACKOFF_MAX_MS - nominal ? BACKOFF_MAX_MS : nominal + jitter;
  network->retry_deadline_ms =
      now_ms > UINT64_MAX - delay ? UINT64_MAX : now_ms + delay;
  if (network->failure_count < UINT32_MAX) {
    ++network->failure_count;
  }
  network->state = PBNS_NETWORK_BACKOFF;
  network->state_entered_ms = now_ms;
  *made_progress = true;
  return cause;
}

void pbns_network_init(pbns_network *network) {
  if (network == NULL) {
    return;
  }
  *network = (pbns_network){
      .state = PBNS_NETWORK_DOWN,
      .failure = PBNS_OK,
      .initialized = true,
  };
}

static pbns_status poll_connecting_stage(pbns_network *network,
                                         const pbns_network_ops *ops,
                                         pbns_network_action_fn poll,
                                         pbns_network_state next_state,
                                         bool *made_progress, uint64_t now_ms) {
  const pbns_status status = poll(ops->context);
  if (status == PBNS_ERR_WOULD_BLOCK) {
    return PBNS_OK;
  }
  if (status != PBNS_OK) {
    return schedule_backoff(network, now_ms, ops, status, made_progress);
  }
  network->state = next_state;
  network->state_entered_ms = now_ms;
  if (next_state == PBNS_NETWORK_READY) {
    network->failure_count = 0U;
    network->retry_deadline_ms = 0U;
  }
  *made_progress = true;
  return PBNS_OK;
}

pbns_status pbns_network_step(pbns_network *network,
                              const pbns_network_ops *ops, uint64_t now_ms,
                              bool usb_connected, bool *made_progress) {
  if (made_progress != NULL) {
    *made_progress = false;
  }
  if (network == NULL || !network->initialized || !ops_are_valid(ops) ||
      made_progress == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (network->failure != PBNS_OK) {
    return network->failure;
  }
  if (!usb_connected) {
    if (network->state != PBNS_NETWORK_DOWN) {
      close_active_connection(network, ops);
      network->state = PBNS_NETWORK_DOWN;
      network->failure_count = 0U;
      network->retry_deadline_ms = 0U;
      network->state_entered_ms = 0U;
      *made_progress = true;
    }
    return PBNS_OK;
  }

  const uint64_t timeout = state_timeout(network->state);
  if (timeout > 0U && now_ms >= network->state_entered_ms &&
      now_ms - network->state_entered_ms >= timeout) {
    return schedule_backoff(network, now_ms, ops, PBNS_ERR_TIMEOUT,
                            made_progress);
  }

  switch (network->state) {
  case PBNS_NETWORK_DOWN: {
    network->connection_active = true;
    const pbns_status status = ops->wifi_start(ops->context);
    if (status != PBNS_OK) {
      return schedule_backoff(network, now_ms, ops, status, made_progress);
    }
    network->state = PBNS_NETWORK_WIFI_CONNECTING;
    network->state_entered_ms = now_ms;
    *made_progress = true;
    return PBNS_OK;
  }
  case PBNS_NETWORK_WIFI_CONNECTING:
    return poll_connecting_stage(network, ops, ops->wifi_poll,
                                 PBNS_NETWORK_TCP_CONNECTING, made_progress,
                                 now_ms);
  case PBNS_NETWORK_TCP_CONNECTING:
    return poll_connecting_stage(network, ops, ops->tcp_poll,
                                 PBNS_NETWORK_SESSION_CONNECTING, made_progress,
                                 now_ms);
  case PBNS_NETWORK_SESSION_CONNECTING:
    return poll_connecting_stage(network, ops, ops->session_poll,
                                 PBNS_NETWORK_READY, made_progress, now_ms);
  case PBNS_NETWORK_READY: {
    const pbns_status status = ops->session_poll(ops->context);
    if (status == PBNS_OK || status == PBNS_ERR_WOULD_BLOCK) {
      return PBNS_OK;
    }
    return schedule_backoff(network, now_ms, ops, status, made_progress);
  }
  case PBNS_NETWORK_BACKOFF:
    if (now_ms >= network->retry_deadline_ms) {
      network->state = PBNS_NETWORK_DOWN;
      network->state_entered_ms = now_ms;
      *made_progress = true;
    }
    return PBNS_OK;
  default:
    close_active_connection(network, ops);
    network->failure = PBNS_ERR_STATE;
    return network->failure;
  }
}
