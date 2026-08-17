#include "pbns_proxy/provision_gate.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static uint64_t next_sample_deadline(uint64_t now_ms) {
  if (now_ms > UINT64_MAX - PBNS_PROVISION_SAMPLE_INTERVAL_MS) {
    return UINT64_MAX;
  }
  return now_ms + PBNS_PROVISION_SAMPLE_INTERVAL_MS;
}

void pbns_provision_gate_init(pbns_provision_gate *gate) {
  if (gate == NULL) {
    return;
  }
  *gate = (pbns_provision_gate){
      .state = PBNS_PROVISION_GATE_IDLE,
      .initialized = true,
  };
}

bool pbns_provision_gate_sample_due(const pbns_provision_gate *gate,
                                    uint64_t now_ms) {
  if (gate == NULL || !gate->initialized ||
      gate->state == PBNS_PROVISION_GATE_LATCHED) {
    return false;
  }
  if (!gate->has_sample || now_ms < gate->last_sample_ms) {
    return true;
  }
  return gate->last_sample_ms != UINT64_MAX && now_ms >= gate->next_sample_ms;
}

pbns_status pbns_provision_gate_observe(pbns_provision_gate *gate,
                                        uint64_t now_ms, bool pressed,
                                        bool *activated) {
  if (activated != NULL) {
    *activated = false;
  }
  if (gate == NULL || !gate->initialized || activated == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (gate->state == PBNS_PROVISION_GATE_LATCHED) {
    return PBNS_OK;
  }
  if (!pbns_provision_gate_sample_due(gate, now_ms)) {
    return PBNS_ERR_WOULD_BLOCK;
  }

  if (gate->has_sample && now_ms < gate->last_sample_ms) {
    gate->state = PBNS_PROVISION_GATE_IDLE;
    gate->press_started_ms = 0U;
  }
  gate->has_sample = true;
  gate->last_sample_ms = now_ms;
  gate->next_sample_ms = next_sample_deadline(now_ms);

  if (!pressed) {
    gate->state = PBNS_PROVISION_GATE_IDLE;
    gate->press_started_ms = 0U;
    return PBNS_OK;
  }
  if (gate->state == PBNS_PROVISION_GATE_IDLE) {
    gate->state = PBNS_PROVISION_GATE_PRESS_PENDING;
    gate->press_started_ms = now_ms;
    return PBNS_OK;
  }
  if (gate->state != PBNS_PROVISION_GATE_PRESS_PENDING) {
    return PBNS_ERR_STATE;
  }
  if (now_ms - gate->press_started_ms >= PBNS_PROVISION_HOLD_MS) {
    gate->state = PBNS_PROVISION_GATE_LATCHED;
    *activated = true;
  }
  return PBNS_OK;
}

bool pbns_provision_gate_is_latched(const pbns_provision_gate *gate) {
  return gate != NULL && gate->initialized &&
         gate->state == PBNS_PROVISION_GATE_LATCHED;
}

void pbns_provision_session_init(pbns_provision_session *session) {
  if (session == NULL) {
    return;
  }
  *session = (pbns_provision_session){
      .state = PBNS_PROVISION_SESSION_INACTIVE,
      .initialized = true,
  };
}

pbns_status pbns_provision_session_activate(pbns_provision_session *session,
                                            bool connected) {
  if (session == NULL || !session->initialized) {
    return PBNS_ERR_ARGUMENT;
  }
  session->state = connected ? PBNS_PROVISION_SESSION_WAIT_DISCONNECT
                             : PBNS_PROVISION_SESSION_WAIT_CONNECT;
  return PBNS_OK;
}

pbns_status pbns_provision_session_observe(pbns_provision_session *session,
                                           bool connected, bool *opened) {
  if (opened != NULL) {
    *opened = false;
  }
  if (session == NULL || !session->initialized || opened == NULL) {
    return PBNS_ERR_ARGUMENT;
  }

  switch (session->state) {
  case PBNS_PROVISION_SESSION_INACTIVE:
    return PBNS_ERR_STATE;
  case PBNS_PROVISION_SESSION_WAIT_DISCONNECT:
    if (!connected) {
      session->state = PBNS_PROVISION_SESSION_WAIT_CONNECT;
    }
    return PBNS_OK;
  case PBNS_PROVISION_SESSION_WAIT_CONNECT:
    if (connected) {
      session->state = PBNS_PROVISION_SESSION_READY;
      *opened = true;
    }
    return PBNS_OK;
  case PBNS_PROVISION_SESSION_READY:
    if (!connected) {
      session->state = PBNS_PROVISION_SESSION_WAIT_CONNECT;
    }
    return PBNS_OK;
  default:
    return PBNS_ERR_STATE;
  }
}

bool pbns_provision_session_is_ready(const pbns_provision_session *session) {
  return session != NULL && session->initialized &&
         session->state == PBNS_PROVISION_SESSION_READY;
}
