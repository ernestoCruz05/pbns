#ifndef PBNS_PROXY_PROVISION_GATE_H
#define PBNS_PROXY_PROVISION_GATE_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/status.h"

#define PBNS_PROVISION_SAMPLE_INTERVAL_MS UINT64_C(50)
#define PBNS_PROVISION_HOLD_MS UINT64_C(2000)

typedef enum pbns_provision_gate_state {
  PBNS_PROVISION_GATE_IDLE = 0,
  PBNS_PROVISION_GATE_PRESS_PENDING,
  PBNS_PROVISION_GATE_LATCHED
} pbns_provision_gate_state;

typedef struct pbns_provision_gate {
  pbns_provision_gate_state state;
  uint64_t press_started_ms;
  uint64_t last_sample_ms;
  uint64_t next_sample_ms;
  bool has_sample;
  bool initialized;
} pbns_provision_gate;

typedef enum pbns_provision_session_state {
  PBNS_PROVISION_SESSION_INACTIVE = 0,
  PBNS_PROVISION_SESSION_WAIT_DISCONNECT,
  PBNS_PROVISION_SESSION_WAIT_CONNECT,
  PBNS_PROVISION_SESSION_READY
} pbns_provision_session_state;

typedef struct pbns_provision_session {
  pbns_provision_session_state state;
  bool initialized;
} pbns_provision_session;

void pbns_provision_gate_init(pbns_provision_gate *gate);
bool pbns_provision_gate_sample_due(const pbns_provision_gate *gate,
                                    uint64_t now_ms);
pbns_status pbns_provision_gate_observe(pbns_provision_gate *gate,
                                        uint64_t now_ms, bool pressed,
                                        bool *activated);
bool pbns_provision_gate_is_latched(const pbns_provision_gate *gate);

void pbns_provision_session_init(pbns_provision_session *session);
pbns_status pbns_provision_session_activate(pbns_provision_session *session,
                                            bool connected);
pbns_status pbns_provision_session_observe(pbns_provision_session *session,
                                           bool connected, bool *opened);
bool pbns_provision_session_is_ready(const pbns_provision_session *session);

#endif
