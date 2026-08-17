#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns_proxy/provision_gate.h"

static void test_null_and_uninitialized_arguments_fail_closed(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_session session = {0};
  bool changed = true;

  pbns_provision_gate_init(NULL);
  assert(!pbns_provision_gate_sample_due(NULL, 0U));
  assert(!pbns_provision_gate_is_latched(NULL));
  assert(pbns_provision_gate_observe(NULL, 0U, false, &changed) ==
         PBNS_ERR_ARGUMENT);
  assert(!changed);
  changed = true;
  assert(pbns_provision_gate_observe(&gate, 0U, false, &changed) ==
         PBNS_ERR_ARGUMENT);
  assert(!changed);
  assert(pbns_provision_gate_observe(&gate, 0U, false, NULL) ==
         PBNS_ERR_ARGUMENT);

  pbns_provision_session_init(NULL);
  assert(!pbns_provision_session_is_ready(NULL));
  assert(pbns_provision_session_activate(NULL, false) == PBNS_ERR_ARGUMENT);
  assert(pbns_provision_session_activate(&session, false) == PBNS_ERR_ARGUMENT);
  changed = true;
  assert(pbns_provision_session_observe(NULL, false, &changed) ==
         PBNS_ERR_ARGUMENT);
  assert(!changed);
  changed = true;
  assert(pbns_provision_session_observe(&session, false, &changed) ==
         PBNS_ERR_ARGUMENT);
  assert(!changed);
  assert(pbns_provision_session_observe(&session, false, NULL) ==
         PBNS_ERR_ARGUMENT);

  pbns_provision_session_init(&session);
  changed = true;
  assert(pbns_provision_session_observe(&session, false, &changed) ==
         PBNS_ERR_STATE);
  assert(!changed);
}

static void test_no_press_never_activates(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = true;

  for (uint64_t now = 0U; now <= UINT64_C(5000);
       now += PBNS_PROVISION_SAMPLE_INTERVAL_MS) {
    assert(pbns_provision_gate_observe(&gate, now, false, &activated) ==
           PBNS_OK);
    assert(!activated);
    assert(!pbns_provision_gate_is_latched(&gate));
  }
}

static void test_sampling_deadline_rejects_early_observations(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = true;

  assert(pbns_provision_gate_sample_due(&gate, 0U));
  assert(pbns_provision_gate_observe(&gate, 0U, true, &activated) == PBNS_OK);
  assert(!activated);
  assert(!pbns_provision_gate_sample_due(&gate, 49U));

  activated = true;
  assert(pbns_provision_gate_observe(&gate, 49U, false, &activated) ==
         PBNS_ERR_WOULD_BLOCK);
  assert(!activated);
  assert(gate.state == PBNS_PROVISION_GATE_PRESS_PENDING);
  assert(pbns_provision_gate_sample_due(&gate, 50U));
}

static void test_continuous_press_latches_at_two_seconds(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = true;

  assert(pbns_provision_gate_observe(&gate, 0U, true, &activated) == PBNS_OK);
  assert(!activated);
  for (uint64_t now = PBNS_PROVISION_SAMPLE_INTERVAL_MS;
       now < PBNS_PROVISION_HOLD_MS; now += PBNS_PROVISION_SAMPLE_INTERVAL_MS) {
    assert(pbns_provision_gate_sample_due(&gate, now));
    assert(pbns_provision_gate_observe(&gate, now, true, &activated) ==
           PBNS_OK);
    assert(!activated);
  }

  assert(pbns_provision_gate_observe(&gate, PBNS_PROVISION_HOLD_MS, true,
                                     &activated) == PBNS_OK);
  assert(activated);
  assert(pbns_provision_gate_is_latched(&gate));
  assert(!pbns_provision_gate_sample_due(
      &gate, PBNS_PROVISION_HOLD_MS + PBNS_PROVISION_SAMPLE_INTERVAL_MS));

  activated = true;
  assert(pbns_provision_gate_observe(
             &gate, PBNS_PROVISION_HOLD_MS + PBNS_PROVISION_SAMPLE_INTERVAL_MS,
             false, &activated) == PBNS_OK);
  assert(!activated);
  assert(pbns_provision_gate_is_latched(&gate));
}

static void test_press_shorter_than_threshold_does_not_latch(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = false;

  assert(pbns_provision_gate_observe(&gate, 0U, true, &activated) == PBNS_OK);
  assert(pbns_provision_gate_observe(&gate, PBNS_PROVISION_HOLD_MS - 1U, true,
                                     &activated) == PBNS_OK);
  assert(!activated);
  assert(!pbns_provision_gate_is_latched(&gate));
  assert(pbns_provision_gate_observe(&gate,
                                     PBNS_PROVISION_HOLD_MS - 1U +
                                         PBNS_PROVISION_SAMPLE_INTERVAL_MS,
                                     true, &activated) == PBNS_OK);
  assert(activated);
}

static void test_release_restarts_the_hold_interval(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = false;

  assert(pbns_provision_gate_observe(&gate, 100U, true, &activated) == PBNS_OK);
  assert(pbns_provision_gate_observe(&gate, 1100U, false, &activated) ==
         PBNS_OK);
  assert(pbns_provision_gate_observe(&gate, 1150U, true, &activated) ==
         PBNS_OK);
  assert(pbns_provision_gate_observe(&gate, 3100U, true, &activated) ==
         PBNS_OK);
  assert(!activated);
  assert(pbns_provision_gate_observe(&gate, 3150U, true, &activated) ==
         PBNS_OK);
  assert(activated);
}

static void test_clock_regression_restarts_the_hold_interval(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = false;

  assert(pbns_provision_gate_observe(&gate, 1000U, true, &activated) ==
         PBNS_OK);
  assert(pbns_provision_gate_observe(&gate, 1050U, true, &activated) ==
         PBNS_OK);
  assert(pbns_provision_gate_sample_due(&gate, 100U));
  assert(pbns_provision_gate_observe(&gate, 100U, true, &activated) == PBNS_OK);
  assert(pbns_provision_gate_observe(&gate, 2050U, true, &activated) ==
         PBNS_OK);
  assert(!activated);
  assert(pbns_provision_gate_observe(&gate, 2100U, true, &activated) ==
         PBNS_OK);
  assert(activated);
}

static void test_deadline_saturates_at_uint64_max(void) {
  pbns_provision_gate gate = {0};
  pbns_provision_gate_init(&gate);
  bool activated = false;

  assert(pbns_provision_gate_observe(
             &gate, UINT64_MAX - PBNS_PROVISION_SAMPLE_INTERVAL_MS + 1U, false,
             &activated) == PBNS_OK);
  assert(gate.next_sample_ms == UINT64_MAX);
  assert(!pbns_provision_gate_sample_due(&gate, UINT64_MAX - 1U));
  assert(pbns_provision_gate_sample_due(&gate, UINT64_MAX));
  assert(pbns_provision_gate_observe(&gate, UINT64_MAX, false, &activated) ==
         PBNS_OK);
  assert(!pbns_provision_gate_sample_due(&gate, UINT64_MAX));
}

static void test_activation_while_disconnected_accepts_next_connection(void) {
  pbns_provision_session session = {0};
  pbns_provision_session_init(&session);
  bool opened = true;

  assert(pbns_provision_session_activate(&session, false) == PBNS_OK);
  assert(pbns_provision_session_observe(&session, false, &opened) == PBNS_OK);
  assert(!opened);
  assert(!pbns_provision_session_is_ready(&session));
  assert(pbns_provision_session_observe(&session, true, &opened) == PBNS_OK);
  assert(opened);
  assert(pbns_provision_session_is_ready(&session));

  opened = true;
  assert(pbns_provision_session_observe(&session, true, &opened) == PBNS_OK);
  assert(!opened);
  assert(pbns_provision_session_is_ready(&session));
}

static void test_activation_while_connected_requires_disconnect(void) {
  pbns_provision_session session = {0};
  pbns_provision_session_init(&session);
  bool opened = true;

  assert(pbns_provision_session_activate(&session, true) == PBNS_OK);
  assert(pbns_provision_session_observe(&session, true, &opened) == PBNS_OK);
  assert(!opened);
  assert(!pbns_provision_session_is_ready(&session));
  assert(pbns_provision_session_observe(&session, false, &opened) == PBNS_OK);
  assert(!opened);
  assert(!pbns_provision_session_is_ready(&session));
  assert(pbns_provision_session_observe(&session, true, &opened) == PBNS_OK);
  assert(opened);
  assert(pbns_provision_session_is_ready(&session));
}

static void
test_ready_session_requires_fresh_connection_after_disconnect(void) {
  pbns_provision_session session = {0};
  pbns_provision_session_init(&session);
  bool opened = false;

  assert(pbns_provision_session_activate(&session, false) == PBNS_OK);
  assert(pbns_provision_session_observe(&session, true, &opened) == PBNS_OK);
  assert(opened);
  assert(pbns_provision_session_observe(&session, false, &opened) == PBNS_OK);
  assert(!opened);
  assert(!pbns_provision_session_is_ready(&session));
  assert(pbns_provision_session_observe(&session, true, &opened) == PBNS_OK);
  assert(opened);
  assert(pbns_provision_session_is_ready(&session));
}

int main(void) {
  test_null_and_uninitialized_arguments_fail_closed();
  test_no_press_never_activates();
  test_sampling_deadline_rejects_early_observations();
  test_continuous_press_latches_at_two_seconds();
  test_press_shorter_than_threshold_does_not_latch();
  test_release_restarts_the_hold_interval();
  test_clock_regression_restarts_the_hold_interval();
  test_deadline_saturates_at_uint64_max();
  test_activation_while_disconnected_accepts_next_connection();
  test_activation_while_connected_requires_disconnect();
  test_ready_session_requires_fresh_connection_after_disconnect();
  return 0;
}
