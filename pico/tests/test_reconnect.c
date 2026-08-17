#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns_proxy/network.h"

typedef struct fake_driver {
  size_t wifi_start_calls;
  size_t wifi_poll_calls;
  size_t tcp_poll_calls;
  size_t session_poll_calls;
  size_t close_calls;
  size_t random_calls;
  pbns_status wifi_start_status;
  pbns_status wifi_poll_status;
  pbns_status tcp_poll_status;
  pbns_status session_poll_status;
  pbns_status random_status;
  uint32_t random_value;
} fake_driver;

static pbns_status fake_wifi_start(void *context) {
  fake_driver *const driver = context;
  ++driver->wifi_start_calls;
  return driver->wifi_start_status;
}

static pbns_status fake_wifi_poll(void *context) {
  fake_driver *const driver = context;
  ++driver->wifi_poll_calls;
  return driver->wifi_poll_status;
}

static pbns_status fake_tcp_poll(void *context) {
  fake_driver *const driver = context;
  ++driver->tcp_poll_calls;
  return driver->tcp_poll_status;
}

static pbns_status fake_session_poll(void *context) {
  fake_driver *const driver = context;
  ++driver->session_poll_calls;
  return driver->session_poll_status;
}

static void fake_close(void *context) {
  fake_driver *const driver = context;
  ++driver->close_calls;
}

static pbns_status fake_random(void *context, uint32_t *value) {
  fake_driver *const driver = context;
  ++driver->random_calls;
  *value = driver->random_value;
  return driver->random_status;
}

static pbns_network_ops fake_ops(fake_driver *driver) {
  return (pbns_network_ops){
      .wifi_start = fake_wifi_start,
      .wifi_poll = fake_wifi_poll,
      .tcp_poll = fake_tcp_poll,
      .session_poll = fake_session_poll,
      .close = fake_close,
      .random_u32 = fake_random,
      .context = driver,
  };
}

static void test_disconnected_controller_does_not_busy_loop(void) {
  fake_driver driver = {0};
  const pbns_network_ops ops = fake_ops(&driver);
  pbns_network controller = {0};
  pbns_network_init(&controller);
  for (uint64_t now = 0U; now < UINT64_C(10000); ++now) {
    bool made_progress = true;
    assert(pbns_network_step(&controller, &ops, now, false, &made_progress) ==
           PBNS_OK);
    assert(!made_progress);
  }
  assert(controller.state == PBNS_NETWORK_DOWN);
  assert(driver.wifi_start_calls == 0U);
  assert(driver.wifi_poll_calls == 0U);
  assert(driver.tcp_poll_calls == 0U);
  assert(driver.session_poll_calls == 0U);
  assert(driver.close_calls == 0U);
  assert(driver.random_calls == 0U);
}

static void test_connection_progresses_one_stage_per_step(void) {
  fake_driver driver = {
      .wifi_start_status = PBNS_OK,
      .wifi_poll_status = PBNS_ERR_WOULD_BLOCK,
      .tcp_poll_status = PBNS_ERR_WOULD_BLOCK,
      .session_poll_status = PBNS_ERR_WOULD_BLOCK,
      .random_status = PBNS_OK,
  };
  const pbns_network_ops ops = fake_ops(&driver);
  pbns_network controller = {0};
  pbns_network_init(&controller);
  bool made_progress = false;

  assert(pbns_network_step(&controller, &ops, 0U, true, &made_progress) ==
         PBNS_OK);
  assert(made_progress && controller.state == PBNS_NETWORK_WIFI_CONNECTING);

  made_progress = true;
  assert(pbns_network_step(&controller, &ops, 1U, true, &made_progress) ==
         PBNS_OK);
  assert(!made_progress && controller.state == PBNS_NETWORK_WIFI_CONNECTING);

  driver.wifi_poll_status = PBNS_OK;
  assert(pbns_network_step(&controller, &ops, 2U, true, &made_progress) ==
         PBNS_OK);
  assert(made_progress && controller.state == PBNS_NETWORK_TCP_CONNECTING);

  driver.tcp_poll_status = PBNS_OK;
  assert(pbns_network_step(&controller, &ops, 3U, true, &made_progress) ==
         PBNS_OK);
  assert(made_progress && controller.state == PBNS_NETWORK_SESSION_CONNECTING);

  driver.session_poll_status = PBNS_OK;
  assert(pbns_network_step(&controller, &ops, 4U, true, &made_progress) ==
         PBNS_OK);
  assert(made_progress && controller.state == PBNS_NETWORK_READY);
  assert(controller.failure_count == 0U);
}

static void test_backoff_is_jittered_doubled_and_bounded(void) {
  fake_driver driver = {
      .wifi_start_status = PBNS_ERR_TRANSPORT,
      .random_status = PBNS_OK,
      .random_value = UINT32_MAX,
  };
  const pbns_network_ops ops = fake_ops(&driver);
  pbns_network controller = {0};
  pbns_network_init(&controller);
  uint64_t now = UINT64_C(1000);

  for (size_t failure = 0U; failure < 10U; ++failure) {
    bool made_progress = false;
    assert(pbns_network_step(&controller, &ops, now, true, &made_progress) ==
           PBNS_ERR_TRANSPORT);
    assert(made_progress && controller.state == PBNS_NETWORK_BACKOFF);
    const uint64_t delay = controller.retry_deadline_ms - now;
    uint64_t nominal = UINT64_C(250) << (failure < 5U ? failure : 5U);
    if (nominal > UINT64_C(8000)) {
      nominal = UINT64_C(8000);
    }
    assert(delay >= nominal);
    assert(delay <= UINT64_C(8000));

    made_progress = true;
    assert(pbns_network_step(&controller, &ops,
                             controller.retry_deadline_ms - 1U, true,
                             &made_progress) == PBNS_OK);
    assert(!made_progress && controller.state == PBNS_NETWORK_BACKOFF);

    now = controller.retry_deadline_ms;
    assert(pbns_network_step(&controller, &ops, now, true, &made_progress) ==
           PBNS_OK);
    assert(made_progress && controller.state == PBNS_NETWORK_DOWN);
  }
}

static void test_connecting_stage_times_out_without_extra_poll(void) {
  fake_driver driver = {
      .wifi_start_status = PBNS_OK,
      .wifi_poll_status = PBNS_ERR_WOULD_BLOCK,
      .random_status = PBNS_OK,
  };
  const pbns_network_ops ops = fake_ops(&driver);
  pbns_network controller = {0};
  pbns_network_init(&controller);
  bool made_progress = false;
  assert(pbns_network_step(&controller, &ops, 0U, true, &made_progress) ==
         PBNS_OK);
  assert(pbns_network_step(&controller, &ops, PBNS_NETWORK_WIFI_TIMEOUT_MS - 1U,
                           true, &made_progress) == PBNS_OK);
  assert(driver.wifi_poll_calls == 1U);
  assert(pbns_network_step(&controller, &ops, PBNS_NETWORK_WIFI_TIMEOUT_MS,
                           true, &made_progress) == PBNS_ERR_TIMEOUT);
  assert(controller.state == PBNS_NETWORK_BACKOFF);
  assert(driver.wifi_poll_calls == 1U);
}

static void test_usb_cancellation_resets_connection_and_backoff(void) {
  fake_driver driver = {
      .wifi_start_status = PBNS_OK,
      .wifi_poll_status = PBNS_ERR_TRANSPORT,
      .random_status = PBNS_OK,
  };
  const pbns_network_ops ops = fake_ops(&driver);
  pbns_network controller = {0};
  pbns_network_init(&controller);
  bool made_progress = false;
  assert(pbns_network_step(&controller, &ops, 0U, true, &made_progress) ==
         PBNS_OK);
  assert(pbns_network_step(&controller, &ops, 1U, true, &made_progress) ==
         PBNS_ERR_TRANSPORT);
  assert(controller.state == PBNS_NETWORK_BACKOFF);
  assert(controller.failure_count == 1U);

  assert(pbns_network_step(&controller, &ops, 2U, false, &made_progress) ==
         PBNS_OK);
  assert(made_progress);
  assert(controller.state == PBNS_NETWORK_DOWN);
  assert(controller.failure_count == 0U);
  assert(controller.retry_deadline_ms == 0U);
  assert(driver.close_calls == 1U);

  made_progress = true;
  assert(pbns_network_step(&controller, &ops, 3U, false, &made_progress) ==
         PBNS_OK);
  assert(!made_progress);
  assert(driver.close_calls == 1U);
}

static void test_entropy_failure_is_sticky(void) {
  fake_driver driver = {
      .wifi_start_status = PBNS_ERR_TRANSPORT,
      .random_status = PBNS_ERR_ENTROPY,
  };
  const pbns_network_ops ops = fake_ops(&driver);
  pbns_network controller = {0};
  pbns_network_init(&controller);
  bool made_progress = false;
  assert(pbns_network_step(&controller, &ops, 0U, true, &made_progress) ==
         PBNS_ERR_ENTROPY);
  assert(controller.state == PBNS_NETWORK_DOWN);
  assert(controller.failure == PBNS_ERR_ENTROPY);

  assert(pbns_network_step(&controller, &ops, 1U, true, &made_progress) ==
         PBNS_ERR_ENTROPY);
  assert(driver.wifi_start_calls == 1U);
  assert(driver.random_calls == 1U);
}

int main(void) {
  test_disconnected_controller_does_not_busy_loop();
  test_connection_progresses_one_stage_per_step();
  test_backoff_is_jittered_doubled_and_bounded();
  test_connecting_stage_times_out_without_extra_poll();
  test_usb_cancellation_resets_connection_and_backoff();
  test_entropy_failure_is_sticky();
  return 0;
}
