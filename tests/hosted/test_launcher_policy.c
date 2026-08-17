#include "pbns/launcher.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TEST_STATUS_LOAD UINT64_C(0x8000000000000001)
#define TEST_STATUS_START UINT64_C(0x8000000000000002)
#define TEST_STATUS_RECOVERY UINT64_C(0x8000000000000003)
#define TEST_STATUS_UNEXPECTED UINT64_C(0x8000000000000004)

struct fake_launcher {
  pbns_status read_result;
  pbns_status normal_load_result;
  pbns_status normal_start_result;
  pbns_status recovery_load_result;
  pbns_status recovery_start_result;
  uint64_t read_platform_status;
  uint64_t normal_load_status;
  uint64_t normal_start_status;
  uint64_t recovery_load_status;
  uint64_t recovery_start_status;
  bool normal_returned;
  bool recovery_returned;
  bool null_normal_handle;
  bool null_recovery_handle;
  bool normal_error_handle;
  bool recovery_error_handle;
  pbns_launcher_config config;
  char calls[32];
  size_t call_count;
  size_t normal_unloads;
  size_t recovery_unloads;
  size_t failure_records;
  pbns_launcher_stage recorded_stage;
  uint64_t recorded_status;
};

static void record_call(struct fake_launcher *fake, char call) {
  assert(fake != NULL);
  assert(fake->call_count < sizeof(fake->calls));
  fake->calls[fake->call_count] = call;
  fake->call_count += 1U;
}

static pbns_status fake_read_config(void *context, pbns_launcher_config *config,
                                    uint64_t *platform_status) {
  struct fake_launcher *fake = context;
  record_call(fake, 'R');
  assert(config != NULL);
  assert(platform_status != NULL);
  *platform_status = fake->read_platform_status;
  if (fake->read_result == PBNS_OK) {
    *config = fake->config;
  }
  return fake->read_result;
}

static pbns_status fake_load(void *context, pbns_launcher_target target,
                             const pbns_launcher_config *config, void **image,
                             uint64_t *platform_status) {
  struct fake_launcher *fake = context;
  assert(config != NULL);
  assert(image != NULL);
  assert(platform_status != NULL);
  if (target == PBNS_LAUNCHER_TARGET_NORMAL) {
    record_call(fake, 'L');
    *platform_status = fake->normal_load_status;
    *image =
        ((fake->normal_load_result == PBNS_OK) && !fake->null_normal_handle) ||
                fake->normal_error_handle
            ? (void *)(uintptr_t)1U
            : NULL;
    return fake->normal_load_result;
  }
  assert(target == PBNS_LAUNCHER_TARGET_RECOVERY);
  record_call(fake, 'l');
  *platform_status = fake->recovery_load_status;
  *image = ((fake->recovery_load_result == PBNS_OK) &&
            !fake->null_recovery_handle) ||
                   fake->recovery_error_handle
               ? (void *)(uintptr_t)2U
               : NULL;
  return fake->recovery_load_result;
}

static pbns_status fake_start(void *context, pbns_launcher_target target,
                              void *image, bool *returned,
                              uint64_t *platform_status) {
  struct fake_launcher *fake = context;
  assert(image != NULL);
  assert(returned != NULL);
  assert(platform_status != NULL);
  if (target == PBNS_LAUNCHER_TARGET_NORMAL) {
    record_call(fake, 'S');
    *returned = fake->normal_returned;
    *platform_status = fake->normal_start_status;
    return fake->normal_start_result;
  }
  assert(target == PBNS_LAUNCHER_TARGET_RECOVERY);
  record_call(fake, 's');
  *returned = fake->recovery_returned;
  *platform_status = fake->recovery_start_status;
  return fake->recovery_start_result;
}

static void fake_record_failure(void *context, pbns_launcher_stage stage,
                                uint64_t platform_status) {
  struct fake_launcher *fake = context;
  record_call(fake, 'F');
  fake->failure_records += 1U;
  fake->recorded_stage = stage;
  fake->recorded_status = platform_status;
}

static void fake_unload(void *context, pbns_launcher_target target,
                        void *image) {
  struct fake_launcher *fake = context;
  assert(image != NULL);
  record_call(fake, target == PBNS_LAUNCHER_TARGET_NORMAL ? 'U' : 'u');
  if (target == PBNS_LAUNCHER_TARGET_NORMAL) {
    fake->normal_unloads += 1U;
  } else {
    fake->recovery_unloads += 1U;
  }
}

static const pbns_launcher_ops fake_ops = {
    .read_config = fake_read_config,
    .load = fake_load,
    .start = fake_start,
    .record_failure = fake_record_failure,
    .unload = fake_unload,
};

static struct fake_launcher default_fake(void) {
  static const uint8_t recovery_path[] = {0x01U, 0x02U, 0x03U, 0x04U};
  struct fake_launcher fake = {
      .read_result = PBNS_OK,
      .normal_load_result = PBNS_OK,
      .normal_start_result = PBNS_OK,
      .recovery_load_result = PBNS_OK,
      .recovery_start_result = PBNS_OK,
      .normal_returned = false,
      .recovery_returned = false,
      .config =
          {
              .normal_boot_option = UINT16_C(7),
              .recovery_device_path = {recovery_path, sizeof(recovery_path)},
              .self_reference = false,
          },
  };
  return fake;
}

static pbns_status run_fake(struct fake_launcher *fake,
                            pbns_launcher_result *result) {
  return pbns_launcher_run(&fake_ops, fake, TEST_STATUS_UNEXPECTED, result);
}

static void test_normal_transfer_is_invisible(void) {
  struct fake_launcher fake = default_fake();
  pbns_launcher_result result = {0};

  assert(run_fake(&fake, &result) == PBNS_OK);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_NORMAL_TRANSFERRED);
  assert(fake.call_count == 3U);
  assert(memcmp(fake.calls, "RLS", 3U) == 0);
  assert(fake.failure_records == 0U);
  assert(fake.normal_unloads == 0U);
  assert(fake.recovery_unloads == 0U);
}

static void test_configuration_failures_stop_before_loading(void) {
  struct fake_launcher malformed = default_fake();
  pbns_launcher_result result = {0};
  malformed.read_result = PBNS_ERR_FORMAT;
  malformed.read_platform_status = TEST_STATUS_LOAD;

  assert(run_fake(&malformed, &result) == PBNS_ERR_FORMAT);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_FAILED);
  assert(result.stage == PBNS_LAUNCHER_STAGE_READ_CONFIG);
  assert(malformed.call_count == 1U);

  struct fake_launcher recursive = default_fake();
  recursive.config.self_reference = true;
  assert(run_fake(&recursive, &result) == PBNS_ERR_STATE);
  assert(result.stage == PBNS_LAUNCHER_STAGE_VALIDATE_CONFIG);
  assert(recursive.call_count == 1U);

  struct fake_launcher missing_path = default_fake();
  missing_path.config.recovery_device_path = (pbns_view){NULL, 0U};
  assert(run_fake(&missing_path, &result) == PBNS_ERR_FORMAT);
  assert(result.stage == PBNS_LAUNCHER_STAGE_VALIDATE_CONFIG);
  assert(missing_path.call_count == 1U);
}

static void test_normal_load_failure_starts_recovery(void) {
  struct fake_launcher fake = default_fake();
  pbns_launcher_result result = {0};
  fake.normal_load_result = PBNS_ERR_IO;
  fake.normal_load_status = TEST_STATUS_LOAD;

  assert(run_fake(&fake, &result) == PBNS_OK);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED);
  assert(result.original_stage == PBNS_LAUNCHER_STAGE_LOAD_NORMAL);
  assert(result.original_platform_status == TEST_STATUS_LOAD);
  assert(fake.recorded_stage == PBNS_LAUNCHER_STAGE_LOAD_NORMAL);
  assert(fake.recorded_status == TEST_STATUS_LOAD);
  assert(fake.call_count == 5U);
  assert(memcmp(fake.calls, "RLFls", 5U) == 0);
}

static void test_normal_start_error_unloads_then_recovers(void) {
  struct fake_launcher fake = default_fake();
  pbns_launcher_result result = {0};
  fake.normal_start_result = PBNS_ERR_IO;
  fake.normal_start_status = TEST_STATUS_START;
  fake.normal_returned = true;

  assert(run_fake(&fake, &result) == PBNS_OK);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED);
  assert(result.original_stage == PBNS_LAUNCHER_STAGE_START_NORMAL);
  assert(result.original_platform_status == TEST_STATUS_START);
  assert(fake.normal_unloads == 1U);
  assert(fake.call_count == 7U);
  assert(memcmp(fake.calls, "RLSUFls", 7U) == 0);
}

static void test_unexpected_success_return_uses_typed_failure(void) {
  struct fake_launcher fake = default_fake();
  pbns_launcher_result result = {0};
  fake.normal_returned = true;
  fake.normal_start_status = 0U;

  assert(run_fake(&fake, &result) == PBNS_OK);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED);
  assert(result.original_stage == PBNS_LAUNCHER_STAGE_START_NORMAL);
  assert(result.original_platform_status == TEST_STATUS_UNEXPECTED);
  assert(fake.recorded_status == TEST_STATUS_UNEXPECTED);
  assert(fake.normal_unloads == 1U);
}

static void test_recovery_failures_preserve_original_error(void) {
  struct fake_launcher missing = default_fake();
  pbns_launcher_result result = {0};
  missing.normal_load_result = PBNS_ERR_IO;
  missing.normal_load_status = TEST_STATUS_LOAD;
  missing.recovery_load_result = PBNS_ERR_IO;
  missing.recovery_load_status = TEST_STATUS_RECOVERY;

  assert(run_fake(&missing, &result) == PBNS_ERR_IO);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_FAILED);
  assert(result.original_platform_status == TEST_STATUS_LOAD);
  assert(result.recovery_platform_status == TEST_STATUS_RECOVERY);
  assert(result.stage == PBNS_LAUNCHER_STAGE_LOAD_RECOVERY);
  assert(missing.call_count == 4U);
  assert(memcmp(missing.calls, "RLFl", 4U) == 0);

  struct fake_launcher returned = default_fake();
  returned.normal_load_result = PBNS_ERR_IO;
  returned.normal_load_status = TEST_STATUS_LOAD;
  returned.recovery_returned = true;
  returned.recovery_start_status = 0U;
  assert(run_fake(&returned, &result) == PBNS_ERR_IO);
  assert(result.original_platform_status == TEST_STATUS_LOAD);
  assert(result.recovery_platform_status == TEST_STATUS_UNEXPECTED);
  assert(result.stage == PBNS_LAUNCHER_STAGE_START_RECOVERY);
  assert(returned.recovery_unloads == 1U);
  assert(memcmp(returned.calls, "RLFlsu", 6U) == 0);
}

static void test_error_handles_are_unloaded_exactly_once(void) {
  struct fake_launcher normal = default_fake();
  pbns_launcher_result result = {0};
  normal.normal_load_result = PBNS_ERR_IO;
  normal.normal_load_status = TEST_STATUS_LOAD;
  normal.normal_error_handle = true;

  assert(run_fake(&normal, &result) == PBNS_OK);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED);
  assert(normal.normal_unloads == 1U);

  struct fake_launcher recovery = default_fake();
  recovery.normal_load_result = PBNS_ERR_IO;
  recovery.normal_load_status = TEST_STATUS_LOAD;
  recovery.recovery_load_result = PBNS_ERR_IO;
  recovery.recovery_load_status = TEST_STATUS_RECOVERY;
  recovery.recovery_error_handle = true;
  assert(run_fake(&recovery, &result) == PBNS_ERR_IO);
  assert(recovery.recovery_unloads == 1U);
}

static void test_null_handles_and_resource_failures_are_bounded(void) {
  struct fake_launcher normal = default_fake();
  pbns_launcher_result result = {0};
  normal.null_normal_handle = true;
  assert(run_fake(&normal, &result) == PBNS_OK);
  assert(result.outcome == PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED);
  assert(result.original_stage == PBNS_LAUNCHER_STAGE_LOAD_NORMAL);
  assert(normal.normal_unloads == 0U);

  struct fake_launcher recovery = default_fake();
  recovery.normal_load_result = PBNS_ERR_RESOURCE;
  recovery.normal_load_status = TEST_STATUS_LOAD;
  recovery.null_recovery_handle = true;
  assert(run_fake(&recovery, &result) == PBNS_ERR_RESOURCE);
  assert(result.stage == PBNS_LAUNCHER_STAGE_LOAD_RECOVERY);
  assert(recovery.recovery_unloads == 0U);
}

static void test_argument_validation(void) {
  struct fake_launcher fake = default_fake();
  pbns_launcher_result result = {0};
  pbns_launcher_ops missing = fake_ops;
  missing.start = NULL;

  assert(pbns_launcher_run(NULL, &fake, TEST_STATUS_UNEXPECTED, &result) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_launcher_run(&fake_ops, NULL, TEST_STATUS_UNEXPECTED, &result) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_launcher_run(&fake_ops, &fake, TEST_STATUS_UNEXPECTED, NULL) ==
         PBNS_ERR_ARGUMENT);
  assert(pbns_launcher_run(&missing, &fake, TEST_STATUS_UNEXPECTED, &result) ==
         PBNS_ERR_ARGUMENT);
}

int main(void) {
  test_normal_transfer_is_invisible();
  test_configuration_failures_stop_before_loading();
  test_normal_load_failure_starts_recovery();
  test_normal_start_error_unloads_then_recovers();
  test_unexpected_success_return_uses_typed_failure();
  test_recovery_failures_preserve_original_error();
  test_error_handles_are_unloaded_exactly_once();
  test_null_handles_and_resource_failures_are_bounded();
  test_argument_validation();
  return 0;
}
