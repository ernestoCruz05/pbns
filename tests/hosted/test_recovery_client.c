#include "PbnsRecoveryClientLib.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum event {
  EVENT_NONE = 0,
  EVENT_CONFIRM,
  EVENT_PLATFORM,
  EVENT_TIME,
  EVENT_MANIFEST,
  EVENT_ALLOCATE,
  EVENT_STREAM,
  EVENT_DIGEST,
  EVENT_READ_VERSION,
  EVENT_LOAD,
  EVENT_ADVANCE,
  EVENT_START,
  EVENT_UNLOAD,
  EVENT_FREE,
  EVENT_FAILED,
  EVENT_STATE_BASE = 100
};

enum failure {
  FAIL_NONE = 0,
  FAIL_CONFIRM,
  FAIL_PLATFORM,
  FAIL_TIME,
  FAIL_MANIFEST,
  FAIL_ALLOCATE,
  FAIL_STREAM,
  FAIL_DIGEST,
  FAIL_READ_VERSION,
  FAIL_LOAD,
  FAIL_ADVANCE
};

typedef struct fixture {
  enum event events[64];
  size_t event_count;
  enum failure failure;
  bool accepted;
  bool return_handle_on_load_failure;
  uint64_t current_version;
  uint64_t target_version;
  uint8_t image[32];
  uint8_t authorization[4];
  int handle;
  PBNS_RECOVERY_CLIENT_STATE failed_stage;
  pbns_status failed_status;
} fixture;

static void record(fixture *value, enum event event) {
  if (value->event_count < sizeof(value->events) / sizeof(value->events[0])) {
    value->events[value->event_count++] = event;
  }
}

static pbns_status status_for(fixture *value, enum failure failure) {
  return value->failure == failure ? PBNS_ERR_IO : PBNS_OK;
}

static pbns_status confirm(void *context, bool *accepted) {
  fixture *value = context;
  record(value, EVENT_CONFIRM);
  *accepted = value->accepted;
  return status_for(value, FAIL_CONFIRM);
}

static pbns_status platform_ready(void *context) {
  fixture *value = context;
  record(value, EVENT_PLATFORM);
  return status_for(value, FAIL_PLATFORM);
}

static pbns_status trusted_time(void *context) {
  fixture *value = context;
  record(value, EVENT_TIME);
  return status_for(value, FAIL_TIME);
}

static pbns_status verified_manifest(void *context, PBNS_RECOVERY_PLAN *plan) {
  fixture *value = context;
  record(value, EVENT_MANIFEST);
  if (value->failure == FAIL_MANIFEST) {
    return PBNS_ERR_AUTHENTICATION;
  }
  *plan = (PBNS_RECOVERY_PLAN){
      .artifact_size = sizeof(value->image),
      .target_version = value->target_version,
      .artifact_digest = {0x42U},
      .version_authorization = {value->authorization,
                                sizeof(value->authorization)},
  };
  return PBNS_OK;
}

static pbns_status allocate_pages(void *context, uint64_t size, void **image) {
  fixture *value = context;
  record(value, EVENT_ALLOCATE);
  if (size != sizeof(value->image) || value->failure == FAIL_ALLOCATE) {
    return PBNS_ERR_RESOURCE;
  }
  *image = value->image;
  return PBNS_OK;
}

static pbns_status stream_image(void *context, void *image, uint64_t size) {
  fixture *value = context;
  record(value, EVENT_STREAM);
  if (image != value->image || size != sizeof(value->image)) {
    return PBNS_ERR_ARGUMENT;
  }
  return status_for(value, FAIL_STREAM);
}

static pbns_status verify_digest(void *context, pbns_view image,
                                 const uint8_t expected_digest[32]) {
  fixture *value = context;
  record(value, EVENT_DIGEST);
  if (image.ptr != value->image || image.len != sizeof(value->image) ||
      expected_digest[0] != 0x42U) {
    return PBNS_ERR_ARGUMENT;
  }
  return value->failure == FAIL_DIGEST ? PBNS_ERR_AUTHENTICATION : PBNS_OK;
}

static pbns_status read_version(void *context, uint64_t *version) {
  fixture *value = context;
  record(value, EVENT_READ_VERSION);
  *version = value->current_version;
  return status_for(value, FAIL_READ_VERSION);
}

static pbns_status load_image(void *context, pbns_buffer image,
                              void **image_handle) {
  fixture *value = context;
  record(value, EVENT_LOAD);
  if (image.ptr != value->image || image.len != sizeof(value->image)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (value->failure == FAIL_LOAD) {
    if (value->return_handle_on_load_failure) {
      *image_handle = &value->handle;
    }
    return PBNS_ERR_AUTHENTICATION;
  }
  *image_handle = &value->handle;
  return PBNS_OK;
}

static pbns_status advance_version(void *context, uint64_t current_version,
                                   uint64_t target_version,
                                   pbns_view authorization) {
  fixture *value = context;
  record(value, EVENT_ADVANCE);
  if (current_version != value->current_version ||
      target_version != value->target_version ||
      authorization.ptr != value->authorization ||
      authorization.len != sizeof(value->authorization)) {
    return PBNS_ERR_ARGUMENT;
  }
  return status_for(value, FAIL_ADVANCE);
}

static pbns_status start_image(void *context, void *image_handle) {
  fixture *value = context;
  record(value, EVENT_START);
  return image_handle == &value->handle ? PBNS_OK : PBNS_ERR_ARGUMENT;
}

static pbns_status unload_image(void *context, void *image_handle) {
  fixture *value = context;
  record(value, EVENT_UNLOAD);
  return image_handle == &value->handle ? PBNS_OK : PBNS_ERR_ARGUMENT;
}

static pbns_status free_pages(void *context, void *image, uint64_t size) {
  fixture *value = context;
  record(value, EVENT_FREE);
  return image == value->image && size == sizeof(value->image)
             ? PBNS_OK
             : PBNS_ERR_ARGUMENT;
}

static void state_changed(void *context, PBNS_RECOVERY_CLIENT_STATE state) {
  fixture *value = context;
  record(value, (enum event)((int)EVENT_STATE_BASE + (int)state));
}

static void failed(void *context, PBNS_RECOVERY_CLIENT_STATE stage,
                   pbns_status status) {
  fixture *value = context;
  record(value, EVENT_FAILED);
  value->failed_stage = stage;
  value->failed_status = status;
}

static PBNS_RECOVERY_CLIENT_OPS operations(void) {
  return (PBNS_RECOVERY_CLIENT_OPS){
      .confirm = confirm,
      .platform_ready = platform_ready,
      .trusted_time = trusted_time,
      .verified_manifest = verified_manifest,
      .allocate_pages = allocate_pages,
      .stream_image = stream_image,
      .verify_digest = verify_digest,
      .read_version = read_version,
      .load_image = load_image,
      .advance_version = advance_version,
      .start_image = start_image,
      .unload_image = unload_image,
      .free_pages = free_pages,
      .state_changed = state_changed,
      .failed = failed,
  };
}

static fixture initialized_fixture(void) {
  return (fixture){
      .failure = FAIL_NONE,
      .accepted = true,
      .current_version = 4U,
      .target_version = 5U,
  };
}

static size_t event_index(const fixture *value, enum event wanted) {
  for (size_t index = 0U; index < value->event_count; ++index) {
    if (value->events[index] == wanted) {
      return index;
    }
  }
  return SIZE_MAX;
}

static size_t event_count(const fixture *value, enum event wanted) {
  size_t count = 0U;
  for (size_t index = 0U; index < value->event_count; ++index) {
    if (value->events[index] == wanted) {
      ++count;
    }
  }
  return count;
}

static int check_ordered_return_cleanup(void) {
  fixture value = initialized_fixture();
  PBNS_RECOVERY_CLIENT_RESULT result = {0};
  const PBNS_RECOVERY_CLIENT_OPS ops = operations();
  if (PbnsRecoveryClientRun(&ops, &value, &result) != PBNS_ERR_STATE ||
      result.state != PBNS_RECOVERY_STATE_FAILED ||
      result.failed_stage != PBNS_RECOVERY_STATE_START ||
      value.failed_stage != PBNS_RECOVERY_STATE_START ||
      value.failed_status != PBNS_ERR_STATE) {
    return 1;
  }
  const enum event ordered[] = {
      EVENT_CONFIRM,  EVENT_PLATFORM, EVENT_TIME,   EVENT_MANIFEST,
      EVENT_ALLOCATE, EVENT_STREAM,   EVENT_DIGEST, EVENT_READ_VERSION,
      EVENT_LOAD,     EVENT_ADVANCE,  EVENT_START,  EVENT_UNLOAD,
      EVENT_FREE,     EVENT_FAILED,
  };
  size_t previous = 0U;
  for (size_t index = 0U; index < sizeof(ordered) / sizeof(ordered[0]);
       ++index) {
    const size_t current = event_index(&value, ordered[index]);
    if (current == SIZE_MAX || (index != 0U && current <= previous)) {
      return 1;
    }
    previous = current;
  }
  return 0;
}

static int check_cancel_and_early_failures(void) {
  const PBNS_RECOVERY_CLIENT_OPS ops = operations();
  fixture cancel = initialized_fixture();
  cancel.accepted = false;
  PBNS_RECOVERY_CLIENT_RESULT result = {0};
  if (PbnsRecoveryClientRun(&ops, &cancel, &result) != PBNS_ERR_STATE ||
      result.failed_stage != PBNS_RECOVERY_STATE_CONFIRM ||
      event_count(&cancel, EVENT_ALLOCATE) != 0U) {
    return 1;
  }
  const enum failure failures[] = {
      FAIL_CONFIRM, FAIL_PLATFORM, FAIL_TIME, FAIL_MANIFEST, FAIL_ALLOCATE,
  };
  for (size_t index = 0U; index < sizeof(failures) / sizeof(failures[0]);
       ++index) {
    fixture value = initialized_fixture();
    value.failure = failures[index];
    if (PbnsRecoveryClientRun(&ops, &value, &result) == PBNS_OK ||
        event_count(&value, EVENT_LOAD) != 0U ||
        event_count(&value, EVENT_ADVANCE) != 0U) {
      return 1;
    }
  }
  return 0;
}

static int check_allocated_failure_cleanup(void) {
  const PBNS_RECOVERY_CLIENT_OPS ops = operations();
  const enum failure failures[] = {
      FAIL_STREAM, FAIL_DIGEST, FAIL_READ_VERSION, FAIL_LOAD, FAIL_ADVANCE,
  };
  for (size_t index = 0U; index < sizeof(failures) / sizeof(failures[0]);
       ++index) {
    fixture value = initialized_fixture();
    value.failure = failures[index];
    value.return_handle_on_load_failure = failures[index] == FAIL_LOAD;
    PBNS_RECOVERY_CLIENT_RESULT result = {0};
    if (PbnsRecoveryClientRun(&ops, &value, &result) == PBNS_OK ||
        event_count(&value, EVENT_FREE) != 1U ||
        event_count(&value, EVENT_START) != 0U) {
      return 1;
    }
    const size_t expected_unloads =
        failures[index] == FAIL_LOAD || failures[index] == FAIL_ADVANCE ? 1U
                                                                        : 0U;
    if (event_count(&value, EVENT_UNLOAD) != expected_unloads) {
      return 1;
    }
    if (failures[index] == FAIL_LOAD &&
        event_count(&value, EVENT_ADVANCE) != 0U) {
      return 1;
    }
  }
  return 0;
}

static int check_downgrade_rejected_before_load(void) {
  fixture value = initialized_fixture();
  value.target_version = value.current_version;
  const PBNS_RECOVERY_CLIENT_OPS ops = operations();
  PBNS_RECOVERY_CLIENT_RESULT result = {0};
  return PbnsRecoveryClientRun(&ops, &value, &result) == PBNS_ERR_REPLAY &&
                 result.failed_stage == PBNS_RECOVERY_STATE_DIGEST &&
                 event_count(&value, EVENT_LOAD) == 0U &&
                 event_count(&value, EVENT_FREE) == 1U
             ? 0
             : 1;
}

int main(void) {
  const PBNS_RECOVERY_CLIENT_OPS ops = operations();
  PBNS_RECOVERY_CLIENT_RESULT result = {0};
  if (PbnsRecoveryClientRun(NULL, NULL, &result) != PBNS_ERR_ARGUMENT ||
      PbnsRecoveryClientRun(&ops, NULL, NULL) != PBNS_ERR_ARGUMENT ||
      check_ordered_return_cleanup() != 0 ||
      check_cancel_and_early_failures() != 0 ||
      check_allocated_failure_cleanup() != 0 ||
      check_downgrade_rejected_before_load() != 0) {
    fputs("recovery client tests failed\n", stderr);
    return 1;
  }
  puts("recovery client tests passed");
  return 0;
}
