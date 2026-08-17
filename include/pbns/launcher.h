#ifndef PBNS_LAUNCHER_H
#define PBNS_LAUNCHER_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_LAUNCHER_MAX_DEVICE_PATH_SIZE 4096U

typedef enum pbns_launcher_target {
  PBNS_LAUNCHER_TARGET_NORMAL = 1,
  PBNS_LAUNCHER_TARGET_RECOVERY = 2
} pbns_launcher_target;

typedef enum pbns_launcher_stage {
  PBNS_LAUNCHER_STAGE_NONE = 0,
  PBNS_LAUNCHER_STAGE_READ_CONFIG = 1,
  PBNS_LAUNCHER_STAGE_VALIDATE_CONFIG = 2,
  PBNS_LAUNCHER_STAGE_LOAD_NORMAL = 3,
  PBNS_LAUNCHER_STAGE_START_NORMAL = 4,
  PBNS_LAUNCHER_STAGE_LOAD_RECOVERY = 5,
  PBNS_LAUNCHER_STAGE_START_RECOVERY = 6
} pbns_launcher_stage;

typedef enum pbns_launcher_outcome {
  PBNS_LAUNCHER_OUTCOME_FAILED = 0,
  PBNS_LAUNCHER_OUTCOME_NORMAL_TRANSFERRED = 1,
  PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED = 2
} pbns_launcher_outcome;

typedef struct pbns_launcher_config {
  uint16_t normal_boot_option;
  pbns_view recovery_device_path;
  bool self_reference;
} pbns_launcher_config;

typedef struct pbns_launcher_result {
  pbns_launcher_outcome outcome;
  pbns_launcher_stage stage;
  pbns_launcher_stage original_stage;
  uint64_t original_platform_status;
  uint64_t recovery_platform_status;
} pbns_launcher_result;

typedef struct pbns_launcher_ops {
  pbns_status (*read_config)(void *context, pbns_launcher_config *config,
                             uint64_t *platform_status);
  pbns_status (*load)(void *context, pbns_launcher_target target,
                      const pbns_launcher_config *config, void **image,
                      uint64_t *platform_status);
  pbns_status (*start)(void *context, pbns_launcher_target target, void *image,
                       bool *returned, uint64_t *platform_status);
  void (*record_failure)(void *context, pbns_launcher_stage stage,
                         uint64_t platform_status);
  void (*unload)(void *context, pbns_launcher_target target, void *image);
} pbns_launcher_ops;

pbns_status pbns_launcher_run(const pbns_launcher_ops *ops, void *context,
                              uint64_t unexpected_return_status,
                              pbns_launcher_result *result);

#endif
