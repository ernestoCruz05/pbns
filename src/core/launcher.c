#include "pbns/launcher.h"

#include <stddef.h>

static bool config_valid(const pbns_launcher_config *config) {
  if (config == NULL || config->self_reference ||
      config->recovery_device_path.ptr == NULL ||
      config->recovery_device_path.len == 0U ||
      config->recovery_device_path.len > PBNS_LAUNCHER_MAX_DEVICE_PATH_SIZE) {
    return false;
  }
  return true;
}

static bool ops_valid(const pbns_launcher_ops *ops) {
  return ops != NULL && ops->read_config != NULL && ops->load != NULL &&
         ops->start != NULL && ops->record_failure != NULL &&
         ops->unload != NULL;
}

pbns_status pbns_launcher_run(const pbns_launcher_ops *ops, void *context,
                              uint64_t unexpected_return_status,
                              pbns_launcher_result *result) {
  pbns_launcher_config config = {0};
  pbns_status status = PBNS_ERR_STATE;
  pbns_status original_status = PBNS_ERR_STATE;
  uint64_t platform_status = 0U;
  void *image = NULL;
  bool returned = true;

  if (!ops_valid(ops) || context == NULL || result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *result = (pbns_launcher_result){
      .outcome = PBNS_LAUNCHER_OUTCOME_FAILED,
      .stage = PBNS_LAUNCHER_STAGE_READ_CONFIG,
  };

  status = ops->read_config(context, &config, &platform_status);
  if (status != PBNS_OK) {
    result->original_stage = PBNS_LAUNCHER_STAGE_READ_CONFIG;
    result->original_platform_status = platform_status;
    return status;
  }
  if (!config_valid(&config)) {
    result->stage = PBNS_LAUNCHER_STAGE_VALIDATE_CONFIG;
    result->original_stage = PBNS_LAUNCHER_STAGE_VALIDATE_CONFIG;
    return config.self_reference ? PBNS_ERR_STATE : PBNS_ERR_FORMAT;
  }

  result->stage = PBNS_LAUNCHER_STAGE_LOAD_NORMAL;
  platform_status = 0U;
  status = ops->load(context, PBNS_LAUNCHER_TARGET_NORMAL, &config, &image,
                     &platform_status);
  if (status == PBNS_OK && image == NULL) {
    status = PBNS_ERR_STATE;
    platform_status = unexpected_return_status;
  }
  if (status != PBNS_OK && image != NULL) {
    ops->unload(context, PBNS_LAUNCHER_TARGET_NORMAL, image);
    image = NULL;
  }
  if (status == PBNS_OK) {
    result->stage = PBNS_LAUNCHER_STAGE_START_NORMAL;
    returned = true;
    platform_status = 0U;
    status = ops->start(context, PBNS_LAUNCHER_TARGET_NORMAL, image, &returned,
                        &platform_status);
    if (status == PBNS_OK && !returned) {
      result->outcome = PBNS_LAUNCHER_OUTCOME_NORMAL_TRANSFERRED;
      result->stage = PBNS_LAUNCHER_STAGE_NONE;
      return PBNS_OK;
    }
    ops->unload(context, PBNS_LAUNCHER_TARGET_NORMAL, image);
    image = NULL;
    if (status == PBNS_OK) {
      status = PBNS_ERR_STATE;
      platform_status = unexpected_return_status;
    }
  }

  original_status = status;
  result->original_stage = result->stage;
  result->original_platform_status = platform_status;
  ops->record_failure(context, result->original_stage, platform_status);

  result->stage = PBNS_LAUNCHER_STAGE_LOAD_RECOVERY;
  platform_status = 0U;
  status = ops->load(context, PBNS_LAUNCHER_TARGET_RECOVERY, &config, &image,
                     &platform_status);
  if (status == PBNS_OK && image == NULL) {
    status = PBNS_ERR_STATE;
    platform_status = unexpected_return_status;
  }
  if (status != PBNS_OK && image != NULL) {
    ops->unload(context, PBNS_LAUNCHER_TARGET_RECOVERY, image);
    image = NULL;
  }
  if (status != PBNS_OK) {
    result->recovery_platform_status = platform_status;
    return original_status;
  }

  result->stage = PBNS_LAUNCHER_STAGE_START_RECOVERY;
  returned = true;
  platform_status = 0U;
  status = ops->start(context, PBNS_LAUNCHER_TARGET_RECOVERY, image, &returned,
                      &platform_status);
  if (status == PBNS_OK && !returned) {
    result->outcome = PBNS_LAUNCHER_OUTCOME_RECOVERY_TRANSFERRED;
    result->stage = PBNS_LAUNCHER_STAGE_NONE;
    return PBNS_OK;
  }
  ops->unload(context, PBNS_LAUNCHER_TARGET_RECOVERY, image);
  if (status == PBNS_OK) {
    platform_status = unexpected_return_status;
  }
  result->recovery_platform_status = platform_status;
  return original_status;
}
