#include "PbnsRecoveryClientLib.h"

#include <limits.h>

static bool operations_valid(const PBNS_RECOVERY_CLIENT_OPS *ops) {
  return ops != NULL && ops->confirm != NULL && ops->platform_ready != NULL &&
         ops->trusted_time != NULL && ops->verified_manifest != NULL &&
         ops->allocate_pages != NULL && ops->stream_image != NULL &&
         ops->verify_digest != NULL && ops->read_version != NULL &&
         ops->load_image != NULL && ops->advance_version != NULL &&
         ops->start_image != NULL && ops->unload_image != NULL &&
         ops->free_pages != NULL;
}

static void transition(const PBNS_RECOVERY_CLIENT_OPS *ops, void *context,
                       PBNS_RECOVERY_CLIENT_RESULT *result,
                       PBNS_RECOVERY_CLIENT_STATE state) {
  result->state = state;
  if (ops->state_changed != NULL) {
    ops->state_changed(context, state);
  }
}

static pbns_status fail_run(const PBNS_RECOVERY_CLIENT_OPS *ops, void *context,
                            PBNS_RECOVERY_CLIENT_RESULT *result,
                            PBNS_RECOVERY_CLIENT_STATE stage,
                            pbns_status status, void *image,
                            uint64_t image_size, void *image_handle) {
  if (image_handle != NULL) {
    (void)ops->unload_image(context, image_handle);
  }
  if (image != NULL) {
    (void)ops->free_pages(context, image, image_size);
  }
  result->failed_stage = stage;
  result->status = status;
  transition(ops, context, result, PBNS_RECOVERY_STATE_FAILED);
  if (ops->failed != NULL) {
    ops->failed(context, stage, status);
  }
  return status;
}

pbns_status PbnsRecoveryClientRun(const PBNS_RECOVERY_CLIENT_OPS *ops,
                                  void *context,
                                  PBNS_RECOVERY_CLIENT_RESULT *result) {
  if (!operations_valid(ops) || result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *result = (PBNS_RECOVERY_CLIENT_RESULT){
      .state = PBNS_RECOVERY_STATE_CONFIRM,
      .failed_stage = PBNS_RECOVERY_STATE_CONFIRM,
      .status = PBNS_OK,
  };

  bool accepted = false;
  transition(ops, context, result, PBNS_RECOVERY_STATE_CONFIRM);
  pbns_status status = ops->confirm(context, &accepted);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_CONFIRM, status,
                    NULL, 0U, NULL);
  }
  if (!accepted) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_CONFIRM,
                    PBNS_ERR_STATE, NULL, 0U, NULL);
  }
  status = ops->platform_ready(context);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_CONFIRM, status,
                    NULL, 0U, NULL);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_TIME);
  status = ops->trusted_time(context);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_TIME, status,
                    NULL, 0U, NULL);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_MANIFEST);
  PBNS_RECOVERY_PLAN plan = {0};
  status = ops->verified_manifest(context, &plan);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_MANIFEST, status,
                    NULL, 0U, NULL);
  }
  if (plan.artifact_size == 0U ||
      plan.artifact_size > PBNS_RECOVERY_CLIENT_MAX_ARTIFACT_SIZE ||
      plan.artifact_size > (uint64_t)SIZE_MAX || plan.target_version == 0U) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_MANIFEST,
                    PBNS_ERR_LIMIT, NULL, 0U, NULL);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_ALLOCATE);
  void *image = NULL;
  status = ops->allocate_pages(context, plan.artifact_size, &image);
  if (status != PBNS_OK || image == NULL) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_ALLOCATE,
                    status == PBNS_OK ? PBNS_ERR_RESOURCE : status, NULL, 0U,
                    NULL);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_STREAM);
  status = ops->stream_image(context, image, plan.artifact_size);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_STREAM, status,
                    image, plan.artifact_size, NULL);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_DIGEST);
  status = ops->verify_digest(context,
                              (pbns_view){image, (size_t)plan.artifact_size},
                              plan.artifact_digest);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_DIGEST, status,
                    image, plan.artifact_size, NULL);
  }
  uint64_t current_version = 0U;
  status = ops->read_version(context, &current_version);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_DIGEST, status,
                    image, plan.artifact_size, NULL);
  }
  if (plan.target_version <= current_version) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_DIGEST,
                    PBNS_ERR_REPLAY, image, plan.artifact_size, NULL);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_LOAD_VERIFY);
  void *image_handle = NULL;
  status = ops->load_image(context,
                           (pbns_buffer){image, (size_t)plan.artifact_size,
                                         (size_t)plan.artifact_size},
                           &image_handle);
  if (status != PBNS_OK || image_handle == NULL) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_LOAD_VERIFY,
                    status == PBNS_OK ? PBNS_ERR_UNSUPPORTED : status, image,
                    plan.artifact_size, image_handle);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_ADVANCE_VERSION);
  status = ops->advance_version(context, current_version, plan.target_version,
                                plan.version_authorization);
  if (status != PBNS_OK) {
    return fail_run(ops, context, result, PBNS_RECOVERY_STATE_ADVANCE_VERSION,
                    status, image, plan.artifact_size, image_handle);
  }

  transition(ops, context, result, PBNS_RECOVERY_STATE_START);
  (void)ops->start_image(context, image_handle);
  return fail_run(ops, context, result, PBNS_RECOVERY_STATE_START,
                  PBNS_ERR_STATE, image, plan.artifact_size, image_handle);
}
