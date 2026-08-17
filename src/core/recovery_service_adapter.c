#include "recovery_service_adapter.h"

#include <stddef.h>

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  while (bytes != NULL && length > 0U) {
    *bytes = 0U;
    ++bytes;
    --length;
  }
}

static bool controller_matches_mode(pbns_recovery_assurance_mode mode,
                                    const pbns_anti_rollback *controller) {
  return controller != NULL &&
         ((mode == PBNS_RECOVERY_ASSURANCE_T &&
           controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_TPM) ||
          (mode == PBNS_RECOVERY_ASSURANCE_S &&
           controller->assurance == PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED));
}

void pbns_recovery_service_manifest_invalidate(
    pbns_recovery_service_manifest_state *state,
    pbns_recovery_live_workspace *workspace) {
  if (state != NULL) {
    secure_zero(&state->manifest, sizeof(state->manifest));
    state->ready = false;
  }
  if (workspace != NULL) {
    secure_zero(workspace, sizeof(*workspace));
  }
}

pbns_status pbns_recovery_service_manifest_set(
    pbns_recovery_service_manifest_state *state,
    const pbns_recovery_manifest *manifest) {
  if (state == NULL || manifest == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  state->manifest = *manifest;
  state->ready = true;
  return PBNS_OK;
}

bool pbns_recovery_service_manifest_target_matches(
    const pbns_recovery_service_manifest_state *state, uint64_t target) {
  return state != NULL && state->ready && target > 0U &&
         target == state->manifest.artifact_version;
}

pbns_status pbns_recovery_service_stream(
    const pbns_recovery_live_client *client,
    pbns_recovery_service_manifest_state *state, pbns_buffer exact_pages,
    pbns_recovery_live_workspace *workspace) {
  if (state == NULL || !state->ready || exact_pages.ptr == NULL ||
      exact_pages.len != 0U ||
      exact_pages.cap != state->manifest.image_size) {
    if (state != NULL) {
      pbns_recovery_service_manifest_invalidate(state, workspace);
    }
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = pbns_recovery_live_artifact(
      client, &state->manifest, exact_pages, workspace);
  if (status != PBNS_OK) {
    pbns_recovery_service_manifest_invalidate(state, workspace);
  }
  return status;
}

pbns_status pbns_recovery_service_rollback_read(
    pbns_recovery_service_rollback *rollback, uint64_t *version) {
  pbns_anti_rollback_state state = {0};
  if (rollback == NULL || version == NULL ||
      !controller_matches_mode(rollback->mode, rollback->controller)) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status =
      pbns_anti_rollback_read(rollback->controller, &state);
  if (status != PBNS_OK) {
    rollback->retained_valid = false;
    return status;
  }
  rollback->retained = state;
  rollback->retained_valid = true;
  *version = state.version;
  return PBNS_OK;
}

pbns_status pbns_recovery_service_rollback_advance(
    pbns_recovery_service_rollback *rollback,
    const pbns_recovery_service_manifest_state *manifest_state,
    uint64_t current, uint64_t target, pbns_view manifest_authorization) {
  pbns_anti_rollback_state reread = {0};
  if (rollback == NULL ||
      !controller_matches_mode(rollback->mode, rollback->controller)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!rollback->retained_valid || current != rollback->retained.version ||
      target <= current) {
    return PBNS_ERR_REPLAY;
  }
  if (!pbns_recovery_service_manifest_target_matches(manifest_state, target)) {
    return PBNS_ERR_AUTHENTICATION;
  }
  pbns_status status = pbns_anti_rollback_read(rollback->controller, &reread);
  if (status != PBNS_OK || reread.version != current) {
    rollback->retained_valid = false;
    return status == PBNS_OK ? PBNS_ERR_REPLAY : status;
  }
  const pbns_view authorization = rollback->mode == PBNS_RECOVERY_ASSURANCE_T
                                      ? manifest_authorization
                                      : (pbns_view){NULL, 0U};
  status = pbns_anti_rollback_advance(rollback->controller, target,
                                      authorization, &reread);
  if (status != PBNS_OK) {
    rollback->retained_valid = false;
    return status;
  }
  status = pbns_anti_rollback_read(rollback->controller, &reread);
  if (status != PBNS_OK || reread.version != target) {
    rollback->retained_valid = false;
    return status == PBNS_OK ? PBNS_ERR_STATE : status;
  }
  rollback->retained = reread;
  rollback->retained_valid = true;
  return PBNS_OK;
}
