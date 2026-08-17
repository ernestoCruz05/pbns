#ifndef PBNS_RECOVERY_SERVICE_ADAPTER_H
#define PBNS_RECOVERY_SERVICE_ADAPTER_H

#include <stdbool.h>
#include <stdint.h>

#include "pbns/anti_rollback.h"
#include "pbns/recovery_assurance.h"
#include "pbns/recovery_live.h"

typedef struct pbns_recovery_service_manifest_state {
  pbns_recovery_manifest manifest;
  bool ready;
} pbns_recovery_service_manifest_state;

typedef struct pbns_recovery_service_rollback {
  pbns_recovery_assurance_mode mode;
  pbns_anti_rollback *controller;
  pbns_anti_rollback_state retained;
  bool retained_valid;
} pbns_recovery_service_rollback;

void pbns_recovery_service_manifest_invalidate(
    pbns_recovery_service_manifest_state *state,
    pbns_recovery_live_workspace *workspace);
pbns_status pbns_recovery_service_manifest_set(
    pbns_recovery_service_manifest_state *state,
    const pbns_recovery_manifest *manifest);
bool pbns_recovery_service_manifest_target_matches(
    const pbns_recovery_service_manifest_state *state, uint64_t target);
pbns_status pbns_recovery_service_stream(
    const pbns_recovery_live_client *client,
    pbns_recovery_service_manifest_state *state, pbns_buffer exact_pages,
    pbns_recovery_live_workspace *workspace);
pbns_status pbns_recovery_service_rollback_read(
    pbns_recovery_service_rollback *rollback, uint64_t *version);
pbns_status pbns_recovery_service_rollback_advance(
    pbns_recovery_service_rollback *rollback,
    const pbns_recovery_service_manifest_state *manifest_state,
    uint64_t current, uint64_t target, pbns_view manifest_authorization);

#endif
