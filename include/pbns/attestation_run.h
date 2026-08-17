#ifndef PBNS_ATTESTATION_RUN_H
#define PBNS_ATTESTATION_RUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/attestation.h"
#include "pbns/attestation_receipt.h"
#include "pbns/attestation_upload.h"
#include "pbns/attestation_wire.h"
#include "pbns/broker.h"
#include "pbns/identity.h"

#define PBNS_ATTESTATION_RUN_KID_MAX_SIZE 64U

typedef struct pbns_attestation_run_result {
  pbns_attestation_receipt_verdict verdict;
  uint64_t reasons[PBNS_ATTESTATION_RECEIPT_MAX_REASONS];
  size_t reason_count;
  pbns_attestation_display_state display_state;
} pbns_attestation_run_result;

typedef pbns_status (*pbns_attestation_run_trusted_time_fn)(
    void *context, pbns_time_interval *interval);
typedef pbns_status (*pbns_attestation_run_monotonic_fn)(
    void *context, uint64_t *now_ms);
typedef pbns_status (*pbns_attestation_run_cancel_fn)(
    void *context, bool *requested);
typedef pbns_status (*pbns_attestation_run_inventory_fn)(
    void *context, pbns_buffer variable_scratch,
    pbns_inventory_report *report);
typedef pbns_status (*pbns_attestation_run_measured_fn)(
    void *context, pbns_measured_boot_selection selection,
    pbns_buffer event_log_arena, pbns_measured_boot_evidence *evidence);
typedef pbns_status (*pbns_attestation_run_display_fn)(
    void *context, const pbns_attestation_run_result *result);

typedef struct pbns_attestation_run_ops {
  pbns_attestation_run_trusted_time_fn trusted_time;
  pbns_attestation_run_monotonic_fn monotonic_ms;
  pbns_attestation_run_cancel_fn cancel_requested;
  pbns_attestation_run_inventory_fn capture_inventory;
  pbns_attestation_run_measured_fn capture_measured;
  pbns_attestation_run_display_fn display_authenticated;
} pbns_attestation_run_ops;

typedef struct pbns_attestation_run_config {
  pbns_broker *broker;
  /* As regiões dos contextos broker abrangem objectos concretos completos e
   * são obtidas do adaptador proprietário de cada contexto opaco. */
  pbns_view broker_transport_context_region;
  pbns_view broker_platform_context_region;
  pbns_identity_assurance identity_assurance;
  uint8_t host_fingerprint[PBNS_INVENTORY_DIGEST_SIZE];
  pbns_view recipient_kid;
  pbns_view challenge_kid;
  pbns_view receipt_kid;
  pbns_view ak_name;
  pbns_view ak_reference;
  const pbns_crypto *challenge_verifier;
  const pbns_crypto *receipt_verifier;
  pbns_view challenge_verifier_context_region;
  pbns_view receipt_verifier_context_region;
  pbns_attestation_submission submission_template;
  pbns_attestation_run_ops ops;
  void *context;
  pbns_view context_region;
  uint64_t timeout_ms;
} pbns_attestation_run_config;

typedef struct pbns_attestation_run_workspace {
  pbns_buffer issue_wire;
  pbns_buffer issue_canonical;
  pbns_buffer submit_wire;
  pbns_buffer submit_canonical;
  pbns_attestation_challenge_workspace challenge;
  pbns_buffer inventory_variable_scratch;
  pbns_buffer event_log_arena;
  pbns_attestation_workspace attestation;
  pbns_attestation_receipt_workspace receipt;
  pbns_buffer evidence_digest;
} pbns_attestation_run_workspace;

pbns_status pbns_attestation_run(const pbns_attestation_run_config *config,
                                 pbns_attestation_run_workspace *workspace,
                                 pbns_attestation_run_result *result);

#endif
