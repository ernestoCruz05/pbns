#include "PbnsRecoveryStreamUefi.h"

pbns_status PbnsRecoveryServiceLiveArtifact(
    pbns_broker *broker, const pbns_identity *identity,
    const pbns_cose_key *identity_key, const pbns_cose_key *manifest_key,
    pbns_recovery_service_manifest_state *manifest_state, pbns_buffer pages,
    pbns_recovery_live_workspace *workspace, mbedtls_sha256_context *hash);

pbns_status PbnsRecoveryServiceStreamUefi(
    pbns_broker *broker, const pbns_identity *identity,
    const pbns_cose_key *identity_key, const pbns_cose_key *manifest_key,
    pbns_recovery_service_manifest_state *manifest_state, pbns_buffer pages,
    pbns_recovery_live_workspace *workspace, mbedtls_sha256_context *hash) {
  if (broker == NULL || identity == NULL || identity_key == NULL ||
      manifest_key == NULL || manifest_state == NULL || !manifest_state->ready ||
      pages.ptr == NULL || pages.len != 0U ||
      pages.cap != manifest_state->manifest.image_size || workspace == NULL ||
      hash == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  return PbnsRecoveryServiceLiveArtifact(broker, identity, identity_key,
                                         manifest_key, manifest_state, pages,
                                         workspace, hash);
}
