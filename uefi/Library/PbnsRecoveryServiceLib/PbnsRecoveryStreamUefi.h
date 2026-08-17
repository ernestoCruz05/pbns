#ifndef PBNS_RECOVERY_STREAM_UEFI_H
#define PBNS_RECOVERY_STREAM_UEFI_H

#include <Library/PbnsCoseCryptoLib.h>

#include <mbedtls/sha256.h>

#include "pbns/broker.h"
#include "pbns/identity.h"
#include "../../../src/core/recovery_service_adapter.h"
#include "pbns/recovery_live.h"

pbns_status PbnsRecoveryServiceStreamUefi(
    pbns_broker *broker, const pbns_identity *identity,
    const pbns_cose_key *identity_key, const pbns_cose_key *manifest_key,
    pbns_recovery_service_manifest_state *manifest_state, pbns_buffer pages,
    pbns_recovery_live_workspace *workspace, mbedtls_sha256_context *hash);

#endif
