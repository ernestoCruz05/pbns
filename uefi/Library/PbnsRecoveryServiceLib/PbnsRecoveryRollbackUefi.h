#ifndef PBNS_RECOVERY_ROLLBACK_UEFI_H
#define PBNS_RECOVERY_ROLLBACK_UEFI_H

#include <Uefi.h>

#include "pbns/buffer.h"
#include "../../../src/core/recovery_service_adapter.h"
#include "pbns/recovery_assurance.h"
#include "pbns/status.h"

typedef struct PBNS_RECOVERY_ROLLBACK PBNS_RECOVERY_ROLLBACK;

EFI_STATUS EFIAPI PbnsRecoveryRollbackOpen(
    pbns_recovery_assurance_mode mode, PBNS_RECOVERY_ROLLBACK **rollback);
void EFIAPI PbnsRecoveryRollbackDestroy(PBNS_RECOVERY_ROLLBACK *rollback);
pbns_status PbnsRecoveryRollbackRead(PBNS_RECOVERY_ROLLBACK *rollback,
                                     uint64_t *version);
pbns_status PbnsRecoveryRollbackAdvance(
    PBNS_RECOVERY_ROLLBACK *rollback,
    const pbns_recovery_service_manifest_state *manifest_state,
    uint64_t current, uint64_t target, pbns_view authorization);

#endif
