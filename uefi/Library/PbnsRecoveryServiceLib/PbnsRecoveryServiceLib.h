#ifndef PBNS_RECOVERY_SERVICE_LIB_H
#define PBNS_RECOVERY_SERVICE_LIB_H

#include <Uefi.h>

#include <PbnsRecoveryClientLib.h>

#include "pbns/recovery_assurance.h"
#include "pbns/status.h"
#include "pbns/tls_transport.h"

typedef struct PBNS_RECOVERY_SERVICE PBNS_RECOVERY_SERVICE;

const pbns_tls_client_config *EFIAPI PbnsRecoveryServiceTrustConfig(void);

EFI_STATUS EFIAPI PbnsRecoveryServiceCreate(
    EFI_SYSTEM_TABLE *system_table, pbns_recovery_assurance_mode mode,
    PBNS_RECOVERY_SERVICE **service);
pbns_status PbnsRecoveryServiceTrustedTime(PBNS_RECOVERY_SERVICE *service);
pbns_status PbnsRecoveryServiceManifest(PBNS_RECOVERY_SERVICE *service,
                                        PBNS_RECOVERY_PLAN *plan);
pbns_status PbnsRecoveryServiceStream(PBNS_RECOVERY_SERVICE *service,
                                      void *image, uint64_t size);
pbns_status PbnsRecoveryServiceReadVersion(PBNS_RECOVERY_SERVICE *service,
                                           uint64_t *version);
pbns_status PbnsRecoveryServiceAdvanceVersion(PBNS_RECOVERY_SERVICE *service,
                                              uint64_t current, uint64_t target,
                                              pbns_view authorization);
void EFIAPI PbnsRecoveryServiceDestroy(PBNS_RECOVERY_SERVICE *service);

#endif
