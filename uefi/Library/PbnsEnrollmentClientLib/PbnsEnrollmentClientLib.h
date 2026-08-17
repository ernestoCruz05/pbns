#ifndef PBNS_ENROLLMENT_CLIENT_LIB_H
#define PBNS_ENROLLMENT_CLIENT_LIB_H

#include <Uefi.h>

#include <Library/PbnsCoseCryptoLib.h>
#include <PbnsTlsTransportLib.h>

#include <stdbool.h>

#include "pbns/deployment_trust.h"

typedef struct PBNS_ENROLLMENT_CLIENT_ADAPTER {
  pbns_cose_key IdentityKey;
  pbns_cose_key RecipientKey;
  pbns_cose_key SignerKey;
  pbns_identity *Identity;
  bool IdentityKeyReady;
  bool RecipientKeyReady;
  bool SignerKeyReady;
  bool Initialized;
} PBNS_ENROLLMENT_CLIENT_ADAPTER;

EFI_STATUS EFIAPI PbnsEnrollmentClientAdapterInit(
    PBNS_ENROLLMENT_CLIENT_ADAPTER *Adapter, pbns_identity *Identity,
    const pbns_deployment_public_key *Recipient,
    const pbns_deployment_public_key *Signer);

VOID EFIAPI
PbnsEnrollmentClientAdapterReset(PBNS_ENROLLMENT_CLIENT_ADAPTER *Adapter);

pbns_status EFIAPI PbnsEnrollmentClientTlsOpen(
    EFI_BOOT_SERVICES *BootServices, pbns_transport Lower,
    const pbns_tls_client_config *Config,
    const PBNS_TPM_RANDOM_SOURCE *TpmRandom, PBNS_TLS_UEFI_TRANSPORT **Tls,
    pbns_transport *BrokerTransport);

pbns_status EFIAPI
PbnsEnrollmentClientTlsDestroy(PBNS_TLS_UEFI_TRANSPORT **Tls);

#endif
