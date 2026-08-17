#include "PbnsEnrollmentClientLib.h"

#include <stddef.h>
#include <stdint.h>

static void secure_zero(void *value, size_t length) {
  volatile uint8_t *bytes = value;
  if (bytes == NULL) {
    return;
  }
  for (size_t index = 0U; index < length; ++index) {
    bytes[index] = 0U;
  }
}

static bool public_key_valid(const pbns_deployment_public_key *key) {
  return key != NULL && key->kid.ptr != NULL && key->kid.len > 0U &&
         key->kid.len <= 64U && key->x.ptr != NULL && key->x.len == 32U &&
         key->y.ptr != NULL && key->y.len == 32U;
}

VOID EFIAPI
PbnsEnrollmentClientAdapterReset(PBNS_ENROLLMENT_CLIENT_ADAPTER *adapter) {
  if (adapter == NULL) {
    return;
  }
  if (adapter->SignerKeyReady || adapter->RecipientKeyReady ||
      adapter->IdentityKeyReady || adapter->Initialized) {
    pbns_cose_key_reset(&adapter->SignerKey);
    pbns_cose_key_reset(&adapter->RecipientKey);
    pbns_cose_key_reset(&adapter->IdentityKey);
  }
  secure_zero(adapter, sizeof(*adapter));
}

EFI_STATUS EFIAPI PbnsEnrollmentClientAdapterInit(
    PBNS_ENROLLMENT_CLIENT_ADAPTER *adapter, pbns_identity *identity,
    const pbns_deployment_public_key *recipient,
    const pbns_deployment_public_key *signer) {
  if (adapter == NULL || identity == NULL || !public_key_valid(recipient) ||
      !public_key_valid(signer) || adapter->Initialized ||
      adapter->IdentityKeyReady || adapter->RecipientKeyReady ||
      adapter->SignerKeyReady) {
    return EFI_INVALID_PARAMETER;
  }
  secure_zero(adapter, sizeof(*adapter));
  if (pbns_cose_key_from_identity(&adapter->IdentityKey, identity) != PBNS_OK) {
    adapter->IdentityKeyReady = true;
    PbnsEnrollmentClientAdapterReset(adapter);
    return EFI_SECURITY_VIOLATION;
  }
  adapter->IdentityKeyReady = true;
  if (pbns_cose_key_from_p256_public(&adapter->RecipientKey, recipient->x,
                                     recipient->y) != PBNS_OK) {
    adapter->RecipientKeyReady = true;
    PbnsEnrollmentClientAdapterReset(adapter);
    return EFI_SECURITY_VIOLATION;
  }
  adapter->RecipientKeyReady = true;
  if (pbns_cose_key_from_p256_public(&adapter->SignerKey, signer->x,
                                     signer->y) != PBNS_OK) {
    adapter->SignerKeyReady = true;
    PbnsEnrollmentClientAdapterReset(adapter);
    return EFI_SECURITY_VIOLATION;
  }
  adapter->SignerKeyReady = true;
  adapter->Identity = identity;
  adapter->Initialized = true;
  return EFI_SUCCESS;
}

pbns_status EFIAPI PbnsEnrollmentClientTlsOpen(
    EFI_BOOT_SERVICES *boot_services, pbns_transport lower,
    const pbns_tls_client_config *config,
    const PBNS_TPM_RANDOM_SOURCE *tpm_random, PBNS_TLS_UEFI_TRANSPORT **tls,
    pbns_transport *broker_transport) {
  if (tls == NULL || broker_transport == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (*tls != NULL) {
    return PBNS_ERR_STATE;
  }
  *broker_transport = (pbns_transport){0};
  if (boot_services == NULL || lower.ops == NULL || config == NULL ||
      tpm_random == NULL || tpm_random->Fill == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  PBNS_TLS_UEFI_TRANSPORT *created = NULL;
  const pbns_status status = PbnsTlsTransportCreate(
      boot_services, lower, config, tpm_random, &created);
  *tls = created;
  if (status != PBNS_OK) {
    return status;
  }
  if (created == NULL) {
    return PBNS_ERR_STATE;
  }
  const pbns_transport transport = PbnsTlsTransportAsTransport(created);
  if (transport.ops == NULL || transport.context == NULL) {
    return PBNS_ERR_STATE;
  }
  *broker_transport = transport;
  return PBNS_OK;
}

pbns_status EFIAPI
PbnsEnrollmentClientTlsDestroy(PBNS_TLS_UEFI_TRANSPORT **tls) {
  if (tls == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (*tls == NULL) {
    return PBNS_OK;
  }
  pbns_status status = PBNS_ERR_STATE;
  for (size_t attempt = 0U; attempt < 3U; ++attempt) {
    status = PbnsTlsTransportDestroy(*tls);
    if (status == PBNS_OK) {
      *tls = NULL;
      return PBNS_OK;
    }
  }
  return status;
}
