#ifndef PBNS_TRUSTED_TIME_LIB_H
#define PBNS_TRUSTED_TIME_LIB_H

#include <Uefi.h>

#include <Library/PbnsCoseCryptoLib.h>

#include "pbns/broker.h"
#include "pbns/identity.h"
#include "pbns/status.h"
#include "pbns/trusted_time.h"

typedef struct pbns_uefi_trusted_time_environment {
  EFI_BOOT_SERVICES *boot_services;
  pbns_broker *broker;
  const pbns_identity *identity;
  const pbns_cose_key *identity_key;
  const pbns_cose_key *time_verification_key;
  pbns_view time_key_id;
  uint32_t maximum_round_trip_ms;
} pbns_uefi_trusted_time_environment;

pbns_status EFIAPI
PbnsTrustedTimeClientInit(pbns_uefi_trusted_time_environment *environment,
                          pbns_trusted_time_client *client);

#endif
