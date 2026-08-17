#ifndef PBNS_ATTESTATION_CLIENT_LIB_H
#define PBNS_ATTESTATION_CLIENT_LIB_H

#include <Uefi.h>

#include <Library/PbnsCoseCryptoLib.h>
#include <PbnsTpmIdentityLib.h>

#include <stdbool.h>
#include <stdint.h>

#include "pbns/attestation.h"

/* Os contextos concretos são públicos para permitir regiões completas e exatas
 * na execução portável, sem presumir dimensões opacas. */
typedef struct PBNS_ATTESTATION_CLIENT_COSE_CONTEXT {
  pbns_identity *Identity;
  const pbns_cose_key *Key;
} PBNS_ATTESTATION_CLIENT_COSE_CONTEXT;

typedef struct PBNS_ATTESTATION_CLIENT_QUOTE_CONTEXT {
  pbns_identity *Identity;
  UINT32 *CommandResult;
} PBNS_ATTESTATION_CLIENT_QUOTE_CONTEXT;

typedef struct PBNS_ATTESTATION_CLIENT_SHA256_CONTEXT {
  uint32_t Guard;
} PBNS_ATTESTATION_CLIENT_SHA256_CONTEXT;

typedef struct PBNS_ATTESTATION_CLIENT_ADAPTER {
  pbns_cose_key IdentityKey;
  PBNS_ATTESTATION_CLIENT_COSE_CONTEXT ChallengeContext;
  PBNS_ATTESTATION_CLIENT_COSE_CONTEXT ReceiptContext;
  PBNS_ATTESTATION_CLIENT_COSE_CONTEXT HostSignerContext;
  PBNS_ATTESTATION_CLIENT_COSE_CONTEXT RecipientContext;
  PBNS_ATTESTATION_CLIENT_SHA256_CONTEXT Sha256Context;
  PBNS_ATTESTATION_CLIENT_QUOTE_CONTEXT QuoteContext;
  pbns_crypto ChallengeVerifier;
  pbns_crypto ReceiptVerifier;
  pbns_crypto HostSigner;
  pbns_crypto RecipientEncrypter;
  pbns_view ChallengeVerifierContextRegion;
  pbns_view ReceiptVerifierContextRegion;
  pbns_attestation_submission Submission;
  UINT32 TpmCommandResult;
  bool Initialized;
} PBNS_ATTESTATION_CLIENT_ADAPTER;

/* O adaptador deve começar a zero; reponha-o antes de nova inicialização. */
EFI_STATUS EFIAPI PbnsAttestationClientAdapterInit(
    PBNS_ATTESTATION_CLIENT_ADAPTER *Adapter, pbns_identity *Identity,
    const pbns_cose_key *ChallengeVerifierKey,
    const pbns_cose_key *RecipientKey,
    const pbns_cose_key *ReceiptVerifierKey);

void EFIAPI PbnsAttestationClientAdapterReset(
    PBNS_ATTESTATION_CLIENT_ADAPTER *Adapter);

#endif
