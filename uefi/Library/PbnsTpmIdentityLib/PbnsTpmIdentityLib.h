#ifndef PBNS_TPM_IDENTITY_LIB_H
#define PBNS_TPM_IDENTITY_LIB_H

#include <Uefi.h>

#include "pbns/buffer.h"
#include "pbns/identity.h"
#include "pbns/measured_boot.h"
#include "pbns/tpm_capabilities.h"

#define PBNS_TPM_ENROLLMENT_PUBLIC_MAX_SIZE 1024U
#define PBNS_TPM_ENROLLMENT_NAME_MAX_SIZE 64U

typedef struct pbns_tpm_enrollment_public {
  pbns_buffer EkPublic;
  pbns_buffer AkPublic;
  pbns_buffer AkName;
  pbns_buffer EkCertificate;
  pbns_buffer IdentityPublic;
} pbns_tpm_enrollment_public;

typedef struct pbns_tpm_capability_result {
  pbns_tpm_capabilities required;
  bool ek_certificate_present;
  uint8_t ek_chain_digest[32];
} pbns_tpm_capability_result;

EFI_STATUS EFIAPI
PbnsTpmIdentityCapabilities(pbns_tpm_capability_result *Result);
EFI_STATUS EFIAPI PbnsTpmIdentityCreate(pbns_identity *Identity,
                                        pbns_tpm_capability_result *Result);
EFI_STATUS EFIAPI PbnsTpmIdentityOpen(pbns_identity *Identity,
                                      pbns_tpm_capability_result *Result);
EFI_STATUS EFIAPI PbnsTpmIdentityReset(void);
EFI_STATUS EFIAPI PbnsTpmReadBaselinePcrs(uint8_t Digests[4][32],
                                          uint32_t *UpdateCounter);
EFI_STATUS EFIAPI PbnsTpmIdentityEnrollmentPublic(
    pbns_identity *Identity, pbns_tpm_enrollment_public *Evidence);
EFI_STATUS EFIAPI PbnsTpmIdentityQuote(
    pbns_identity *Identity, pbns_measured_boot_selection Selection,
    const uint8_t QualifyingData[32], pbns_buffer Attestation,
    UINTN *AttestationSize, pbns_buffer Signature, UINTN *SignatureSize,
    UINT32 *CommandResult);
EFI_STATUS EFIAPI PbnsTpmIdentityCertify(
    pbns_identity *Identity, pbns_view Nonce, pbns_buffer Attestation,
    UINTN *AttestationSize, pbns_buffer Signature, UINTN *SignatureSize,
    UINT32 *CommandResult);
EFI_STATUS EFIAPI PbnsTpmIdentityActivateCredential(
    pbns_identity *Identity, pbns_view CredentialBlob, pbns_view Secret,
    pbns_buffer Output, UINTN *OutputSize, UINT32 *CommandResult);

#endif
