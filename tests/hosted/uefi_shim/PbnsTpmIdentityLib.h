#ifndef PBNS_TEST_TPM_IDENTITY_LIB_H
#define PBNS_TEST_TPM_IDENTITY_LIB_H

#include <Uefi.h>

#include "pbns/buffer.h"
#include "pbns/identity.h"
#include "pbns/measured_boot.h"

EFI_STATUS EFIAPI PbnsTpmIdentityQuote(
    pbns_identity *Identity, pbns_measured_boot_selection Selection,
    const uint8_t QualifyingData[32], pbns_buffer Attestation,
    UINTN *AttestationSize, pbns_buffer Signature, UINTN *SignatureSize,
    UINT32 *CommandResult);

#endif
