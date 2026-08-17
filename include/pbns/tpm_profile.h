#ifndef PBNS_TPM_PROFILE_H
#define PBNS_TPM_PROFILE_H

#include <stdbool.h>
#include <stdint.h>

#include <tss2/tss2_tpm2_types.h>

#include "pbns/buffer.h"
#include "pbns/status.h"
#include "pbns/tpm_capabilities.h"

#define PBNS_TPM_RECOVERY_NV_INDEX ((TPM2_HANDLE)UINT32_C(0x01801000))
#define PBNS_TPM_COMMAND_RETRY_LIMIT 3U
#define PBNS_TPM_COMMAND_RETRY_STALL_US 10000U

typedef pbns_status (*pbns_tpm_sha256)(void *context, pbns_view input,
                                       pbns_buffer digest);

bool pbns_tpm_command_retryable(uint32_t command_result);
bool pbns_tpm_command_retry_delay_us(uint32_t command_result, size_t attempt,
                                     size_t *delay_us);
pbns_status
pbns_tpm_capabilities_validate(const pbns_tpm_capabilities *capabilities);
pbns_status pbns_tpm_identity_template(TPM2B_PUBLIC *output);
pbns_status pbns_tpm_ak_template(TPM2B_PUBLIC *output);
pbns_status pbns_tpm_ek_template(TPM2B_PUBLIC *output);
pbns_status pbns_tpm_srk_template(TPM2B_PUBLIC *output);
pbns_status pbns_tpm_nv_public(TPM2_HANDLE index, pbns_view policy_digest,
                               TPM2B_NV_PUBLIC *output);
pbns_status pbns_tpm_public_name(const TPM2B_PUBLIC *public_area,
                                 pbns_tpm_sha256 sha256, void *sha256_context,
                                 pbns_buffer output, size_t *written);
pbns_status pbns_tpm_public_encode(const TPM2B_PUBLIC *value,
                                   pbns_buffer output, size_t *written);
pbns_status pbns_tpm_public_decode(pbns_view encoded, TPM2B_PUBLIC *value);
pbns_status pbns_tpm_private_encode(const TPM2B_PRIVATE *value,
                                    pbns_buffer output, size_t *written);
pbns_status pbns_tpm_private_decode(pbns_view encoded, TPM2B_PRIVATE *value);
pbns_status pbns_tpm_signature_encode(const TPMT_SIGNATURE *value,
                                      pbns_buffer output, size_t *written);

#endif
