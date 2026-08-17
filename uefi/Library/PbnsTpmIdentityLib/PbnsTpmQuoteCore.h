#ifndef PBNS_TPM_QUOTE_CORE_H
#define PBNS_TPM_QUOTE_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tss2/tss2_sys.h>

#include "pbns/buffer.h"
#include "pbns/measured_boot.h"
#include "pbns/status.h"

typedef TSS2_RC (*pbns_tpm_quote_command_fn)(
    void *context, TPM2_HANDLE ak_handle,
    const TSS2L_SYS_AUTH_COMMAND *auth,
    const TPM2B_DATA *qualifying_data, const TPMT_SIG_SCHEME *scheme,
    const TPML_PCR_SELECTION *selection, TPM2B_ATTEST *quoted,
    TPMT_SIGNATURE *signature);
typedef bool (*pbns_tpm_quote_retry_fn)(void *context, TSS2_RC result,
                                        size_t attempt);

pbns_status pbns_tpm_quote_core(
    TPM2_HANDLE ak_handle, pbns_measured_boot_selection selection,
    const uint8_t qualifying_data[32], pbns_tpm_quote_command_fn command,
    void *command_context, pbns_tpm_quote_retry_fn retry,
    void *retry_context, pbns_buffer quote, size_t *quote_size,
    pbns_buffer signature, size_t *signature_size, uint32_t *command_result);

#endif
