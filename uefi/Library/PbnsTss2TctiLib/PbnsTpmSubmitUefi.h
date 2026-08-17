#ifndef PBNS_TPM_SUBMIT_UEFI_H
#define PBNS_TPM_SUBMIT_UEFI_H

#include <stdint.h>

#include "PbnsTpmSubmit.h"
#include "pbns/status.h"

#define PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE 16U

pbns_status
pbns_tpm_submit_uefi_init(uint8_t storage[PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE],
                          pbns_tpm_submit *submit, void **submit_context);
void pbns_tpm_submit_uefi_final(
    uint8_t storage[PBNS_TPM_SUBMIT_UEFI_STORAGE_SIZE]);

#endif
