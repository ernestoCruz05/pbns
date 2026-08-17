#ifndef PBNS_TPM_STORAGE_H
#define PBNS_TPM_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_TPM_STORAGE_VERSION 1U
#define PBNS_TPM_STORAGE_HEADER_SIZE 52U
#define PBNS_TPM_STORAGE_MAX_SIZE 16384U
#define PBNS_TPM_PUBLIC_MAX 1024U
#define PBNS_TPM_PRIVATE_MAX 2048U
#define PBNS_TPM_NAME_SIZE 34U
#define PBNS_TPM_EK_CHAIN_DIGEST_SIZE 32U

#define PBNS_TPM_VARIABLE_NON_VOLATILE UINT32_C(0x00000001)
#define PBNS_TPM_VARIABLE_BOOTSERVICE UINT32_C(0x00000002)
#define PBNS_TPM_VARIABLE_RUNTIME UINT32_C(0x00000004)
#define PBNS_TPM_STORAGE_VARIABLE_ATTRIBUTES                                   \
  (PBNS_TPM_VARIABLE_NON_VOLATILE | PBNS_TPM_VARIABLE_BOOTSERVICE)

typedef struct pbns_tpm_storage_record {
  uint32_t manufacturer;
  uint32_t firmware1;
  uint32_t firmware2;
  pbns_view ek_public;
  pbns_view ek_name;
  pbns_view srk_public;
  pbns_view srk_name;
  pbns_view ak_public;
  pbns_view ak_private;
  pbns_view ak_name;
  pbns_view identity_public;
  pbns_view identity_private;
  pbns_view identity_name;
  pbns_view ek_chain_digest;
} pbns_tpm_storage_record;

typedef pbns_status (*pbns_tpm_storage_name)(void *context,
                                             pbns_view public_blob,
                                             pbns_buffer output);

pbns_status pbns_tpm_storage_encode(const pbns_tpm_storage_record *record,
                                    pbns_buffer output, size_t *written);
pbns_status pbns_tpm_storage_decode(pbns_view encoded,
                                    pbns_tpm_storage_record *record);
pbns_status
pbns_tpm_storage_validate_names(const pbns_tpm_storage_record *record,
                                pbns_tpm_storage_name compute_name,
                                void *compute_context);

#endif
