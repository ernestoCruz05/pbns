#ifndef PBNS_TPM_SUBMIT_H
#define PBNS_TPM_SUBMIT_H

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_TPM_SUBMIT_RESPONSE_HEADER_SIZE 10U
#define PBNS_TPM_SUBMIT_RESPONSE_MAX 4096U

static inline pbns_status pbns_tpm_response_size(const uint8_t *response,
                                                  size_t capacity,
                                                  size_t *response_size) {
  if (response == NULL || response_size == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *response_size = 0U;
  if (capacity < PBNS_TPM_SUBMIT_RESPONSE_HEADER_SIZE ||
      capacity > PBNS_TPM_SUBMIT_RESPONSE_MAX) {
    return PBNS_ERR_FORMAT;
  }
  const uint32_t declared = ((uint32_t)response[2] << 24U) |
                            ((uint32_t)response[3] << 16U) |
                            ((uint32_t)response[4] << 8U) |
                            (uint32_t)response[5];
  if (declared < PBNS_TPM_SUBMIT_RESPONSE_HEADER_SIZE ||
      declared > capacity || declared > PBNS_TPM_SUBMIT_RESPONSE_MAX) {
    return PBNS_ERR_FORMAT;
  }
  *response_size = (size_t)declared;
  return PBNS_OK;
}

typedef pbns_status (*pbns_tpm_submit)(void *context, pbns_view command,
                                       pbns_buffer response,
                                       size_t *response_length);

#endif
