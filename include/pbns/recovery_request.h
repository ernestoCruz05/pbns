#ifndef PBNS_RECOVERY_REQUEST_H
#define PBNS_RECOVERY_REQUEST_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_RECOVERY_REQUEST_DOMAIN "PBNS-RECOVERY-REQUEST-v1"
#define PBNS_RECOVERY_REQUEST_AAD "PBNS-RECOVERY-REQUEST-AAD-v1"
#define PBNS_RECOVERY_REQUEST_VERSION UINT64_C(1)
#define PBNS_RECOVERY_REQUEST_SERVICE UINT64_C(2)
#define PBNS_RECOVERY_REQUEST_ID_SIZE 16U
#define PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE 32U
#define PBNS_RECOVERY_REQUEST_NONCE_SIZE 32U
#define PBNS_RECOVERY_REQUEST_DIGEST_SIZE 32U
#define PBNS_RECOVERY_REQUEST_ENCODED_MAX_SIZE 256U

typedef enum pbns_recovery_operation {
  PBNS_RECOVERY_OPERATION_INVALID = 0,
  PBNS_RECOVERY_OPERATION_MANIFEST = 1,
  PBNS_RECOVERY_OPERATION_ARTIFACT = 2
} pbns_recovery_operation;

typedef struct pbns_recovery_request {
  pbns_recovery_operation operation;
  uint8_t request_id[PBNS_RECOVERY_REQUEST_ID_SIZE];
  uint8_t host_fingerprint[PBNS_RECOVERY_REQUEST_FINGERPRINT_SIZE];
  uint8_t nonce[PBNS_RECOVERY_REQUEST_NONCE_SIZE];
  uint8_t artifact_digest[PBNS_RECOVERY_REQUEST_DIGEST_SIZE];
} pbns_recovery_request;

pbns_status pbns_recovery_request_encode(const pbns_recovery_request *request,
                                         pbns_buffer output, size_t *written);

pbns_status pbns_recovery_request_decode(pbns_view encoded,
                                         pbns_buffer canonical_scratch,
                                         pbns_recovery_request *request);

#endif
