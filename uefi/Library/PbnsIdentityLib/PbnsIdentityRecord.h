#ifndef PBNS_IDENTITY_RECORD_H
#define PBNS_IDENTITY_RECORD_H

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_IDENTITY_RECORD_VERSION 1U
#define PBNS_IDENTITY_CURVE_P256 1U
#define PBNS_IDENTITY_RECORD_HEADER_SIZE 24U
#define PBNS_IDENTITY_PRIVATE_DER_MAX 512U
#define PBNS_IDENTITY_PUBLIC_COSE_MAX 128U
#define PBNS_IDENTITY_FINGERPRINT_SIZE 32U
#define PBNS_IDENTITY_RECORD_MAX_SIZE                                          \
  (PBNS_IDENTITY_RECORD_HEADER_SIZE + PBNS_IDENTITY_PRIVATE_DER_MAX +          \
   PBNS_IDENTITY_PUBLIC_COSE_MAX + PBNS_IDENTITY_FINGERPRINT_SIZE)

typedef struct pbns_identity_record {
  pbns_view private_der;
  pbns_view public_cose_key;
  pbns_view fingerprint;
} pbns_identity_record;

pbns_status pbns_identity_record_encode(pbns_view private_der,
                                        pbns_view public_cose_key,
                                        pbns_view fingerprint,
                                        pbns_buffer output, size_t *written);
pbns_status pbns_identity_record_decode(pbns_view encoded,
                                        pbns_identity_record *record);

#endif
