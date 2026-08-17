#ifndef PBNS_IDENTITY_H
#define PBNS_IDENTITY_H

#include "pbns/buffer.h"
#include "pbns/status.h"

typedef enum pbns_identity_assurance {
  PBNS_IDENTITY_INVALID = 0,
  PBNS_IDENTITY_TPM_VERIFIED = 1,
  PBNS_IDENTITY_TPM_UNVERIFIED_EK = 2,
  PBNS_IDENTITY_SOFTWARE = 3
} pbns_identity_assurance;

typedef struct pbns_identity_ops pbns_identity_ops;
typedef struct pbns_identity pbns_identity;

struct pbns_identity_ops {
  pbns_status (*public_cose_key)(void *context, pbns_buffer output,
                                 size_t *written);
  pbns_status (*fingerprint)(void *context, pbns_buffer output);
  pbns_status (*sign_digest)(void *context, pbns_view digest,
                             pbns_buffer signature, size_t *written);
  pbns_status (*random)(void *context, pbns_buffer output);
  void (*close)(void *context);
};

struct pbns_identity {
  const pbns_identity_ops *ops;
  void *context;
  pbns_identity_assurance assurance;
};

pbns_status pbns_identity_open(pbns_identity *identity,
                               const pbns_identity_ops *ops, void *context,
                               pbns_identity_assurance assurance);
void pbns_identity_close(pbns_identity *identity);
pbns_status pbns_identity_public_cose_key(const pbns_identity *identity,
                                          pbns_buffer output, size_t *written);
pbns_status pbns_identity_fingerprint(const pbns_identity *identity,
                                      pbns_buffer output);
pbns_status pbns_identity_sign(const pbns_identity *identity, pbns_view digest,
                               pbns_buffer signature, size_t *written);
pbns_status pbns_identity_random(const pbns_identity *identity,
                                 pbns_buffer output);
pbns_identity_assurance
pbns_identity_assurance_level(const pbns_identity *identity);

#endif
