#ifndef PBNS_ENROLLMENT_TRUST_H
#define PBNS_ENROLLMENT_TRUST_H

#include "pbns/deployment_trust.h"

typedef struct pbns_enrollment_trust {
  pbns_deployment_public_key recipient;
  pbns_deployment_public_key signer;
} pbns_enrollment_trust;

#endif
