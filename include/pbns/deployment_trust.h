#ifndef PBNS_DEPLOYMENT_TRUST_H
#define PBNS_DEPLOYMENT_TRUST_H

#include "pbns/buffer.h"
#include "pbns/tls_transport.h"

typedef struct pbns_deployment_public_key {
  pbns_view kid;
  pbns_view x;
  pbns_view y;
} pbns_deployment_public_key;

typedef struct pbns_deployment_trust {
  pbns_tls_client_config tls;
  pbns_deployment_public_key time;
  pbns_deployment_public_key challenge;
  pbns_deployment_public_key recipient;
  pbns_deployment_public_key receipt;
} pbns_deployment_trust;

#endif
