#ifndef PBNS_PROXY_DIAGNOSTIC_STORAGE_H
#define PBNS_PROXY_DIAGNOSTIC_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/status.h"
#include "pbns_proxy/credentials.h"

typedef struct pbns_diagnostic_storage {
  pbns_credentials_storage credentials;
  const uint8_t *flash;
  size_t flash_size;
} pbns_diagnostic_storage;

pbns_status pbns_diagnostic_storage_init(pbns_diagnostic_storage *storage,
                                         const uint8_t *flash,
                                         size_t flash_size);

#endif
