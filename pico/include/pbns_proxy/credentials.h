#ifndef PBNS_PROXY_CREDENTIALS_H
#define PBNS_PROXY_CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_CREDENTIALS_VERSION UINT64_C(1)
#define PBNS_CREDENTIALS_SSID_MAX 32U
#define PBNS_CREDENTIALS_PSK_MAX 63U
#define PBNS_CREDENTIALS_HOSTNAME_MAX 253U
#define PBNS_CREDENTIALS_SPKI_SIZE 32U
#define PBNS_CREDENTIALS_CBOR_MAX 448U
#define PBNS_CREDENTIALS_SLOT_COUNT 2U
#define PBNS_CREDENTIALS_PAGE_SIZE 256U
#define PBNS_CREDENTIALS_SECTOR_SIZE 4096U

typedef struct pbns_credentials {
  uint8_t ssid[PBNS_CREDENTIALS_SSID_MAX];
  size_t ssid_len;
  uint8_t psk[PBNS_CREDENTIALS_PSK_MAX];
  size_t psk_len;
  char hostname[PBNS_CREDENTIALS_HOSTNAME_MAX + 1U];
  size_t hostname_len;
  uint16_t port;
  uint8_t spki_sha256[PBNS_CREDENTIALS_SPKI_SIZE];
} pbns_credentials;

typedef struct pbns_credentials_storage_ops {
  pbns_status (*read)(void *context, size_t offset, pbns_buffer destination);
  pbns_status (*erase)(void *context, size_t offset, size_t length);
  pbns_status (*program)(void *context, size_t offset, pbns_view source);
} pbns_credentials_storage_ops;

typedef struct pbns_credentials_storage {
  const pbns_credentials_storage_ops *ops;
  void *context;
  size_t slot_offsets[PBNS_CREDENTIALS_SLOT_COUNT];
} pbns_credentials_storage;

pbns_status pbns_credentials_decode_cbor(pbns_view encoded,
                                         pbns_credentials *credentials);
pbns_status pbns_credentials_encode_cbor(const pbns_credentials *credentials,
                                         pbns_buffer output, size_t *written);
pbns_status pbns_credentials_load(const pbns_credentials_storage *storage,
                                  pbns_credentials *credentials);
pbns_status pbns_credentials_store(const pbns_credentials_storage *storage,
                                   const pbns_credentials *credentials);
pbns_status pbns_credentials_clear(const pbns_credentials_storage *storage);

#endif
