#include "pbns_proxy/diagnostic_storage.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static pbns_status diagnostic_read(void *context, size_t offset,
                                   pbns_buffer destination) {
  const pbns_diagnostic_storage *const storage = context;
  if (storage == NULL || storage->flash == NULL || destination.ptr == NULL ||
      destination.len != 0U || offset > storage->flash_size ||
      destination.cap > storage->flash_size - offset) {
    return PBNS_ERR_ARGUMENT;
  }
  memcpy(destination.ptr, storage->flash + offset, destination.cap);
  return PBNS_OK;
}

static pbns_status diagnostic_erase(void *context, size_t offset,
                                    size_t length) {
  (void)context;
  (void)offset;
  (void)length;
  return PBNS_ERR_STATE;
}

static pbns_status diagnostic_program(void *context, size_t offset,
                                      pbns_view source) {
  (void)context;
  (void)offset;
  (void)source;
  return PBNS_ERR_STATE;
}

static const pbns_credentials_storage_ops diagnostic_ops = {
    .read = diagnostic_read,
    .erase = diagnostic_erase,
    .program = diagnostic_program,
};

pbns_status pbns_diagnostic_storage_init(pbns_diagnostic_storage *storage,
                                         const uint8_t *flash,
                                         size_t flash_size) {
  if (storage != NULL) {
    *storage = (pbns_diagnostic_storage){0};
  }
  const size_t credential_bytes = (size_t)PBNS_CREDENTIALS_SECTOR_SIZE *
                                  (size_t)PBNS_CREDENTIALS_SLOT_COUNT;
  if (storage == NULL || flash == NULL || flash_size < credential_bytes ||
      flash_size % PBNS_CREDENTIALS_SECTOR_SIZE != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  storage->flash = flash;
  storage->flash_size = flash_size;
  storage->credentials = (pbns_credentials_storage){
      .ops = &diagnostic_ops,
      .context = storage,
      .slot_offsets =
          {
              flash_size - credential_bytes,
              flash_size - PBNS_CREDENTIALS_SECTOR_SIZE,
          },
  };
  return PBNS_OK;
}
