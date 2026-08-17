#ifndef PBNS_SOFTWARE_IDENTITY_H
#define PBNS_SOFTWARE_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/identity.h"

#define PBNS_IDENTITY_VARIABLE_ATTRIBUTES UINT32_C(3)
#define PBNS_SOFTWARE_RANDOM_STATE_SIZE 32U

typedef pbns_status (*pbns_identity_store_read)(void *context,
                                                pbns_buffer output,
                                                size_t *written,
                                                uint32_t *attributes);
typedef pbns_status (*pbns_identity_store_write)(void *context, pbns_view value,
                                                 uint32_t attributes);
typedef pbns_status (*pbns_identity_store_remove)(void *context);

typedef struct pbns_identity_store {
  pbns_identity_store_read read;
  pbns_identity_store_write write;
  pbns_identity_store_remove remove;
  void *context;
} pbns_identity_store;

typedef void *(*pbns_identity_allocate)(void *context, size_t size);
typedef void (*pbns_identity_release)(void *context, void *value, size_t size);

typedef struct pbns_identity_memory {
  pbns_identity_allocate allocate;
  pbns_identity_release release;
  void *context;
} pbns_identity_memory;

typedef union pbns_identity_random_state {
  void *pointer_alignment;
  uint64_t integer_alignment;
  uint8_t bytes[PBNS_SOFTWARE_RANDOM_STATE_SIZE];
} pbns_identity_random_state;

typedef pbns_status (*pbns_identity_random_fill)(void *state,
                                                 pbns_buffer output);

typedef struct pbns_software_identity_environment {
  pbns_identity_store store;
  pbns_identity_memory memory;
  pbns_identity_random_fill random_fill;
  pbns_identity_random_state random_state;
} pbns_software_identity_environment;

pbns_status pbns_software_identity_create(
    const pbns_software_identity_environment *environment,
    pbns_identity *identity);
pbns_status pbns_software_identity_open(
    const pbns_software_identity_environment *environment,
    pbns_identity *identity);
pbns_status pbns_software_identity_reset(
    const pbns_software_identity_environment *environment);

#endif
