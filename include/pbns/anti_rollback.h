#ifndef PBNS_ANTI_ROLLBACK_H
#define PBNS_ANTI_ROLLBACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_ANTI_ROLLBACK_SLOT_COUNT 2U
#define PBNS_ANTI_ROLLBACK_RECORD_SIZE 24U
#define PBNS_ANTI_ROLLBACK_AUTHORIZATION_MAX_SIZE 4096U
#define PBNS_ANTI_ROLLBACK_NO_SLOT SIZE_MAX

typedef enum pbns_anti_rollback_assurance {
  PBNS_ANTI_ROLLBACK_ASSURANCE_INVALID = 0,
  PBNS_ANTI_ROLLBACK_ASSURANCE_TPM = 1,
  PBNS_ANTI_ROLLBACK_ASSURANCE_NVRAM_REDUCED = 2
} pbns_anti_rollback_assurance;

typedef pbns_status (*pbns_anti_rollback_tpm_read_fn)(void *context,
                                                      uint64_t *version);
typedef pbns_status (*pbns_anti_rollback_tpm_advance_fn)(
    void *context, uint64_t current_version, uint64_t target_version,
    pbns_view authorization);
typedef pbns_status (*pbns_anti_rollback_slot_read_fn)(
    void *context, size_t slot, uint8_t record[PBNS_ANTI_ROLLBACK_RECORD_SIZE],
    bool *present);
typedef pbns_status (*pbns_anti_rollback_slot_write_fn)(void *context,
                                                        size_t slot,
                                                        pbns_view record);

typedef struct pbns_anti_rollback {
  pbns_anti_rollback_assurance assurance;
  void *context;
  pbns_anti_rollback_tpm_read_fn tpm_read;
  pbns_anti_rollback_tpm_advance_fn tpm_advance;
  pbns_anti_rollback_slot_read_fn slot_read;
  pbns_anti_rollback_slot_write_fn slot_write;
} pbns_anti_rollback;

typedef struct pbns_anti_rollback_state {
  uint64_t version;
  uint64_t generation;
  size_t active_slot;
  pbns_anti_rollback_assurance assurance;
} pbns_anti_rollback_state;

/* O contexto e os callbacks são emprestados e têm de sobreviver ao controlador.
 */
pbns_status pbns_anti_rollback_init_tpm(
    pbns_anti_rollback *controller, pbns_anti_rollback_tpm_read_fn read,
    pbns_anti_rollback_tpm_advance_fn advance, void *context);

pbns_status pbns_anti_rollback_init_nvram(
    pbns_anti_rollback *controller, pbns_anti_rollback_slot_read_fn read,
    pbns_anti_rollback_slot_write_fn write, void *context);

pbns_status pbns_anti_rollback_read(const pbns_anti_rollback *controller,
                                    pbns_anti_rollback_state *state);

/* A autorização é apenas consultada durante a chamada. */
pbns_status pbns_anti_rollback_advance(const pbns_anti_rollback *controller,
                                       uint64_t target_version,
                                       pbns_view authorization,
                                       pbns_anti_rollback_state *state);

#endif
