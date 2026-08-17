#ifndef PBNS_RECOVERY_CLIENT_LIB_H
#define PBNS_RECOVERY_CLIENT_LIB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_RECOVERY_CLIENT_DIGEST_SIZE 32U
#define PBNS_RECOVERY_CLIENT_MAX_ARTIFACT_SIZE (UINT64_C(256) * 1024U * 1024U)

typedef enum PBNS_RECOVERY_CLIENT_STATE {
  PBNS_RECOVERY_STATE_CONFIRM = 0,
  PBNS_RECOVERY_STATE_TIME,
  PBNS_RECOVERY_STATE_MANIFEST,
  PBNS_RECOVERY_STATE_ALLOCATE,
  PBNS_RECOVERY_STATE_STREAM,
  PBNS_RECOVERY_STATE_DIGEST,
  PBNS_RECOVERY_STATE_LOAD_VERIFY,
  PBNS_RECOVERY_STATE_ADVANCE_VERSION,
  PBNS_RECOVERY_STATE_START,
  PBNS_RECOVERY_STATE_FAILED
} PBNS_RECOVERY_CLIENT_STATE;

typedef struct PBNS_RECOVERY_PLAN {
  uint64_t artifact_size;
  uint64_t target_version;
  uint8_t artifact_digest[PBNS_RECOVERY_CLIENT_DIGEST_SIZE];
  pbns_view version_authorization;
} PBNS_RECOVERY_PLAN;

typedef struct PBNS_RECOVERY_CLIENT_RESULT {
  PBNS_RECOVERY_CLIENT_STATE state;
  PBNS_RECOVERY_CLIENT_STATE failed_stage;
  pbns_status status;
} PBNS_RECOVERY_CLIENT_RESULT;

typedef struct PBNS_RECOVERY_CLIENT_OPS {
  pbns_status (*confirm)(void *context, bool *accepted);
  pbns_status (*platform_ready)(void *context);
  pbns_status (*trusted_time)(void *context);
  pbns_status (*verified_manifest)(void *context, PBNS_RECOVERY_PLAN *plan);
  pbns_status (*allocate_pages)(void *context, uint64_t size, void **image);
  pbns_status (*stream_image)(void *context, void *image, uint64_t size);
  pbns_status (*verify_digest)(void *context, pbns_view image,
                               const uint8_t expected_digest[32]);
  pbns_status (*read_version)(void *context, uint64_t *version);
  pbns_status (*load_image)(void *context, pbns_buffer image,
                            void **image_handle);
  pbns_status (*advance_version)(void *context, uint64_t current_version,
                                 uint64_t target_version,
                                 pbns_view authorization);
  pbns_status (*start_image)(void *context, void *image_handle);
  pbns_status (*unload_image)(void *context, void *image_handle);
  pbns_status (*free_pages)(void *context, void *image, uint64_t size);
  void (*state_changed)(void *context, PBNS_RECOVERY_CLIENT_STATE state);
  void (*failed)(void *context, PBNS_RECOVERY_CLIENT_STATE stage,
                 pbns_status status);
} PBNS_RECOVERY_CLIENT_OPS;

pbns_status PbnsRecoveryClientRun(const PBNS_RECOVERY_CLIENT_OPS *ops,
                                  void *context,
                                  PBNS_RECOVERY_CLIENT_RESULT *result);

#endif
