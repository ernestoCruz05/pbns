#ifndef PBNS_RECOVERY_STREAM_H
#define PBNS_RECOVERY_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/frame.h"
#include "pbns/recovery_manifest.h"

typedef struct pbns_recovery_hash_ops {
  pbns_status (*begin)(void *context);
  pbns_status (*update)(void *context, pbns_view data);
  pbns_status (*finish)(void *context,
                        uint8_t digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE]);
  void (*clear)(void *context);
} pbns_recovery_hash_ops;

typedef struct pbns_recovery_ack {
  bool required;
  uint32_t next_sequence;
  uint32_t window;
} pbns_recovery_ack;

typedef struct pbns_recovery_stream {
  pbns_request_id request_id;
  uint8_t *pages;
  size_t image_size;
  size_t offset;
  uint8_t expected_digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE];
  uint32_t next_sequence;
  uint32_t records_since_ack;
  const pbns_recovery_hash_ops *hash_ops;
  void *hash_context;
  bool hash_active;
  bool initialized;
  bool complete;
  bool failed;
} pbns_recovery_stream;

pbns_status pbns_recovery_stream_init(
    pbns_recovery_stream *stream, pbns_request_id request_id,
    pbns_buffer exact_pages,
    const uint8_t expected_digest[PBNS_RECOVERY_MANIFEST_DIGEST_SIZE],
    const pbns_recovery_hash_ops *hash_ops, void *hash_context);

pbns_status pbns_recovery_stream_accept(pbns_recovery_stream *stream,
                                        const pbns_frame *frame,
                                        pbns_view payload,
                                        pbns_recovery_ack *ack);

pbns_status pbns_recovery_stream_complete(pbns_recovery_stream *stream,
                                          const pbns_frame *frame,
                                          pbns_view payload);

/* Elimina os bytes recebidos e o estado do resumo, mas nunca liberta as
 * páginas. */
void pbns_recovery_stream_reset(pbns_recovery_stream *stream);

#endif
