#ifndef PBNS_CONTROLLED_BASELINE_H
#define PBNS_CONTROLLED_BASELINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/inventory.h"
#include "pbns/status.h"

#define PBNS_CONTROLLED_BASELINE_DIGEST_SIZE 32U

typedef pbns_status (*pbns_controlled_baseline_hash_fn)(
    void *Context, const pbns_view *Parts, size_t PartCount,
    uint8_t Digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE]);

typedef struct pbns_controlled_baseline {
  uint8_t measurement_digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE];
  bool secure_boot;
  bool setup_mode;
  uint8_t db_digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE];
  uint8_t dbx_digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE];
  uint8_t firmware_digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE];
  uint64_t memory_mib;
  uint64_t storage_gib;
  uint64_t block_devices;
  uint64_t memory_mib_delta;
  uint64_t storage_gib_delta;
  uint64_t block_device_delta;
} pbns_controlled_baseline;

pbns_status pbns_controlled_baseline_from_inventory(
    const uint8_t MeasurementDigest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE],
    const pbns_inventory_report *Inventory,
    pbns_controlled_baseline_hash_fn Hash, void *HashContext,
    pbns_controlled_baseline *Value);

pbns_status pbns_controlled_baseline_firmware_identity(
    pbns_view Vendor, pbns_view Version, pbns_controlled_baseline_hash_fn Hash,
    void *HashContext, uint8_t Digest[PBNS_CONTROLLED_BASELINE_DIGEST_SIZE]);

pbns_status
pbns_controlled_baseline_encode(const pbns_controlled_baseline *Value,
                                pbns_buffer Output, size_t *Written);

#endif
