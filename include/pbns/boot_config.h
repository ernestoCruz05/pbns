#ifndef PBNS_BOOT_CONFIG_H
#define PBNS_BOOT_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_BOOT_CONFIG_HEADER_SIZE 16U
#define PBNS_BOOT_CONFIG_PATH_CAP 4096U
#define PBNS_BOOT_CONFIG_ENCODED_CAP                                           \
  (PBNS_BOOT_CONFIG_HEADER_SIZE + PBNS_BOOT_CONFIG_PATH_CAP)
#define PBNS_BOOT_FAILURE_ENCODED_SIZE 24U

typedef struct pbns_boot_config {
  uint16_t normal_boot_option;
  pbns_view recovery_device_path;
} pbns_boot_config;

typedef struct pbns_boot_failure {
  uint8_t stage;
  uint64_t platform_status;
} pbns_boot_failure;

pbns_status pbns_boot_config_encode(const pbns_boot_config *config,
                                    pbns_buffer output, size_t *written);
pbns_status pbns_boot_config_decode(pbns_view encoded, pbns_buffer path_storage,
                                    pbns_boot_config *config);
pbns_status pbns_boot_failure_encode(const pbns_boot_failure *failure,
                                     pbns_buffer output, size_t *written);
pbns_status pbns_boot_failure_decode(pbns_view encoded,
                                     pbns_boot_failure *failure);

#endif
