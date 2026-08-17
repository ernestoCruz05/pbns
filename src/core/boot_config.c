#include "pbns/boot_config.h"

#include <stdbool.h>

#include "pbns/crc32c.h"

#define PBNS_BOOT_CONFIG_VERSION 1U
#define PBNS_BOOT_CONFIG_CRC_OFFSET 12U

static const uint8_t boot_config_magic[4] = {'P', 'B', 'C', '1'};
static const uint8_t boot_failure_magic[4] = {'P', 'B', 'F', '1'};

static void copy_bytes(uint8_t *destination, const uint8_t *source,
                       size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    destination[index] = source[index];
  }
}

static void zero_bytes(uint8_t *destination, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    destination[index] = 0U;
  }
}

static bool bytes_equal(const uint8_t *left, const uint8_t *right,
                        size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    if (left[index] != right[index]) {
      return false;
    }
  }
  return true;
}

static uint16_t read_uint16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8U) | (uint16_t)input[1]);
}

static uint32_t read_uint32(const uint8_t *input) {
  return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) |
         ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}

static void write_uint16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8U);
  output[1] = (uint8_t)value;
}

static void write_uint32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value >> 24U);
  output[1] = (uint8_t)(value >> 16U);
  output[2] = (uint8_t)(value >> 8U);
  output[3] = (uint8_t)value;
}

static uint64_t read_uint64(const uint8_t *input) {
  uint64_t value = 0U;
  for (size_t index = 0U; index < sizeof(value); ++index) {
    value = (value << 8U) | input[index];
  }
  return value;
}

static void write_uint64(uint8_t *output, uint64_t value) {
  for (size_t index = 0U; index < sizeof(value); ++index) {
    output[index] = (uint8_t)(value >> ((sizeof(value) - 1U - index) * 8U));
  }
}

static uint32_t encoded_crc(uint8_t *encoded, size_t encoded_size) {
  uint8_t saved[4] = {0};
  uint32_t result = 0U;

  copy_bytes(saved, encoded + PBNS_BOOT_CONFIG_CRC_OFFSET, sizeof(saved));
  zero_bytes(encoded + PBNS_BOOT_CONFIG_CRC_OFFSET, sizeof(saved));
  result = pbns_crc32c((pbns_view){encoded, encoded_size});
  copy_bytes(encoded + PBNS_BOOT_CONFIG_CRC_OFFSET, saved, sizeof(saved));
  return result;
}

pbns_status pbns_boot_config_encode(const pbns_boot_config *config,
                                    pbns_buffer output, size_t *written) {
  size_t encoded_size = 0U;
  uint32_t crc = 0U;

  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (config == NULL || output.ptr == NULL || output.len != 0U ||
      config->recovery_device_path.ptr == NULL ||
      config->recovery_device_path.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (config->recovery_device_path.len > PBNS_BOOT_CONFIG_PATH_CAP) {
    return PBNS_ERR_LIMIT;
  }
  encoded_size =
      PBNS_BOOT_CONFIG_HEADER_SIZE + config->recovery_device_path.len;
  if (output.cap < encoded_size) {
    return PBNS_ERR_LIMIT;
  }

  zero_bytes(output.ptr, encoded_size);
  copy_bytes(output.ptr, boot_config_magic, sizeof(boot_config_magic));
  output.ptr[4] = PBNS_BOOT_CONFIG_VERSION;
  write_uint16(output.ptr + 6U, config->normal_boot_option);
  write_uint32(output.ptr + 8U, (uint32_t)config->recovery_device_path.len);
  copy_bytes(output.ptr + PBNS_BOOT_CONFIG_HEADER_SIZE,
             config->recovery_device_path.ptr,
             config->recovery_device_path.len);
  crc = encoded_crc(output.ptr, encoded_size);
  write_uint32(output.ptr + PBNS_BOOT_CONFIG_CRC_OFFSET, crc);
  *written = encoded_size;
  return PBNS_OK;
}

pbns_status pbns_boot_config_decode(pbns_view encoded, pbns_buffer path_storage,
                                    pbns_boot_config *config) {
  uint8_t scratch[PBNS_BOOT_CONFIG_ENCODED_CAP] = {0};
  uint32_t path_size = 0U;
  uint32_t expected_crc = 0U;

  if (config == NULL || encoded.ptr == NULL || path_storage.ptr == NULL ||
      path_storage.len != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  *config = (pbns_boot_config){0};
  if (encoded.len < PBNS_BOOT_CONFIG_HEADER_SIZE ||
      encoded.len > sizeof(scratch)) {
    return PBNS_ERR_FORMAT;
  }
  if (!bytes_equal(encoded.ptr, boot_config_magic, sizeof(boot_config_magic))) {
    return PBNS_ERR_FORMAT;
  }
  if (encoded.ptr[4] != PBNS_BOOT_CONFIG_VERSION) {
    return PBNS_ERR_VERSION;
  }
  if (encoded.ptr[5] != 0U) {
    return PBNS_ERR_FORMAT;
  }
  path_size = read_uint32(encoded.ptr + 8U);
  if (path_size == 0U || path_size > PBNS_BOOT_CONFIG_PATH_CAP ||
      (size_t)path_size != encoded.len - PBNS_BOOT_CONFIG_HEADER_SIZE) {
    return PBNS_ERR_FORMAT;
  }
  if (path_storage.cap < path_size) {
    return PBNS_ERR_LIMIT;
  }
  copy_bytes(scratch, encoded.ptr, encoded.len);
  expected_crc = read_uint32(encoded.ptr + PBNS_BOOT_CONFIG_CRC_OFFSET);
  if (encoded_crc(scratch, encoded.len) != expected_crc) {
    return PBNS_ERR_CRC;
  }
  copy_bytes(path_storage.ptr, encoded.ptr + PBNS_BOOT_CONFIG_HEADER_SIZE,
             path_size);
  config->normal_boot_option = read_uint16(encoded.ptr + 6U);
  config->recovery_device_path = (pbns_view){path_storage.ptr, path_size};
  return PBNS_OK;
}

pbns_status pbns_boot_failure_encode(const pbns_boot_failure *failure,
                                     pbns_buffer output, size_t *written) {
  uint32_t crc = 0U;

  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (failure == NULL || failure->stage == 0U || output.ptr == NULL ||
      output.len != 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  if (output.cap < PBNS_BOOT_FAILURE_ENCODED_SIZE) {
    return PBNS_ERR_LIMIT;
  }
  zero_bytes(output.ptr, PBNS_BOOT_FAILURE_ENCODED_SIZE);
  copy_bytes(output.ptr, boot_failure_magic, sizeof(boot_failure_magic));
  output.ptr[4] = PBNS_BOOT_CONFIG_VERSION;
  output.ptr[5] = failure->stage;
  write_uint64(output.ptr + 16U, failure->platform_status);
  crc = encoded_crc(output.ptr, PBNS_BOOT_FAILURE_ENCODED_SIZE);
  write_uint32(output.ptr + PBNS_BOOT_CONFIG_CRC_OFFSET, crc);
  *written = PBNS_BOOT_FAILURE_ENCODED_SIZE;
  return PBNS_OK;
}

pbns_status pbns_boot_failure_decode(pbns_view encoded,
                                     pbns_boot_failure *failure) {
  uint8_t scratch[PBNS_BOOT_FAILURE_ENCODED_SIZE] = {0};
  if (failure == NULL || encoded.ptr == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *failure = (pbns_boot_failure){0};
  if (encoded.len != sizeof(scratch) ||
      !bytes_equal(encoded.ptr, boot_failure_magic,
                   sizeof(boot_failure_magic))) {
    return PBNS_ERR_FORMAT;
  }
  if (encoded.ptr[4] != PBNS_BOOT_CONFIG_VERSION) {
    return PBNS_ERR_VERSION;
  }
  if (encoded.ptr[5] == 0U) {
    return PBNS_ERR_FORMAT;
  }
  for (size_t index = 6U; index < PBNS_BOOT_CONFIG_CRC_OFFSET; ++index) {
    if (encoded.ptr[index] != 0U) {
      return PBNS_ERR_FORMAT;
    }
  }
  copy_bytes(scratch, encoded.ptr, encoded.len);
  const uint32_t expected_crc =
      read_uint32(encoded.ptr + PBNS_BOOT_CONFIG_CRC_OFFSET);
  if (encoded_crc(scratch, encoded.len) != expected_crc) {
    return PBNS_ERR_CRC;
  }
  failure->stage = encoded.ptr[5];
  failure->platform_status = read_uint64(encoded.ptr + 16U);
  return PBNS_OK;
}
