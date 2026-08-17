#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pbns/buffer.h"
#include "pbns/status.h"
#include "pbns_proxy/credentials.h"

#define PIN_TEXT_MAX (PBNS_CREDENTIALS_SPKI_SIZE * 2U + 2U)

typedef struct validation_paths {
  const char *record;
  const char *pin;
} validation_paths;

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

static bool read_bounded(const char *path, uint8_t *output, size_t capacity,
                         size_t *length) {
  FILE *stream = fopen(path, "rb");
  if (stream == NULL) {
    return false;
  }
  const size_t count = fread(output, 1U, capacity, stream);
  bool valid = !ferror(stream) && count < capacity;
  if (fclose(stream) != 0) {
    valid = false;
  }
  if (!valid) {
    return false;
  }
  *length = count;
  return true;
}

static bool hex_nibble(uint8_t character, uint8_t *value) {
  if (character >= (uint8_t)'0' && character <= (uint8_t)'9') {
    *value = (uint8_t)(character - (uint8_t)'0');
    return true;
  }
  if (character >= (uint8_t)'a' && character <= (uint8_t)'f') {
    *value = (uint8_t)(character - (uint8_t)'a' + UINT8_C(10));
    return true;
  }
  return false;
}

static bool decode_expected_pin(const char *path,
                                uint8_t pin[PBNS_CREDENTIALS_SPKI_SIZE]) {
  uint8_t text[PIN_TEXT_MAX + 1U] = {0};
  size_t length = 0U;
  if (!read_bounded(path, text, sizeof(text), &length)) {
    return false;
  }
  while (length > 0U &&
         (text[length - 1U] == (uint8_t)'\n' ||
          text[length - 1U] == (uint8_t)'\r')) {
    --length;
  }
  if (length != (size_t)PBNS_CREDENTIALS_SPKI_SIZE * 2U) {
    secure_zero(text, sizeof(text));
    return false;
  }
  for (size_t index = 0U; index < PBNS_CREDENTIALS_SPKI_SIZE; ++index) {
    uint8_t high = 0U;
    uint8_t low = 0U;
    if (!hex_nibble(text[index * 2U], &high) ||
        !hex_nibble(text[index * 2U + 1U], &low)) {
      secure_zero(text, sizeof(text));
      secure_zero(pin, PBNS_CREDENTIALS_SPKI_SIZE);
      return false;
    }
    pin[index] = (uint8_t)((uint8_t)(high << 4U) | low);
  }
  secure_zero(text, sizeof(text));
  return true;
}

static bool pins_equal(const uint8_t left[PBNS_CREDENTIALS_SPKI_SIZE],
                       const uint8_t right[PBNS_CREDENTIALS_SPKI_SIZE]) {
  uint8_t difference = 0U;
  for (size_t index = 0U; index < PBNS_CREDENTIALS_SPKI_SIZE; ++index) {
    difference = (uint8_t)(difference | (uint8_t)(left[index] ^ right[index]));
  }
  return difference == 0U;
}

static bool validate_record(validation_paths paths) {
  uint8_t encoded[PBNS_CREDENTIALS_CBOR_MAX + 1U] = {0};
  uint8_t expected_pin[PBNS_CREDENTIALS_SPKI_SIZE] = {0};
  pbns_credentials credentials = {0};
  size_t encoded_length = 0U;
  bool valid =
      read_bounded(paths.record, encoded, sizeof(encoded), &encoded_length);
  if (valid) {
    valid = decode_expected_pin(paths.pin, expected_pin);
  }
  if (valid) {
    valid = pbns_credentials_decode_cbor(
                (pbns_view){encoded, encoded_length}, &credentials) == PBNS_OK;
  }
  if (valid) {
    valid = pins_equal(credentials.spki_sha256, expected_pin);
  }
  secure_zero(&credentials, sizeof(credentials));
  secure_zero(expected_pin, sizeof(expected_pin));
  secure_zero(encoded, sizeof(encoded));
  return valid;
}

static bool self_test(void) {
  static const uint8_t ssid[] = "test-network";
  static const uint8_t psk[] = "private-passphrase";
  static const char hostname[] = "192.0.2.10";
  pbns_credentials source = {0};
  pbns_credentials decoded = {0};
  uint8_t encoded[PBNS_CREDENTIALS_CBOR_MAX] = {0};
  size_t written = 0U;
  memcpy(source.ssid, ssid, sizeof(ssid) - 1U);
  source.ssid_len = sizeof(ssid) - 1U;
  memcpy(source.psk, psk, sizeof(psk) - 1U);
  source.psk_len = sizeof(psk) - 1U;
  memcpy(source.hostname, hostname, sizeof(hostname) - 1U);
  source.hostname_len = sizeof(hostname) - 1U;
  source.port = UINT16_C(8443);
  memset(source.spki_sha256, 0x5a, sizeof(source.spki_sha256));
  bool valid = pbns_credentials_encode_cbor(
                   &source, (pbns_buffer){encoded, 0U, sizeof(encoded)},
                   &written) == PBNS_OK;
  if (valid) {
    valid = pbns_credentials_decode_cbor((pbns_view){encoded, written},
                                         &decoded) == PBNS_OK;
  }
  if (valid) {
    valid = decoded.ssid_len == source.ssid_len &&
            decoded.psk_len == source.psk_len &&
            decoded.hostname_len == source.hostname_len &&
            decoded.port == source.port &&
            memcmp(decoded.ssid, source.ssid, source.ssid_len) == 0 &&
            memcmp(decoded.psk, source.psk, source.psk_len) == 0 &&
            memcmp(decoded.hostname, source.hostname, source.hostname_len) == 0 &&
            pins_equal(decoded.spki_sha256, source.spki_sha256);
  }
  secure_zero(&source, sizeof(source));
  secure_zero(&decoded, sizeof(decoded));
  secure_zero(encoded, sizeof(encoded));
  return valid;
}

int main(int argc, char **argv) {
  bool valid = false;
  if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
    valid = self_test();
  } else if (argc == 3) {
    valid = validate_record((validation_paths){argv[1], argv[2]});
  }
  if (!valid) {
    if (fputs("Pico credential validation failed\n", stderr) == EOF) {
      return 1;
    }
    return 1;
  }
  if (fputs("PICO CREDENTIAL RECORD VALID\n", stdout) == EOF) {
    return 1;
  }
  return 0;
}
