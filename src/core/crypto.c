#include "pbns/crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static bool view_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool buffer_valid(pbns_buffer buffer) {
  return buffer.len == 0U && (buffer.ptr != NULL || buffer.cap == 0U);
}

static bool ranges_overlap(pbns_view input, pbns_buffer output) {
  if (input.len == 0U || output.cap == 0U) {
    return false;
  }
  const uintptr_t input_start = (uintptr_t)input.ptr;
  const uintptr_t output_start = (uintptr_t)output.ptr;
  if (input.ptr == NULL || output.ptr == NULL ||
      input.len > UINTPTR_MAX - input_start ||
      output.cap > UINTPTR_MAX - output_start) {
    return true;
  }
  return input_start < output_start + output.cap &&
         output_start < input_start + input.len;
}

static pbns_status require_bounded_output(pbns_status status,
                                          pbns_buffer output,
                                          size_t *written) {
  if (status == PBNS_OK && (*written == 0U || *written > output.cap)) {
    volatile uint8_t *cursor = output.ptr;
    for (size_t index = 0U; index < output.cap; ++index) {
      cursor[index] = 0U;
    }
    *written = 0U;
    return PBNS_ERR_LIMIT;
  }
  return status;
}

void pbns_crypto_reset(pbns_crypto *crypto) {
  if (crypto != NULL) {
    *crypto = (pbns_crypto){0};
  }
}

pbns_status pbns_sign1_sign(const pbns_crypto *crypto, pbns_view payload,
                            pbns_view external_aad, pbns_buffer output,
                            size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (crypto == NULL || crypto->ops == NULL ||
      crypto->ops->sign1_sign == NULL || crypto->context == NULL ||
      !view_valid(payload) || !view_valid(external_aad) ||
      !buffer_valid(output) || ranges_overlap(payload, output) ||
      ranges_overlap(external_aad, output)) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = crypto->ops->sign1_sign(
      crypto->context, payload, external_aad, output, written);
  return require_bounded_output(status, output, written);
}

pbns_status pbns_sign1_sign_profile(const pbns_crypto *crypto,
                                    pbns_view payload,
                                    pbns_view external_aad,
                                    pbns_view kid,
                                    pbns_buffer output,
                                    size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (crypto == NULL || crypto->ops == NULL ||
      crypto->ops->sign1_sign_profile == NULL || crypto->context == NULL ||
      !view_valid(payload) || !view_valid(external_aad) || !view_valid(kid) ||
      kid.len == 0U || !buffer_valid(output) || ranges_overlap(payload, output) ||
      ranges_overlap(external_aad, output) || ranges_overlap(kid, output)) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = crypto->ops->sign1_sign_profile(
      crypto->context, payload, external_aad, kid, output, written);
  return require_bounded_output(status, output, written);
}

pbns_status pbns_sign1_verify(const pbns_crypto *crypto, pbns_view cose,
                              pbns_view external_aad, pbns_view *payload) {
  if (payload == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *payload = (pbns_view){0};
  if (crypto == NULL || crypto->ops == NULL ||
      crypto->ops->sign1_verify == NULL || crypto->context == NULL ||
      !view_valid(cose) || !view_valid(external_aad)) {
    return PBNS_ERR_ARGUMENT;
  }
  return crypto->ops->sign1_verify(crypto->context, cose, external_aad,
                                   payload);
}

pbns_status pbns_sign1_verify_profile(const pbns_crypto *crypto,
                                      pbns_view cose,
                                      pbns_view external_aad,
                                      pbns_view expected_kid,
                                      pbns_view *payload) {
  if (payload == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *payload = (pbns_view){0};
  if (crypto == NULL || crypto->ops == NULL ||
      crypto->ops->sign1_verify_profile == NULL || crypto->context == NULL ||
      !view_valid(cose) || !view_valid(external_aad) ||
      !view_valid(expected_kid) || expected_kid.len == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  return crypto->ops->sign1_verify_profile(
      crypto->context, cose, external_aad, expected_kid, payload);
}
