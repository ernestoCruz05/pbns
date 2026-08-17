#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/tls_handshake_observer.h"
#include "pbns/tls_policy.h"

static size_t add_record(uint8_t *output, size_t offset, const uint8_t *body,
                         size_t body_length) {
  assert(body_length <= UINT16_MAX);
  output[offset++] = UINT8_C(22);
  output[offset++] = UINT8_C(3);
  output[offset++] = UINT8_C(3);
  output[offset++] = (uint8_t)(body_length >> 8U);
  output[offset++] = (uint8_t)body_length;
  memcpy(output + offset, body, body_length);
  return offset + body_length;
}

static size_t add_certificate(uint8_t *output, size_t offset,
                              size_t certificate_length) {
  const size_t list_length = certificate_length + 3U;
  const size_t handshake_length = list_length + 3U;
  output[offset++] = UINT8_C(11);
  output[offset++] = (uint8_t)(handshake_length >> 16U);
  output[offset++] = (uint8_t)(handshake_length >> 8U);
  output[offset++] = (uint8_t)handshake_length;
  output[offset++] = (uint8_t)(list_length >> 16U);
  output[offset++] = (uint8_t)(list_length >> 8U);
  output[offset++] = (uint8_t)list_length;
  output[offset++] = (uint8_t)(certificate_length >> 16U);
  output[offset++] = (uint8_t)(certificate_length >> 8U);
  output[offset++] = (uint8_t)certificate_length;
  for (size_t index = 0U; index < certificate_length; ++index) {
    output[offset++] = (uint8_t)(index + 1U);
  }
  return offset;
}

static void test_valid_certificate_all_fragmentations(void) {
  uint8_t handshake[128] = {0};
  uint8_t records[256] = {0};
  size_t handshake_length = 0U;
  handshake[handshake_length++] = UINT8_C(2);
  handshake[handshake_length++] = 0U;
  handshake[handshake_length++] = 0U;
  handshake[handshake_length++] = 0U;
  handshake_length = add_certificate(handshake, handshake_length, 17U);
  const size_t first = 7U;
  size_t record_length = add_record(records, 0U, handshake, first);
  record_length = add_record(records, record_length, handshake + first,
                             handshake_length - first);

  for (size_t fragment = 1U; fragment <= record_length; ++fragment) {
    pbns_tls_handshake_observer observer;
    pbns_tls_handshake_observer_init(&observer);
    for (size_t offset = 0U; offset < record_length; offset += fragment) {
      const size_t amount =
          record_length - offset < fragment ? record_length - offset : fragment;
      assert(pbns_tls_handshake_observer_observe(
                 &observer, (pbns_view){records + offset, amount}) == PBNS_OK);
    }
    assert(pbns_tls_handshake_observer_complete(&observer));
    const uint8_t encrypted_application_record[] = {23U, 3U, 3U, 0U, 1U, 0xffU};
    assert(pbns_tls_handshake_observer_observe(
               &observer, (pbns_view){encrypted_application_record,
                                      sizeof(encrypted_application_record)}) ==
           PBNS_OK);
  }
}

static void assert_rejected(const uint8_t *input, size_t input_length) {
  pbns_tls_handshake_observer observer;
  pbns_tls_handshake_observer_init(&observer);
  assert(pbns_tls_handshake_observer_observe(
             &observer, (pbns_view){input, input_length}) ==
         PBNS_ERR_AUTHENTICATION);
  assert(!pbns_tls_handshake_observer_complete(&observer));
}

static void test_exact_size_boundaries(void) {
  uint8_t handshake[PBNS_TLS_CERTIFICATE_DER_MAX + 16U] = {0};
  uint8_t record[PBNS_TLS_CERTIFICATE_DER_MAX + 32U] = {0};
  const size_t handshake_length =
      add_certificate(handshake, 0U, PBNS_TLS_CERTIFICATE_DER_MAX);
  const size_t record_length =
      add_record(record, 0U, handshake, handshake_length);
  pbns_tls_handshake_observer observer;
  pbns_tls_handshake_observer_init(&observer);
  assert(pbns_tls_handshake_observer_observe(
             &observer, (pbns_view){record, record_length}) == PBNS_OK);
  assert(pbns_tls_handshake_observer_complete(&observer));

  uint8_t maximum_body[16384] = {0};
  uint8_t maximum_record[16389] = {0};
  const size_t certificate_prefix = add_certificate(maximum_body, 0U, 17U);
  assert(certificate_prefix < sizeof(maximum_body));
  const size_t maximum_record_length =
      add_record(maximum_record, 0U, maximum_body, sizeof(maximum_body));
  pbns_tls_handshake_observer_init(&observer);
  assert(pbns_tls_handshake_observer_observe(
             &observer, (pbns_view){maximum_record, maximum_record_length}) ==
         PBNS_OK);
  assert(pbns_tls_handshake_observer_complete(&observer));

  const uint8_t oversized_record_header[] = {22U, 3U, 3U, 0x40U, 0x01U};
  pbns_tls_handshake_observer_init(&observer);
  assert(pbns_tls_handshake_observer_observe(
             &observer, (pbns_view){oversized_record_header,
                                    sizeof(oversized_record_header)}) ==
         PBNS_ERR_AUTHENTICATION);
}

static void test_rejections(void) {
  uint8_t record[128] = {0};
  uint8_t handshake[64] = {0};

  record[0] = UINT8_C(23);
  record[1] = UINT8_C(3);
  record[2] = UINT8_C(3);
  record[3] = 0U;
  record[4] = 1U;
  record[5] = 0U;
  assert_rejected(record, 6U);

  record[0] = UINT8_C(22);
  record[1] = UINT8_C(3);
  record[2] = UINT8_C(1);
  assert_rejected(record, 5U);

  const uint8_t empty_certificate[] = {11U, 0U, 0U, 3U, 0U, 0U, 0U};
  const size_t empty_length =
      add_record(record, 0U, empty_certificate, sizeof(empty_certificate));
  assert_rejected(record, empty_length);

  const uint8_t inconsistent[] = {11U, 0U, 0U, 7U, 0U, 0U, 3U, 0U, 0U, 0U};
  const size_t inconsistent_length =
      add_record(record, 0U, inconsistent, sizeof(inconsistent));
  assert_rejected(record, inconsistent_length);

  const uint8_t multiple[] = {11U, 0U, 0U,    11U, 0U, 0U, 8U,   0U,
                              0U,  1U, 0xaaU, 0U,  0U, 1U, 0xbbU};
  const size_t multiple_length =
      add_record(record, 0U, multiple, sizeof(multiple));
  assert_rejected(record, multiple_length);

  const size_t oversized_certificate = PBNS_TLS_CERTIFICATE_DER_MAX + 1U;
  const size_t oversized_list = oversized_certificate + 3U;
  const size_t oversized_message = oversized_list + 3U;
  handshake[0] = UINT8_C(11);
  handshake[1] = (uint8_t)(oversized_message >> 16U);
  handshake[2] = (uint8_t)(oversized_message >> 8U);
  handshake[3] = (uint8_t)oversized_message;
  handshake[4] = (uint8_t)(oversized_list >> 16U);
  handshake[5] = (uint8_t)(oversized_list >> 8U);
  handshake[6] = (uint8_t)oversized_list;
  handshake[7] = (uint8_t)(oversized_certificate >> 16U);
  handshake[8] = (uint8_t)(oversized_certificate >> 8U);
  handshake[9] = (uint8_t)oversized_certificate;
  const size_t oversized_length = add_record(record, 0U, handshake, 10U);
  assert_rejected(record, oversized_length);

  pbns_tls_handshake_observer observer;
  pbns_tls_handshake_observer_init(&observer);
  record[0] = UINT8_C(22);
  record[1] = UINT8_C(3);
  record[2] = UINT8_C(3);
  record[3] = 0U;
  record[4] = 4U;
  record[5] = UINT8_C(11);
  assert(pbns_tls_handshake_observer_observe(
             &observer, (pbns_view){record, 6U}) == PBNS_OK);
  assert(!pbns_tls_handshake_observer_complete(&observer));
}

int main(void) {
  test_valid_certificate_all_fragmentations();
  test_exact_size_boundaries();
  test_rejections();
  return 0;
}
