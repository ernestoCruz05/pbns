#include "pbns_proxy/credentials.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/crc32c.h"
#include "qcbor/qcbor.h"

#define SLOT_DATA_SIZE (PBNS_CREDENTIALS_PAGE_SIZE * (size_t)2U)
#define SLOT_COMMIT_OFFSET SLOT_DATA_SIZE
#define RECORD_PAYLOAD_OFFSET 20U
#define RECORD_CRC_OFFSET (SLOT_DATA_SIZE - 4U)
#define COMMIT_SIZE PBNS_CREDENTIALS_PAGE_SIZE
#define COMMIT_CRC_OFFSET (COMMIT_SIZE - 4U)
#define RECORD_FORMAT_VERSION UINT8_C(1)
#define RECORD_FLAG_TOMBSTONE UINT8_C(1)

static const uint8_t record_magic[4] = {'P', 'B', 'N', 'C'};
static const uint8_t commit_magic[4] = {'P', 'B', 'O', 'K'};

typedef struct slot_info {
  bool valid;
  bool tombstone;
  uint64_t generation;
  pbns_credentials credentials;
} slot_info;

typedef struct transaction_workspace {
  uint8_t encoded[PBNS_CREDENTIALS_CBOR_MAX];
  slot_info slots[PBNS_CREDENTIALS_SLOT_COUNT];
  uint8_t data[SLOT_DATA_SIZE];
  uint8_t readback[SLOT_DATA_SIZE];
  uint8_t commit[COMMIT_SIZE];
  slot_info uncommitted;
  slot_info verified;
} transaction_workspace;

#if defined(PBNS_CREDENTIALS_STATIC_WORKSPACE)
static transaction_workspace shared_workspace;
#endif

static bool view_is_valid(pbns_view view) {
  return view.ptr != NULL || view.len == 0U;
}

static bool output_is_valid(pbns_buffer output) {
  return output.len == 0U && (output.ptr != NULL || output.cap == 0U);
}

static void secure_zero(void *pointer, size_t size) {
  volatile uint8_t *cursor = pointer;
  while (size > 0U) {
    *cursor = UINT8_C(0);
    ++cursor;
    --size;
  }
}

static bool utf8_is_valid(const uint8_t *text, size_t length) {
  size_t index = 0U;
  while (index < length) {
    const uint8_t first = text[index];
    if (first <= UINT8_C(0x7f)) {
      ++index;
      continue;
    }
    if (first >= UINT8_C(0xc2) && first <= UINT8_C(0xdf)) {
      if (index + 1U >= length || text[index + 1U] < UINT8_C(0x80) ||
          text[index + 1U] > UINT8_C(0xbf)) {
        return false;
      }
      index += 2U;
      continue;
    }
    if (first >= UINT8_C(0xe0) && first <= UINT8_C(0xef)) {
      if (index + 2U >= length) {
        return false;
      }
      const uint8_t second = text[index + 1U];
      const uint8_t third = text[index + 2U];
      const bool second_valid =
          (first == UINT8_C(0xe0) && second >= UINT8_C(0xa0) &&
           second <= UINT8_C(0xbf)) ||
          (first == UINT8_C(0xed) && second >= UINT8_C(0x80) &&
           second <= UINT8_C(0x9f)) ||
          (((first >= UINT8_C(0xe1) && first <= UINT8_C(0xec)) ||
            (first >= UINT8_C(0xee) && first <= UINT8_C(0xef))) &&
           second >= UINT8_C(0x80) && second <= UINT8_C(0xbf));
      if (!second_valid || third < UINT8_C(0x80) || third > UINT8_C(0xbf)) {
        return false;
      }
      index += 3U;
      continue;
    }
    if (first >= UINT8_C(0xf0) && first <= UINT8_C(0xf4)) {
      if (index + 3U >= length) {
        return false;
      }
      const uint8_t second = text[index + 1U];
      const bool second_valid =
          (first == UINT8_C(0xf0) && second >= UINT8_C(0x90) &&
           second <= UINT8_C(0xbf)) ||
          (first == UINT8_C(0xf4) && second >= UINT8_C(0x80) &&
           second <= UINT8_C(0x8f)) ||
          (first >= UINT8_C(0xf1) && first <= UINT8_C(0xf3) &&
           second >= UINT8_C(0x80) && second <= UINT8_C(0xbf));
      if (!second_valid || text[index + 2U] < UINT8_C(0x80) ||
          text[index + 2U] > UINT8_C(0xbf) ||
          text[index + 3U] < UINT8_C(0x80) ||
          text[index + 3U] > UINT8_C(0xbf)) {
        return false;
      }
      index += 4U;
      continue;
    }
    return false;
  }
  return true;
}

static bool contains_zero(const uint8_t *text, size_t length) {
  for (size_t index = 0U; index < length; ++index) {
    if (text[index] == UINT8_C(0)) {
      return true;
    }
  }
  return false;
}

static pbns_status validate_credentials(const pbns_credentials *credentials) {
  if (credentials == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (credentials->ssid_len > PBNS_CREDENTIALS_SSID_MAX ||
      credentials->psk_len > PBNS_CREDENTIALS_PSK_MAX ||
      credentials->hostname_len > PBNS_CREDENTIALS_HOSTNAME_MAX) {
    return PBNS_ERR_LIMIT;
  }
  if (credentials->ssid_len == 0U || credentials->psk_len == 0U ||
      credentials->hostname_len == 0U || credentials->port == 0U) {
    return PBNS_ERR_FORMAT;
  }
  if (!utf8_is_valid(credentials->ssid, credentials->ssid_len) ||
      contains_zero(credentials->ssid, credentials->ssid_len) ||
      contains_zero(credentials->psk, credentials->psk_len) ||
      !utf8_is_valid((const uint8_t *)credentials->hostname,
                     credentials->hostname_len) ||
      contains_zero((const uint8_t *)credentials->hostname,
                    credentials->hostname_len)) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static void write_u32_be(uint8_t *destination, uint32_t value) {
  destination[0] = (uint8_t)(value >> 24U);
  destination[1] = (uint8_t)(value >> 16U);
  destination[2] = (uint8_t)(value >> 8U);
  destination[3] = (uint8_t)value;
}

static uint32_t read_u32_be(const uint8_t *source) {
  return ((uint32_t)source[0] << 24U) | ((uint32_t)source[1] << 16U) |
         ((uint32_t)source[2] << 8U) | (uint32_t)source[3];
}

static void write_u64_be(uint8_t *destination, uint64_t value) {
  for (size_t index = 0U; index < 8U; ++index) {
    destination[index] = (uint8_t)(value >> (56U - (uint32_t)(index * 8U)));
  }
}

static uint64_t read_u64_be(const uint8_t *source) {
  uint64_t value = UINT64_C(0);
  for (size_t index = 0U; index < 8U; ++index) {
    value = (value << 8U) | (uint64_t)source[index];
  }
  return value;
}

static pbns_status next_labeled_item(QCBORDecodeContext *decoder,
                                     int64_t expected_label, QCBORItem *item) {
  if (QCBORDecode_GetNext(decoder, item) != QCBOR_SUCCESS ||
      item->uNestingLevel != 1U || item->uLabelType != QCBOR_TYPE_INT64 ||
      item->label.int64 != expected_label) {
    return PBNS_ERR_FORMAT;
  }
  return PBNS_OK;
}

static bool item_to_uint64(const QCBORItem *item, uint64_t *value) {
  if (item->uDataType == QCBOR_TYPE_INT64 && item->val.int64 >= 0) {
    *value = (uint64_t)item->val.int64;
    return true;
  }
  if (item->uDataType == QCBOR_TYPE_UINT64) {
    *value = item->val.uint64;
    return true;
  }
  return false;
}

static pbns_status encode_canonical(const pbns_credentials *credentials,
                                    pbns_buffer output, size_t *written) {
  QCBOREncodeContext encoder = {0};
  UsefulBufC encoded = {0};
  QCBOREncode_Init(&encoder, (UsefulBuf){output.ptr, output.cap});
  QCBOREncode_OpenMap(&encoder);
  QCBOREncode_AddUInt64ToMapN(&encoder, 1, PBNS_CREDENTIALS_VERSION);
  QCBOREncode_AddBytesToMapN(
      &encoder, 2, (UsefulBufC){credentials->ssid, credentials->ssid_len});
  QCBOREncode_AddBytesToMapN(
      &encoder, 3, (UsefulBufC){credentials->psk, credentials->psk_len});
  QCBOREncode_AddTextToMapN(
      &encoder, 4,
      (UsefulBufC){credentials->hostname, credentials->hostname_len});
  QCBOREncode_AddUInt64ToMapN(&encoder, 5, credentials->port);
  QCBOREncode_AddBytesToMapN(
      &encoder, 6,
      (UsefulBufC){credentials->spki_sha256, sizeof(credentials->spki_sha256)});
  QCBOREncode_CloseMap(&encoder);
  const QCBORError error = QCBOREncode_Finish(&encoder, &encoded);
  if (error == QCBOR_ERR_BUFFER_TOO_SMALL) {
    return PBNS_ERR_LIMIT;
  }
  if (error != QCBOR_SUCCESS) {
    return PBNS_ERR_FORMAT;
  }
  *written = encoded.len;
  return PBNS_OK;
}

pbns_status pbns_credentials_encode_cbor(const pbns_credentials *credentials,
                                         pbns_buffer output, size_t *written) {
  if (written == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *written = 0U;
  if (!output_is_valid(output)) {
    return PBNS_ERR_ARGUMENT;
  }
  const pbns_status status = validate_credentials(credentials);
  if (status != PBNS_OK) {
    return status;
  }
  return encode_canonical(credentials, output, written);
}

pbns_status pbns_credentials_decode_cbor(pbns_view encoded,
                                         pbns_credentials *credentials) {
  if (credentials != NULL) {
    *credentials = (pbns_credentials){0};
  }
  if (!view_is_valid(encoded) || credentials == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  if (encoded.len == 0U) {
    return PBNS_ERR_FORMAT;
  }
  if (encoded.len > PBNS_CREDENTIALS_CBOR_MAX) {
    return PBNS_ERR_LIMIT;
  }

  QCBORDecodeContext decoder = {0};
  QCBORItem item = {0};
  QCBORDecode_Init(&decoder, (UsefulBufC){encoded.ptr, encoded.len},
                   QCBOR_DECODE_MODE_NORMAL);
  if (QCBORDecode_GetNext(&decoder, &item) != QCBOR_SUCCESS ||
      item.uDataType != QCBOR_TYPE_MAP || item.uLabelType != QCBOR_TYPE_NONE ||
      item.val.uCount != 6U) {
    return PBNS_ERR_FORMAT;
  }

  uint64_t version = 0U;
  if (next_labeled_item(&decoder, 1, &item) != PBNS_OK ||
      !item_to_uint64(&item, &version)) {
    return PBNS_ERR_FORMAT;
  }
  if (version != PBNS_CREDENTIALS_VERSION) {
    return PBNS_ERR_VERSION;
  }

  pbns_credentials parsed = {0};
  uint8_t canonical[PBNS_CREDENTIALS_CBOR_MAX] = {0};
  pbns_status status = PBNS_ERR_FORMAT;
  if (next_labeled_item(&decoder, 2, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    goto cleanup;
  }
  if (item.val.string.len > sizeof(parsed.ssid)) {
    status = PBNS_ERR_LIMIT;
    goto cleanup;
  }
  parsed.ssid_len = item.val.string.len;
  if (parsed.ssid_len > 0U) {
    memcpy(parsed.ssid, item.val.string.ptr, parsed.ssid_len);
  }

  if (next_labeled_item(&decoder, 3, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING) {
    goto cleanup;
  }
  if (item.val.string.len > sizeof(parsed.psk)) {
    status = PBNS_ERR_LIMIT;
    goto cleanup;
  }
  parsed.psk_len = item.val.string.len;
  if (parsed.psk_len > 0U) {
    memcpy(parsed.psk, item.val.string.ptr, parsed.psk_len);
  }

  if (next_labeled_item(&decoder, 4, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_TEXT_STRING) {
    goto cleanup;
  }
  if (item.val.string.len > PBNS_CREDENTIALS_HOSTNAME_MAX) {
    status = PBNS_ERR_LIMIT;
    goto cleanup;
  }
  parsed.hostname_len = item.val.string.len;
  if (parsed.hostname_len > 0U) {
    memcpy(parsed.hostname, item.val.string.ptr, parsed.hostname_len);
  }
  parsed.hostname[parsed.hostname_len] = '\0';

  uint64_t port = 0U;
  if (next_labeled_item(&decoder, 5, &item) != PBNS_OK ||
      !item_to_uint64(&item, &port) || port > UINT16_MAX) {
    goto cleanup;
  }
  parsed.port = (uint16_t)port;

  if (next_labeled_item(&decoder, 6, &item) != PBNS_OK ||
      item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      item.val.string.len != sizeof(parsed.spki_sha256)) {
    goto cleanup;
  }
  memcpy(parsed.spki_sha256, item.val.string.ptr, sizeof(parsed.spki_sha256));
  if (QCBORDecode_Finish(&decoder) != QCBOR_SUCCESS) {
    goto cleanup;
  }

  status = validate_credentials(&parsed);
  if (status != PBNS_OK) {
    goto cleanup;
  }
  size_t canonical_len = 0U;
  status = encode_canonical(
      &parsed, (pbns_buffer){canonical, 0U, sizeof(canonical)}, &canonical_len);
  if (status == PBNS_OK && (canonical_len != encoded.len ||
                            memcmp(canonical, encoded.ptr, encoded.len) != 0)) {
    status = PBNS_ERR_FORMAT;
  }
  if (status == PBNS_OK) {
    *credentials = parsed;
  }

cleanup:
  secure_zero(canonical, sizeof(canonical));
  secure_zero(&parsed, sizeof(parsed));
  return status;
}

static bool storage_is_valid(const pbns_credentials_storage *storage) {
  if (storage == NULL || storage->ops == NULL || storage->ops->read == NULL ||
      storage->ops->erase == NULL || storage->ops->program == NULL) {
    return false;
  }
  const size_t first = storage->slot_offsets[0];
  const size_t second = storage->slot_offsets[1];
  if (first % PBNS_CREDENTIALS_SECTOR_SIZE != 0U ||
      second % PBNS_CREDENTIALS_SECTOR_SIZE != 0U ||
      first > SIZE_MAX - PBNS_CREDENTIALS_SECTOR_SIZE ||
      second > SIZE_MAX - PBNS_CREDENTIALS_SECTOR_SIZE) {
    return false;
  }
  const size_t first_end = first + PBNS_CREDENTIALS_SECTOR_SIZE;
  const size_t second_end = second + PBNS_CREDENTIALS_SECTOR_SIZE;
  return first < second_end && second < first_end ? false : true;
}

static bool data_record_is_valid(const uint8_t data[SLOT_DATA_SIZE],
                                 slot_info *info) {
  if (memcmp(data, record_magic, sizeof(record_magic)) != 0 ||
      data[4] != RECORD_FORMAT_VERSION ||
      (data[5] != 0U && data[5] != RECORD_FLAG_TOMBSTONE) || data[6] != 0U ||
      data[7] != 0U) {
    return false;
  }
  const uint64_t generation = read_u64_be(data + 8U);
  const size_t payload_len = (size_t)read_u32_be(data + 16U);
  const bool tombstone = data[5] == RECORD_FLAG_TOMBSTONE;
  if (generation == 0U || payload_len > PBNS_CREDENTIALS_CBOR_MAX ||
      (tombstone && payload_len != 0U) || (!tombstone && payload_len == 0U)) {
    return false;
  }
  const uint32_t expected_crc = read_u32_be(data + RECORD_CRC_OFFSET);
  const uint32_t actual_crc =
      pbns_crc32c((pbns_view){data, RECORD_PAYLOAD_OFFSET + payload_len});
  if (expected_crc != actual_crc) {
    return false;
  }
  info->generation = generation;
  info->tombstone = tombstone;
  if (!tombstone && pbns_credentials_decode_cbor(
                        (pbns_view){data + RECORD_PAYLOAD_OFFSET, payload_len},
                        &info->credentials) != PBNS_OK) {
    secure_zero(&info->credentials, sizeof(info->credentials));
    return false;
  }
  return true;
}

static bool commit_record_is_valid(const uint8_t commit[COMMIT_SIZE],
                                   uint64_t generation) {
  return memcmp(commit, commit_magic, sizeof(commit_magic)) == 0 &&
         read_u64_be(commit + 4U) == generation &&
         read_u32_be(commit + COMMIT_CRC_OFFSET) ==
             pbns_crc32c((pbns_view){commit, COMMIT_CRC_OFFSET});
}

static pbns_status read_slot(const pbns_credentials_storage *storage,
                             size_t slot, slot_info *info, uint8_t *data,
                             uint8_t *commit) {
  *info = (slot_info){0};
  pbns_status status =
      storage->ops->read(storage->context, storage->slot_offsets[slot],
                         (pbns_buffer){data, 0U, SLOT_DATA_SIZE});
  if (status == PBNS_OK) {
    status = storage->ops->read(
        storage->context, storage->slot_offsets[slot] + SLOT_COMMIT_OFFSET,
        (pbns_buffer){commit, 0U, COMMIT_SIZE});
  }
  if (status == PBNS_OK && data_record_is_valid(data, info) &&
      commit_record_is_valid(commit, info->generation)) {
    info->valid = true;
  } else if (status == PBNS_OK) {
    secure_zero(info, sizeof(*info));
  }
  secure_zero(data, SLOT_DATA_SIZE);
  secure_zero(commit, COMMIT_SIZE);
  return status;
}

static int latest_slot(const slot_info slots[PBNS_CREDENTIALS_SLOT_COUNT]) {
  if (!slots[0].valid && !slots[1].valid) {
    return -1;
  }
  if (slots[0].valid && !slots[1].valid) {
    return 0;
  }
  if (!slots[0].valid && slots[1].valid) {
    return 1;
  }
  if (slots[0].generation == slots[1].generation) {
    return -2;
  }
  return slots[0].generation > slots[1].generation ? 0 : 1;
}

static bool credentials_equal(const pbns_credentials *left,
                              const pbns_credentials *right) {
  return left->ssid_len == right->ssid_len &&
         memcmp(left->ssid, right->ssid, left->ssid_len) == 0 &&
         left->psk_len == right->psk_len &&
         memcmp(left->psk, right->psk, left->psk_len) == 0 &&
         left->hostname_len == right->hostname_len &&
         memcmp(left->hostname, right->hostname, left->hostname_len) == 0 &&
         left->port == right->port &&
         memcmp(left->spki_sha256, right->spki_sha256,
                sizeof(left->spki_sha256)) == 0;
}

static void build_data_record(uint8_t data[SLOT_DATA_SIZE], uint64_t generation,
                              bool tombstone, pbns_view payload) {
  memset(data, 0xff, SLOT_DATA_SIZE);
  memcpy(data, record_magic, sizeof(record_magic));
  data[4] = RECORD_FORMAT_VERSION;
  data[5] = tombstone ? RECORD_FLAG_TOMBSTONE : UINT8_C(0);
  data[6] = UINT8_C(0);
  data[7] = UINT8_C(0);
  write_u64_be(data + 8U, generation);
  write_u32_be(data + 16U, (uint32_t)payload.len);
  if (payload.len > 0U) {
    memcpy(data + RECORD_PAYLOAD_OFFSET, payload.ptr, payload.len);
  }
  write_u32_be(
      data + RECORD_CRC_OFFSET,
      pbns_crc32c((pbns_view){data, RECORD_PAYLOAD_OFFSET + payload.len}));
}

static void build_commit_record(uint8_t commit[COMMIT_SIZE],
                                uint64_t generation) {
  memset(commit, 0xff, COMMIT_SIZE);
  memcpy(commit, commit_magic, sizeof(commit_magic));
  write_u64_be(commit + 4U, generation);
  write_u32_be(commit + COMMIT_CRC_OFFSET,
               pbns_crc32c((pbns_view){commit, COMMIT_CRC_OFFSET}));
}

static pbns_status write_transaction(const pbns_credentials_storage *storage,
                                     const pbns_credentials *credentials,
                                     bool tombstone) {
  if (!storage_is_valid(storage)) {
    return PBNS_ERR_ARGUMENT;
  }
#if defined(PBNS_CREDENTIALS_STATIC_WORKSPACE)
  transaction_workspace *const workspace = &shared_workspace;
#else
  transaction_workspace local_workspace;
  transaction_workspace *const workspace = &local_workspace;
#endif
  secure_zero(workspace, sizeof(*workspace));

  size_t encoded_len = 0U;
  if (!tombstone) {
    const pbns_status encode_status = pbns_credentials_encode_cbor(
        credentials,
        (pbns_buffer){workspace->encoded, 0U, sizeof(workspace->encoded)},
        &encoded_len);
    if (encode_status != PBNS_OK) {
      secure_zero(workspace, sizeof(*workspace));
      return encode_status;
    }
  }

  pbns_status status = read_slot(storage, 0U, &workspace->slots[0],
                                 workspace->data, workspace->commit);
  if (status == PBNS_OK) {
    status = read_slot(storage, 1U, &workspace->slots[1], workspace->data,
                       workspace->commit);
  }
  int current = -1;
  if (status == PBNS_OK) {
    current = latest_slot(workspace->slots);
    if (current == -2) {
      status = PBNS_ERR_AMBIGUOUS;
    }
  }
  uint64_t generation = UINT64_C(1);
  if (status == PBNS_OK && current >= 0) {
    if (workspace->slots[(size_t)current].generation == UINT64_MAX) {
      status = PBNS_ERR_LIMIT;
    } else {
      generation = workspace->slots[(size_t)current].generation + UINT64_C(1);
    }
  }

  const size_t target = current == 0 ? 1U : 0U;
  if (status == PBNS_OK) {
    build_data_record(workspace->data, generation, tombstone,
                      (pbns_view){workspace->encoded, encoded_len});
    build_commit_record(workspace->commit, generation);
    status =
        storage->ops->erase(storage->context, storage->slot_offsets[target],
                            PBNS_CREDENTIALS_SECTOR_SIZE);
  }
  if (status == PBNS_OK) {
    status = storage->ops->program(
        storage->context, storage->slot_offsets[target],
        (pbns_view){workspace->data, sizeof(workspace->data)});
  }
  if (status == PBNS_OK) {
    status = storage->ops->read(
        storage->context, storage->slot_offsets[target],
        (pbns_buffer){workspace->readback, 0U, sizeof(workspace->readback)});
  }
  if (status == PBNS_OK &&
      (memcmp(workspace->data, workspace->readback, sizeof(workspace->data)) !=
           0 ||
       !data_record_is_valid(workspace->readback, &workspace->uncommitted) ||
       workspace->uncommitted.generation != generation ||
       workspace->uncommitted.tombstone != tombstone)) {
    status = PBNS_ERR_IO;
  }
  if (status == PBNS_OK) {
    status = storage->ops->program(
        storage->context, storage->slot_offsets[target] + SLOT_COMMIT_OFFSET,
        (pbns_view){workspace->commit, sizeof(workspace->commit)});
  }
  if (status == PBNS_OK) {
    status = read_slot(storage, target, &workspace->verified,
                       workspace->readback, workspace->commit);
  }
  if (status == PBNS_OK &&
      (!workspace->verified.valid ||
       workspace->verified.generation != generation ||
       workspace->verified.tombstone != tombstone ||
       (!tombstone &&
        !credentials_equal(&workspace->verified.credentials, credentials)))) {
    status = PBNS_ERR_IO;
  }

  secure_zero(workspace, sizeof(*workspace));
  return status;
}

pbns_status pbns_credentials_load(const pbns_credentials_storage *storage,
                                  pbns_credentials *credentials) {
  if (credentials != NULL) {
    *credentials = (pbns_credentials){0};
  }
  if (!storage_is_valid(storage) || credentials == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
#if defined(PBNS_CREDENTIALS_STATIC_WORKSPACE)
  transaction_workspace *const workspace = &shared_workspace;
#else
  transaction_workspace local_workspace;
  transaction_workspace *const workspace = &local_workspace;
#endif
  secure_zero(workspace, sizeof(*workspace));
  pbns_status status = read_slot(storage, 0U, &workspace->slots[0],
                                 workspace->data, workspace->commit);
  if (status == PBNS_OK) {
    status = read_slot(storage, 1U, &workspace->slots[1], workspace->data,
                       workspace->commit);
  }
  if (status == PBNS_OK) {
    const int current = latest_slot(workspace->slots);
    if (current == -2) {
      status = PBNS_ERR_AMBIGUOUS;
    } else if (current < 0 || workspace->slots[(size_t)current].tombstone) {
      status = PBNS_ERR_STATE;
    } else {
      *credentials = workspace->slots[(size_t)current].credentials;
    }
  }
  secure_zero(workspace, sizeof(*workspace));
  return status;
}

pbns_status pbns_credentials_store(const pbns_credentials_storage *storage,
                                   const pbns_credentials *credentials) {
  return write_transaction(storage, credentials, false);
}

pbns_status pbns_credentials_clear(const pbns_credentials_storage *storage) {
  return write_transaction(storage, NULL, true);
}
