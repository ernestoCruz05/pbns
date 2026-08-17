#ifndef PBNS_FRAME_H
#define PBNS_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_FRAME_V1_PROTOCOL_VERSION UINT8_C(1)
#define PBNS_FRAME_V1_HEADER_SIZE 36U
#define PBNS_FRAME_V1_TRAILER_SIZE 4U
#define PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX 65536U
#define PBNS_FRAME_V1_DATA_PAYLOAD_MAX 16384U
#define PBNS_FRAME_V1_RAW_MAX 65576U
#define PBNS_FRAME_V1_COBS_MAX 65835U
#define PBNS_FRAME_V1_WIRE_MAX 65836U
#define PBNS_REQUEST_ID_SIZE 16U
#define PBNS_ACK_PAYLOAD_SIZE 8U

typedef enum pbns_service_id {
    PBNS_SERVICE_INVALID = 0,
    PBNS_SERVICE_TRUSTED_TIME = 1,
    PBNS_SERVICE_RECOVERY_ARTIFACT = 2,
    PBNS_SERVICE_PLATFORM_ATTESTATION = 3,
    PBNS_SERVICE_ENROLLMENT = 4
} pbns_service_id;

typedef enum pbns_message_type {
    PBNS_MESSAGE_INVALID = 0,
    PBNS_MESSAGE_REQUEST = 1,
    PBNS_MESSAGE_RESPONSE = 2,
    PBNS_MESSAGE_DATA = 3,
    PBNS_MESSAGE_ACK = 4,
    PBNS_MESSAGE_ERROR = 5,
    PBNS_MESSAGE_CANCEL = 6,
    PBNS_MESSAGE_COMPLETE = 7
} pbns_message_type;

typedef struct pbns_request_id {
    uint8_t bytes[PBNS_REQUEST_ID_SIZE];
} pbns_request_id;

typedef struct pbns_frame {
    pbns_service_id service;
    pbns_message_type type;
    uint8_t flags;
    pbns_request_id request_id;
    uint32_t sequence;
} pbns_frame;

typedef struct pbns_frame_limits {
    size_t control_payload_max;
    size_t data_payload_max;
    size_t encoded_record_max;
} pbns_frame_limits;

pbns_status pbns_frame_encode(const pbns_frame *frame,
                              pbns_view payload,
                              pbns_buffer raw_scratch,
                              pbns_buffer output,
                              size_t *written);
pbns_status pbns_frame_decode(pbns_view cobs_record,
                              pbns_frame_limits limits,
                              pbns_buffer scratch,
                              pbns_frame *frame,
                              pbns_view *payload);

#endif
