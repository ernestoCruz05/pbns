#ifndef PBNS_BROKER_H
#define PBNS_BROKER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/frame.h"
#include "pbns/record_reader.h"
#include "pbns/status.h"
#include "pbns/stream.h"
#include "pbns/transport.h"

typedef struct pbns_broker_platform_ops {
    pbns_status (*random)(void *context, pbns_buffer output);
    pbns_status (*monotonic_ms)(void *context, uint64_t *now_ms);
} pbns_broker_platform_ops;

typedef struct pbns_broker_platform {
    const pbns_broker_platform_ops *ops;
    void *context;
} pbns_broker_platform;

typedef struct pbns_broker_storage {
    pbns_buffer encoded;
    pbns_buffer raw_scratch;
    pbns_buffer receive;
    pbns_buffer decoded;
} pbns_broker_storage;

typedef struct pbns_broker_response {
    pbns_frame frame;
    /* A carga referencia o armazenamento do broker até ao pedido ou reset seguinte. */
    pbns_view payload;
} pbns_broker_response;

typedef struct pbns_broker {
    pbns_transport transport;
    pbns_broker_platform platform;
    pbns_broker_storage storage;
    pbns_record_reader reader;
    pbns_stream_state stream;
    pbns_frame_limits limits;
    pbns_request_id request_id;
    pbns_service_id service;
    uint64_t deadline_ms;
    size_t receive_offset;
    size_t receive_length;
    uint64_t bulk_exact_data_size;
    uint64_t bulk_received_data_size;
    uint32_t bulk_next_ack_sequence;
    uint32_t upload_next_sequence;
    bool initialized;
    bool opened;
    bool active;
    bool deadline_active;
    bool bulk_mode;
    bool bulk_failed;
    bool upload_mode;
    bool upload_response_received;
} pbns_broker;

pbns_status pbns_broker_init(pbns_broker *broker, pbns_transport transport,
                             pbns_broker_platform platform, pbns_broker_storage storage);
pbns_status pbns_broker_request_with_id(pbns_broker *broker, pbns_service_id service,
                                        const pbns_request_id *request_id, pbns_view request_body,
                                        uint32_t timeout_ms, pbns_broker_response *response);
pbns_status pbns_broker_request(pbns_broker *broker, pbns_service_id service,
                                pbns_view request_body, uint32_t timeout_ms,
                                pbns_broker_response *response);
pbns_status pbns_broker_receive(pbns_broker *broker, pbns_broker_response *response);
pbns_status pbns_broker_bulk_begin(pbns_broker *broker, pbns_service_id service,
                                   const pbns_request_id *request_id, pbns_view request_body,
                                   uint64_t exact_data_size, uint32_t timeout_ms);
pbns_status pbns_broker_bulk_receive(pbns_broker *broker, pbns_broker_response *response);
pbns_status pbns_broker_bulk_ack(pbns_broker *broker, uint32_t next_data_sequence,
                                 uint32_t window);
pbns_status pbns_broker_bulk_finish(pbns_broker *broker);
pbns_status pbns_broker_upload_begin(pbns_broker *broker, pbns_service_id service,
                                     const pbns_request_id *request_id,
                                     pbns_view request_body, uint32_t timeout_ms);
pbns_status pbns_broker_upload_send(pbns_broker *broker, pbns_view payload,
                                    bool final_record,
                                    pbns_broker_response *response);
pbns_status pbns_broker_upload_finish(pbns_broker *broker);
pbns_status pbns_broker_cancel(pbns_broker *broker);
void pbns_broker_reset(pbns_broker *broker);

#endif
