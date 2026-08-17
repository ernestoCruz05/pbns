#ifndef PBNS_TRANSPORT_H
#define PBNS_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "pbns/buffer.h"
#include "pbns/frame.h"
#include "pbns/status.h"

typedef struct pbns_transport pbns_transport;
typedef struct pbns_transport_ops pbns_transport_ops;

struct pbns_transport_ops {
    pbns_status (*open)(void *context);
    pbns_status (*close)(void *context);
    pbns_status (*send)(void *context, pbns_view bytes, uint32_t timeout_ms);
    pbns_status (*receive)(void *context, pbns_buffer buffer, uint32_t timeout_ms,
                           size_t *received);
    pbns_status (*cancel)(void *context, const pbns_request_id *request_id);
    pbns_status (*limits)(void *context, pbns_frame_limits *limits);
};

struct pbns_transport {
    const pbns_transport_ops *ops;
    void *context;
};

#endif
