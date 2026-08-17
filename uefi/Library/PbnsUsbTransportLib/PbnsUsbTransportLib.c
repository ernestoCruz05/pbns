#include "PbnsUsbTransportLib.h"
#include "PbnsUsbIoShim.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns/frame.h"
#include "pbns/status.h"
#include "pbns/transport.h"

static const uint8_t expected_product[] = "PBNS Proxy v1";

/* Limita ZLPs consecutivos para evitar espera ocupada sem progresso do dispositivo. */
#define PBNS_USB_RECEIVE_CONSECUTIVE_ZLP_MAX 4U

struct pbns_usb_transport {
    pbns_usb_io io;
    void *device;
    uint8_t endpoint_in;
    uint8_t endpoint_out;
    uint16_t max_packet_in;
    uint16_t max_packet_out;
    bool is_open;
    uint8_t transmit_buffer[PBNS_USB_TRANSFER_MAX];
    uint8_t receive_staging[PBNS_USB_RECEIVE_STAGING_MAX];
    size_t receive_offset;
    size_t receive_length;
};

typedef struct discovery_state {
    size_t matches;
    void *device;
    uint8_t endpoint_in;
    uint8_t endpoint_out;
    uint16_t max_packet_in;
    uint16_t max_packet_out;
} discovery_state;

typedef struct transfer_deadline {
    uint64_t deadline_ms;
    uint64_t last_ms;
} transfer_deadline;

static void wipe_bytes(void *bytes, size_t length) {
    volatile uint8_t *cursor = bytes;
    while (length > 0U) {
        *cursor++ = 0U;
        --length;
    }
}

static bool view_is_valid(pbns_view view) { return view.ptr != NULL || view.len == 0U; }

static void clear_receive_staging(pbns_usb_transport *transport) {
    wipe_bytes(transport->receive_staging, sizeof(transport->receive_staging));
    transport->receive_offset = 0U;
    transport->receive_length = 0U;
}

static bool io_is_valid(const pbns_usb_io *io) {
    return io != NULL && io->ops != NULL && io->ops->enumerate != NULL && io->ops->bulk != NULL &&
           io->ops->reset != NULL && io->ops->set_connected != NULL && io->ops->now_ms != NULL &&
           io->ops->allocate != NULL && io->ops->deallocate != NULL;
}

static bool product_matches(pbns_view product) {
    return view_is_valid(product) && product.len == sizeof(expected_product) - 1U &&
           memcmp(product.ptr, expected_product, product.len) == 0;
}

static bool endpoint_is_valid(const pbns_usb_endpoint *endpoint) {
    const uint8_t number = endpoint->address & UINT8_C(0x0f);
    const uint8_t reserved = endpoint->address & UINT8_C(0x70);
    return number != 0U && reserved == 0U && (endpoint->max_packet_size & UINT16_C(0x07ff)) != 0U;
}

static bool select_endpoints(const pbns_usb_device_description *description,
                             discovery_state *selection) {
    if (description->endpoint_count > PBNS_USB_ENDPOINT_MAX ||
        (description->endpoint_count > 0U && description->endpoints == NULL)) {
        return false;
    }

    bool found_in = false;
    bool found_out = false;
    for (size_t i = 0U; i < description->endpoint_count; ++i) {
        const pbns_usb_endpoint *endpoint = &description->endpoints[i];
        if ((endpoint->attributes & PBNS_USB_ENDPOINT_TRANSFER_MASK) !=
            PBNS_USB_ENDPOINT_TRANSFER_BULK) {
            continue;
        }
        if (!endpoint_is_valid(endpoint)) {
            return false;
        }
        if ((endpoint->address & PBNS_USB_ENDPOINT_DIRECTION_IN) != 0U) {
            const uint16_t max_packet_in = endpoint->max_packet_size & UINT16_C(0x07ff);
            if (found_in || (size_t)max_packet_in > PBNS_USB_RECEIVE_STAGING_MAX ||
                PBNS_USB_RECEIVE_STAGING_MAX / (size_t)max_packet_in == 0U) {
                return false;
            }
            found_in = true;
            selection->endpoint_in = endpoint->address;
            selection->max_packet_in = max_packet_in;
        } else {
            if (found_out) {
                return false;
            }
            found_out = true;
            selection->endpoint_out = endpoint->address;
            selection->max_packet_out = endpoint->max_packet_size & UINT16_C(0x07ff);
        }
    }
    return found_in && found_out;
}

static pbns_status discover_device(void *context, const pbns_usb_device_description *description) {
    discovery_state *state = context;
    if (state == NULL || description == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (description->device == NULL || description->vendor_id != PBNS_USB_VENDOR_ID ||
        description->product_id != PBNS_USB_PRODUCT_ID ||
        description->interface_number != PBNS_USB_CDC_DATA_INTERFACE ||
        description->interface_class != PBNS_USB_CDC_DATA_CLASS ||
        !product_matches(description->product)) {
        return PBNS_OK;
    }

    discovery_state candidate = {0};
    if (!select_endpoints(description, &candidate)) {
        return PBNS_OK;
    }
    ++state->matches;
    if (state->matches > 1U) {
        return PBNS_ERR_AMBIGUOUS;
    }
    state->device = description->device;
    state->endpoint_in = candidate.endpoint_in;
    state->endpoint_out = candidate.endpoint_out;
    state->max_packet_in = candidate.max_packet_in;
    state->max_packet_out = candidate.max_packet_out;
    return PBNS_OK;
}

pbns_status pbns_usb_transport_create_from_io(const pbns_usb_io *io, pbns_usb_transport **result) {
    if (result == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *result = NULL;
    if (!io_is_valid(io)) {
        return PBNS_ERR_ARGUMENT;
    }

    discovery_state discovery = {0};
    pbns_status status = io->ops->enumerate(io->context, discover_device, &discovery);
    if (status != PBNS_OK) {
        return status;
    }
    if (discovery.matches > 1U) {
        return PBNS_ERR_AMBIGUOUS;
    }
    if (discovery.matches == 0U) {
        return PBNS_ERR_UNSUPPORTED;
    }

    pbns_usb_transport *transport = io->ops->allocate(io->context, sizeof(*transport));
    if (transport == NULL) {
        return PBNS_ERR_RESOURCE;
    }
    memset(transport, 0, sizeof(*transport));
    transport->io = *io;
    transport->device = discovery.device;
    transport->endpoint_in = discovery.endpoint_in;
    transport->endpoint_out = discovery.endpoint_out;
    transport->max_packet_in = discovery.max_packet_in;
    transport->max_packet_out = discovery.max_packet_out;
    *result = transport;
    return PBNS_OK;
}

#if defined(PBNS_UEFI_BUILD)
pbns_status pbns_usb_transport_create(EFI_BOOT_SERVICES *boot_services,
                                      pbns_usb_transport **result) {
    if (result == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *result = NULL;
    pbns_usb_io io = {0};
    pbns_status status = pbns_usb_io_shim_init(boot_services, &io);
    if (status != PBNS_OK) {
        return status;
    }
    return pbns_usb_transport_create_from_io(&io, result);
}
#endif

void pbns_usb_transport_destroy(pbns_usb_transport *transport) {
    if (transport == NULL) {
        return;
    }
    pbns_usb_io io = transport->io;
    if (transport->is_open &&
        io.ops->set_connected(io.context, transport->device, false) != PBNS_OK) {
        (void)io.ops->reset(io.context, transport->device);
    }
    wipe_bytes(transport, sizeof(*transport));
    io.ops->deallocate(io.context, transport);
}

static pbns_status transport_open(void *context) {
    pbns_usb_transport *transport = context;
    if (transport == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (transport->is_open) {
        return PBNS_ERR_BUSY;
    }
    pbns_status status =
        transport->io.ops->set_connected(transport->io.context, transport->device, true);
    if (status != PBNS_OK) {
        (void)transport->io.ops->reset(transport->io.context, transport->device);
        return status;
    }
    clear_receive_staging(transport);
    transport->is_open = true;
    return PBNS_OK;
}

static pbns_status transport_close(void *context) {
    pbns_usb_transport *transport = context;
    if (transport == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    pbns_status status = PBNS_OK;
    if (transport->is_open) {
        status = transport->io.ops->set_connected(transport->io.context, transport->device, false);
        if (status != PBNS_OK) {
            (void)transport->io.ops->reset(transport->io.context, transport->device);
        }
    }
    transport->is_open = false;
    wipe_bytes(transport->transmit_buffer, sizeof(transport->transmit_buffer));
    clear_receive_staging(transport);
    return status;
}

static pbns_status deadline_init(pbns_usb_transport *transport, uint32_t timeout_ms,
                                 transfer_deadline *deadline) {
    if (timeout_ms == 0U || deadline == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    uint64_t now_ms = 0U;
    pbns_status status = transport->io.ops->now_ms(transport->io.context, &now_ms);
    if (status != PBNS_OK) {
        return status;
    }
    deadline->last_ms = now_ms;
    if ((uint64_t)timeout_ms > UINT64_MAX - now_ms) {
        deadline->deadline_ms = UINT64_MAX;
    } else {
        deadline->deadline_ms = now_ms + (uint64_t)timeout_ms;
    }
    return PBNS_OK;
}

static pbns_status deadline_remaining(pbns_usb_transport *transport, transfer_deadline *deadline,
                                      uint32_t *remaining_ms) {
    uint64_t now_ms = 0U;
    pbns_status status = transport->io.ops->now_ms(transport->io.context, &now_ms);
    if (status != PBNS_OK) {
        return status;
    }
    if (now_ms < deadline->last_ms) {
        return PBNS_ERR_TRANSPORT;
    }
    deadline->last_ms = now_ms;
    if (now_ms >= deadline->deadline_ms) {
        return PBNS_ERR_TIMEOUT;
    }
    const uint64_t remaining = deadline->deadline_ms - now_ms;
    *remaining_ms = remaining > UINT32_MAX ? UINT32_MAX : (uint32_t)remaining;
    return PBNS_OK;
}

static pbns_status transfer_result(pbns_usb_transport *transport, pbns_status status,
                                   uint32_t usb_status) {
    if ((usb_status & PBNS_USB_TRANSFER_STALL) != 0U) {
        (void)transport->io.ops->reset(transport->io.context, transport->device);
        clear_receive_staging(transport);
        return PBNS_ERR_TRANSPORT;
    }
    if (usb_status != 0U && status == PBNS_OK) {
        clear_receive_staging(transport);
        return PBNS_ERR_TRANSPORT;
    }
    if (status != PBNS_OK) {
        clear_receive_staging(transport);
    }
    return status;
}

static pbns_status transport_send(void *context, pbns_view bytes, uint32_t timeout_ms) {
    pbns_usb_transport *transport = context;
    if (transport == NULL || !view_is_valid(bytes)) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!transport->is_open) {
        return PBNS_ERR_STATE;
    }
    if (bytes.len == 0U) {
        return PBNS_OK;
    }

    transfer_deadline deadline = {0};
    pbns_status status = deadline_init(transport, timeout_ms, &deadline);
    if (status != PBNS_OK) {
        return status;
    }

    size_t offset = 0U;
    while (offset < bytes.len) {
        uint32_t remaining_ms = 0U;
        status = deadline_remaining(transport, &deadline, &remaining_ms);
        if (status != PBNS_OK) {
            return status;
        }
        size_t length = bytes.len - offset;
        if (length > sizeof(transport->transmit_buffer)) {
            length = sizeof(transport->transmit_buffer);
        }
        memcpy(transport->transmit_buffer, bytes.ptr + offset, length);
        const size_t requested = length;
        uint32_t usb_status = 0U;
        status = transport->io.ops->bulk(transport->io.context, transport->device,
                                         transport->endpoint_out, transport->transmit_buffer,
                                         &length, remaining_ms, &usb_status);
        wipe_bytes(transport->transmit_buffer, requested);
        status = transfer_result(transport, status, usb_status);
        if (status != PBNS_OK) {
            return status;
        }
        if (length == 0U || length > requested) {
            return PBNS_ERR_IO;
        }
        offset += length;
    }
    return PBNS_OK;
}

static size_t receive_from_staging(pbns_usb_transport *transport, pbns_buffer buffer) {
    const size_t available = transport->receive_length - transport->receive_offset;
    const size_t length = buffer.cap < available ? buffer.cap : available;
    memcpy(buffer.ptr, transport->receive_staging + transport->receive_offset, length);
    wipe_bytes(transport->receive_staging + transport->receive_offset, length);
    transport->receive_offset += length;
    if (transport->receive_offset == transport->receive_length) {
        transport->receive_offset = 0U;
        transport->receive_length = 0U;
    }
    return length;
}

static bool receive_request_size(const pbns_usb_transport *transport, size_t capacity,
                                 size_t *requested) {
    if (transport == NULL || requested == NULL || transport->max_packet_in == 0U) {
        return false;
    }
    const size_t packet_size = (size_t)transport->max_packet_in;
    const size_t maximum = sizeof(transport->receive_staging) -
                           sizeof(transport->receive_staging) % packet_size;
    if (maximum == 0U) {
        return false;
    }
    size_t length = capacity < maximum ? capacity : maximum;
    const size_t remainder = length % packet_size;
    if (remainder != 0U) {
        const size_t padding = packet_size - remainder;
        if (length > SIZE_MAX - padding) {
            return false;
        }
        length += padding;
    }
    *requested = length <= maximum ? length : maximum;
    return *requested != 0U;
}

static pbns_status transport_receive(void *context, pbns_buffer buffer, uint32_t timeout_ms,
                                     size_t *received) {
    pbns_usb_transport *transport = context;
    if (received == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *received = 0U;
    if (transport == NULL || !transport->is_open) {
        return transport == NULL ? PBNS_ERR_ARGUMENT : PBNS_ERR_STATE;
    }
    if (buffer.ptr == NULL || buffer.len != 0U || buffer.cap == 0U || timeout_ms == 0U) {
        return PBNS_ERR_ARGUMENT;
    }
    if (transport->receive_offset < transport->receive_length) {
        *received = receive_from_staging(transport, buffer);
        return PBNS_OK;
    }

    transfer_deadline deadline = {0};
    pbns_status status = deadline_init(transport, timeout_ms, &deadline);
    if (status != PBNS_OK) {
        return status;
    }
    size_t consecutive_zlps = 0U;
    for (;;) {
        uint32_t remaining_ms = 0U;
        status = deadline_remaining(transport, &deadline, &remaining_ms);
        if (status != PBNS_OK) {
            return status;
        }

        size_t requested = 0U;
        if (!receive_request_size(transport, buffer.cap, &requested)) {
            return PBNS_ERR_STATE;
        }
        size_t length = requested;
        uint32_t usb_status = 0U;
        status = transport->io.ops->bulk(transport->io.context, transport->device,
                                         transport->endpoint_in, transport->receive_staging, &length,
                                         remaining_ms, &usb_status);
        status = transfer_result(transport, status, usb_status);
        if (status != PBNS_OK) {
            return status;
        }
        if (length > requested) {
            clear_receive_staging(transport);
            return PBNS_ERR_IO;
        }
        if (length != 0U) {
            transport->receive_offset = 0U;
            transport->receive_length = length;
            *received = receive_from_staging(transport, buffer);
            return PBNS_OK;
        }
        if (consecutive_zlps == PBNS_USB_RECEIVE_CONSECUTIVE_ZLP_MAX) {
            return PBNS_ERR_IO;
        }
        ++consecutive_zlps;
    }
}

static pbns_status transport_cancel(void *context, const pbns_request_id *request_id) {
    pbns_usb_transport *transport = context;
    if (transport == NULL || request_id == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    if (!transport->is_open) {
        return PBNS_ERR_STATE;
    }
    return PBNS_ERR_UNSUPPORTED;
}

static pbns_status transport_limits(void *context, pbns_frame_limits *limits) {
    if (context == NULL || limits == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    *limits = (pbns_frame_limits){
        .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
        .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
        .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
    };
    return PBNS_OK;
}

static const pbns_transport_ops transport_ops = {
    .open = transport_open,
    .close = transport_close,
    .send = transport_send,
    .receive = transport_receive,
    .cancel = transport_cancel,
    .limits = transport_limits,
};

pbns_transport pbns_usb_transport_as_transport(pbns_usb_transport *transport) {
    if (transport == NULL) {
        return (pbns_transport){0};
    }
    return (pbns_transport){.ops = &transport_ops, .context = transport};
}
