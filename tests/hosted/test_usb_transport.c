#include "PbnsUsbIoShim.h"
#include "PbnsUsbTransportLib.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FAKE_DEVICE_MAX 4U
#define FAKE_ENDPOINT_MAX 4U
#define FAKE_STEP_MAX 8U
#define FAKE_BYTES_MAX 64U

typedef struct fake_device {
    uint8_t product[32];
    pbns_usb_endpoint endpoints[FAKE_ENDPOINT_MAX];
    pbns_usb_device_description description;
} fake_device;

typedef struct fake_transfer_step {
    pbns_status status;
    size_t transferred;
    uint32_t usb_status;
    uint64_t elapsed_ms;
    uint8_t fill;
} fake_transfer_step;

typedef struct fake_usb {
    fake_device devices[FAKE_DEVICE_MAX];
    size_t device_count;
    pbns_status enumerate_status;
    fake_transfer_step steps[FAKE_STEP_MAX];
    size_t step_count;
    size_t step_index;
    uint8_t expected_send[FAKE_BYTES_MAX];
    size_t expected_send_len;
    size_t expected_send_offset;
    uint32_t observed_timeouts[FAKE_STEP_MAX];
    uint8_t observed_endpoints[FAKE_STEP_MAX];
    size_t observed_lengths[FAKE_STEP_MAX];
    size_t bulk_calls;
    size_t reset_calls;
    pbns_status reset_status;
    size_t connect_calls;
    size_t disconnect_calls;
    pbns_status connect_status;
    pbns_status disconnect_status;
    uint64_t now_ms;
    size_t now_calls;
    size_t allocation_count;
    size_t free_count;
    size_t live_allocations;
    bool fail_allocation;
    bool accept_any_send;
} fake_usb;

static const uint8_t expected_product[] = "PBNS Proxy v1";

static pbns_status fake_enumerate(void *context, pbns_usb_device_visitor visitor,
                                  void *visitor_context) {
    fake_usb *fake = context;
    if (fake->enumerate_status != PBNS_OK) {
        return fake->enumerate_status;
    }
    for (size_t i = 0U; i < fake->device_count; ++i) {
        pbns_status status = visitor(visitor_context, &fake->devices[i].description);
        if (status != PBNS_OK) {
            return status;
        }
    }
    return PBNS_OK;
}

static pbns_status fake_bulk(void *context, void *device, uint8_t endpoint, uint8_t *bytes,
                             size_t *length, uint32_t timeout_ms, uint32_t *usb_status) {
    fake_usb *fake = context;
    assert(device != NULL);
    assert(bytes != NULL);
    assert(length != NULL);
    assert(usb_status != NULL);
    assert(fake->step_index < fake->step_count);
    assert(fake->bulk_calls < FAKE_STEP_MAX);

    const fake_transfer_step step = fake->steps[fake->step_index++];
    const size_t requested = *length;
    fake->observed_timeouts[fake->bulk_calls] = timeout_ms;
    fake->observed_endpoints[fake->bulk_calls] = endpoint;
    fake->observed_lengths[fake->bulk_calls] = requested;
    ++fake->bulk_calls;
    fake->now_ms += step.elapsed_ms;
    *usb_status = step.usb_status;
    *length = step.transferred;

    if (step.status == PBNS_OK && step.transferred <= requested) {
        if ((endpoint & PBNS_USB_ENDPOINT_DIRECTION_IN) != 0U) {
            for (size_t i = 0U; i < step.transferred; ++i) {
                bytes[i] = (uint8_t)(step.fill + (uint8_t)i);
            }
        } else {
            assert(fake->expected_send_offset + step.transferred <= fake->expected_send_len);
            if (fake->accept_any_send) {
                for (size_t index = 0U; index < step.transferred; ++index) {
                    assert(bytes[index] == 0U);
                }
            } else {
                assert(memcmp(bytes, fake->expected_send + fake->expected_send_offset,
                              step.transferred) == 0);
            }
            fake->expected_send_offset += step.transferred;
        }
    }
    return step.status;
}

static pbns_status fake_reset(void *context, void *device) {
    fake_usb *fake = context;
    assert(device != NULL);
    ++fake->reset_calls;
    return fake->reset_status;
}

static pbns_status fake_set_connected(void *context, void *device, bool connected) {
    fake_usb *fake = context;
    assert(device != NULL);
    if (connected) {
        ++fake->connect_calls;
        return fake->connect_status;
    }
    ++fake->disconnect_calls;
    return fake->disconnect_status;
}

static pbns_status fake_now_ms(void *context, uint64_t *now_ms) {
    fake_usb *fake = context;
    if (now_ms == NULL) {
        return PBNS_ERR_ARGUMENT;
    }
    ++fake->now_calls;
    *now_ms = fake->now_ms;
    return PBNS_OK;
}

static void *fake_allocate(void *context, size_t size) {
    fake_usb *fake = context;
    if (fake->fail_allocation || size == 0U) {
        return NULL;
    }
    void *allocation = calloc(1U, size);
    if (allocation != NULL) {
        ++fake->allocation_count;
        ++fake->live_allocations;
    }
    return allocation;
}

static void fake_free(void *context, void *allocation) {
    fake_usb *fake = context;
    if (allocation != NULL) {
        assert(fake->live_allocations > 0U);
        --fake->live_allocations;
        ++fake->free_count;
        free(allocation);
    }
}

static const pbns_usb_io_ops fake_ops = {
    .enumerate = fake_enumerate,
    .bulk = fake_bulk,
    .reset = fake_reset,
    .set_connected = fake_set_connected,
    .now_ms = fake_now_ms,
    .allocate = fake_allocate,
    .deallocate = fake_free,
};

static pbns_usb_io fake_io(fake_usb *fake) {
    return (pbns_usb_io){.ops = &fake_ops, .context = fake};
}

static void fake_init(fake_usb *fake) {
    memset(fake, 0, sizeof(*fake));
    fake->enumerate_status = PBNS_OK;
    fake->reset_status = PBNS_OK;
    fake->connect_status = PBNS_OK;
    fake->disconnect_status = PBNS_OK;
    fake->now_ms = UINT64_C(1000);
}

static void fake_add_valid_device(fake_usb *fake) {
    assert(fake->device_count < FAKE_DEVICE_MAX);
    fake_device *device = &fake->devices[fake->device_count++];
    memset(device, 0, sizeof(*device));
    memcpy(device->product, expected_product, sizeof(expected_product) - 1U);
    device->endpoints[0] = (pbns_usb_endpoint){
        .address = UINT8_C(0x02),
        .attributes = PBNS_USB_ENDPOINT_TRANSFER_BULK,
        .max_packet_size = UINT16_C(64),
    };
    device->endpoints[1] = (pbns_usb_endpoint){
        .address = UINT8_C(0x82),
        .attributes = PBNS_USB_ENDPOINT_TRANSFER_BULK,
        .max_packet_size = UINT16_C(64),
    };
    device->description = (pbns_usb_device_description){
        .device = device,
        .vendor_id = PBNS_USB_VENDOR_ID,
        .product_id = PBNS_USB_PRODUCT_ID,
        .interface_number = PBNS_USB_CDC_DATA_INTERFACE,
        .interface_class = PBNS_USB_CDC_DATA_CLASS,
        .product = {.ptr = device->product, .len = sizeof(expected_product) - 1U},
        .endpoints = device->endpoints,
        .endpoint_count = 2U,
    };
}

static pbns_status create_transport(fake_usb *fake, pbns_usb_transport **result) {
    pbns_usb_io io = fake_io(fake);
    return pbns_usb_transport_create_from_io(&io, result);
}

static pbns_transport open_valid_transport(fake_usb *fake, pbns_usb_transport **owned) {
    fake_add_valid_device(fake);
    assert(create_transport(fake, owned) == PBNS_OK);
    assert(*owned != NULL);
    pbns_transport transport = pbns_usb_transport_as_transport(*owned);
    assert(transport.ops != NULL);
    assert(transport.context == *owned);
    assert(transport.ops->open(transport.context) == PBNS_OK);
    return transport;
}

static void assert_create_unsupported(fake_usb *fake) {
    pbns_usb_transport *transport = (void *)fake;
    assert(create_transport(fake, &transport) == PBNS_ERR_UNSUPPORTED);
    assert(transport == NULL);
    assert(fake->allocation_count == 0U);
    assert(fake->live_allocations == 0U);
}

static void test_discovery_rejections(void) {
    fake_usb fake;

    fake_init(&fake);
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.devices[0].description.product =
        (pbns_view){.ptr = (const uint8_t *)"PBNS Proxy v2", .len = 13U};
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.devices[0].description.interface_class = UINT8_C(0x02);
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.devices[0].description.interface_number = UINT8_C(3);
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.devices[0].description.endpoint_count = 1U;
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.devices[0].endpoints[1].address = UINT8_C(0x81);
    fake.devices[0].endpoints[0].address = UINT8_C(0x01);
    fake.devices[0].description.endpoint_count = 3U;
    fake.devices[0].endpoints[2] = (pbns_usb_endpoint){
        .address = UINT8_C(0x02),
        .attributes = PBNS_USB_ENDPOINT_TRANSFER_BULK,
        .max_packet_size = UINT16_C(64),
    };
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.devices[0].endpoints[0].max_packet_size = 0U;
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    const pbns_usb_endpoint single_endpoint = fake.devices[0].endpoints[0];
    fake.devices[0].description.endpoints = &single_endpoint;
    fake.devices[0].description.endpoint_count = PBNS_USB_ENDPOINT_MAX + 1U;
    assert_create_unsupported(&fake);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake_add_valid_device(&fake);
    pbns_usb_transport *transport = NULL;
    assert(create_transport(&fake, &transport) == PBNS_ERR_AMBIGUOUS);
    assert(transport == NULL);
    assert(fake.allocation_count == 0U);

    fake_init(&fake);
    fake.enumerate_status = PBNS_ERR_TRANSPORT;
    transport = NULL;
    assert(create_transport(&fake, &transport) == PBNS_ERR_TRANSPORT);
    assert(transport == NULL);
}

static void test_lifecycle_limits_and_allocation(void) {
    fake_usb fake;
    fake_init(&fake);
    fake_add_valid_device(&fake);
    pbns_usb_transport *owned = NULL;
    assert(create_transport(&fake, &owned) == PBNS_OK);
    assert(fake.allocation_count == 1U);
    assert(fake.live_allocations == 1U);

    pbns_transport transport = pbns_usb_transport_as_transport(owned);
    assert(transport.ops->close(transport.context) == PBNS_OK);
    assert(transport.ops->open(transport.context) == PBNS_OK);
    assert(fake.connect_calls == 1U);
    assert(transport.ops->open(transport.context) == PBNS_ERR_BUSY);
    assert(fake.connect_calls == 1U);

    pbns_frame_limits limits = {0};
    assert(transport.ops->limits(transport.context, &limits) == PBNS_OK);
    assert(limits.control_payload_max == PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX);
    assert(limits.data_payload_max == PBNS_FRAME_V1_DATA_PAYLOAD_MAX);
    assert(limits.encoded_record_max == PBNS_FRAME_V1_WIRE_MAX);
    assert(transport.ops->cancel(transport.context, NULL) == PBNS_ERR_ARGUMENT);
    pbns_request_id request_id = {{0}};
    assert(transport.ops->cancel(transport.context, &request_id) == PBNS_ERR_UNSUPPORTED);
    assert(transport.ops->close(transport.context) == PBNS_OK);
    assert(fake.disconnect_calls == 1U);
    assert(transport.ops->close(transport.context) == PBNS_OK);
    assert(fake.disconnect_calls == 1U);

    pbns_usb_transport_destroy(owned);
    assert(fake.free_count == 1U);
    assert(fake.live_allocations == 0U);
    pbns_usb_transport_destroy(NULL);

    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.fail_allocation = true;
    owned = NULL;
    assert(create_transport(&fake, &owned) == PBNS_ERR_RESOURCE);
    assert(owned == NULL);
    assert(fake.live_allocations == 0U);
}

static void test_control_line_failures(void) {
    fake_usb fake;
    fake_init(&fake);
    fake_add_valid_device(&fake);
    fake.connect_status = PBNS_ERR_TRANSPORT;
    pbns_usb_transport *owned = NULL;
    assert(create_transport(&fake, &owned) == PBNS_OK);
    pbns_transport transport = pbns_usb_transport_as_transport(owned);
    assert(transport.ops->open(transport.context) == PBNS_ERR_TRANSPORT);
    assert(fake.connect_calls == 1U);
    assert(fake.reset_calls == 1U);
    const uint8_t byte = 1U;
    assert(transport.ops->send(transport.context, (pbns_view){&byte, 1U}, UINT32_C(1)) ==
           PBNS_ERR_STATE);

    fake.connect_status = PBNS_OK;
    assert(transport.ops->open(transport.context) == PBNS_OK);
    fake.disconnect_status = PBNS_ERR_TRANSPORT;
    assert(transport.ops->close(transport.context) == PBNS_ERR_TRANSPORT);
    assert(fake.disconnect_calls == 1U);
    assert(fake.reset_calls == 2U);
    assert(transport.ops->close(transport.context) == PBNS_OK);
    assert(fake.disconnect_calls == 1U);
    pbns_usb_transport_destroy(owned);
    assert(fake.live_allocations == 0U);
}

static void test_short_send_and_deadline(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    const uint8_t bytes[] = {0U, 1U, 2U, 3U, 4U};
    memcpy(fake.expected_send, bytes, sizeof(bytes));
    fake.expected_send_len = sizeof(bytes);
    fake.steps[0] = (fake_transfer_step){.status = PBNS_OK, .transferred = 2U};
    fake.steps[1] = (fake_transfer_step){.status = PBNS_OK, .transferred = 3U};
    fake.step_count = 2U;
    assert(transport.ops->send(transport.context, (pbns_view){bytes, sizeof(bytes)},
                               UINT32_C(100)) == PBNS_OK);
    assert(fake.bulk_calls == 2U);
    assert(fake.expected_send_offset == sizeof(bytes));
    assert(fake.observed_endpoints[0] == UINT8_C(0x02));
    assert(fake.observed_timeouts[0] == UINT32_C(100));
    assert(fake.observed_timeouts[1] == UINT32_C(100));
    pbns_usb_transport_destroy(owned);

    fake_init(&fake);
    owned = NULL;
    transport = open_valid_transport(&fake, &owned);
    memcpy(fake.expected_send, bytes, sizeof(bytes));
    fake.expected_send_len = sizeof(bytes);
    fake.steps[0] = (fake_transfer_step){
        .status = PBNS_OK,
        .transferred = 1U,
        .elapsed_ms = UINT64_C(5),
    };
    fake.step_count = 1U;
    assert(transport.ops->send(transport.context, (pbns_view){bytes, sizeof(bytes)}, UINT32_C(4)) ==
           PBNS_ERR_TIMEOUT);
    assert(fake.bulk_calls == 1U);
    pbns_usb_transport_destroy(owned);
}

static void test_send_accepts_ciphertext_larger_than_pbns_frame(void) {
    static uint8_t ciphertext[PBNS_FRAME_V1_WIRE_MAX + 1U] = {0};
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    fake.accept_any_send = true;
    fake.expected_send_len = sizeof(ciphertext);
    for (size_t index = 0U; index < 4U; ++index) {
        fake.steps[index] = (fake_transfer_step){
            .status = PBNS_OK,
            .transferred = PBNS_USB_TRANSFER_MAX,
            .elapsed_ms = UINT64_C(1),
        };
    }
    fake.steps[4] = (fake_transfer_step){
        .status = PBNS_OK,
        .transferred =
            sizeof(ciphertext) - (size_t)4U * (size_t)PBNS_USB_TRANSFER_MAX,
    };
    fake.step_count = 5U;
    assert(transport.ops->send(transport.context,
                               (pbns_view){ciphertext, sizeof(ciphertext)},
                               UINT32_C(100)) == PBNS_OK);
    assert(fake.bulk_calls == 5U);
    assert(fake.expected_send_offset == sizeof(ciphertext));
    assert(fake.observed_timeouts[0] == UINT32_C(100));
    assert(fake.observed_timeouts[4] == UINT32_C(96));
    pbns_usb_transport_destroy(owned);
}

static void test_fragmented_receive_and_invalid_buffers(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    fake.steps[0] = (fake_transfer_step){.status = PBNS_OK, .transferred = 2U, .fill = 0x20U};
    fake.steps[1] = (fake_transfer_step){.status = PBNS_OK, .transferred = 3U, .fill = 0x30U};
    fake.step_count = 2U;

    uint8_t buffer[8] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(50), &received) == PBNS_OK);
    assert(received == 2U);
    assert(buffer[0] == UINT8_C(0x20) && buffer[1] == UINT8_C(0x21));
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(50), &received) == PBNS_OK);
    assert(received == 3U);
    assert(buffer[0] == UINT8_C(0x30) && buffer[2] == UINT8_C(0x32));
    assert(fake.observed_endpoints[0] == UINT8_C(0x82));

    const size_t calls = fake.bulk_calls;
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, 0U}, UINT32_C(50),
                                  &received) == PBNS_ERR_ARGUMENT);
    assert(received == 0U);
    assert(transport.ops->receive(transport.context, (pbns_buffer){NULL, 0U, 1U}, UINT32_C(50),
                                  &received) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 1U, sizeof(buffer)},
                                  UINT32_C(50), &received) == PBNS_ERR_ARGUMENT);
    assert(fake.bulk_calls == calls);
    pbns_usb_transport_destroy(owned);
}

static void test_packet_aligned_receive_retains_surplus_and_close_discards_it(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    fake.steps[0] = (fake_transfer_step){.status = PBNS_OK, .transferred = 128U, .fill = 0x20U};
    fake.steps[1] = (fake_transfer_step){.status = PBNS_OK, .transferred = 3U, .fill = 0x80U};
    fake.step_count = 2U;

    uint8_t first[65] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){first, 0U, sizeof(first)},
                                  UINT32_C(50), &received) == PBNS_OK);
    assert(received == sizeof(first));
    for (size_t index = 0U; index < sizeof(first); ++index) {
        assert(first[index] == (uint8_t)(UINT8_C(0x20) + (uint8_t)index));
    }
    assert(fake.bulk_calls == 1U);
    assert(fake.observed_lengths[0] == 128U);

    uint8_t retained[63] = {0};
    assert(transport.ops->receive(transport.context,
                                  (pbns_buffer){retained, 0U, sizeof(retained)}, UINT32_C(50),
                                  &received) == PBNS_OK);
    assert(received == sizeof(retained));
    for (size_t index = 0U; index < sizeof(retained); ++index) {
        assert(retained[index] == (uint8_t)(UINT8_C(0x61) + (uint8_t)index));
    }
    assert(fake.bulk_calls == 1U);

    assert(transport.ops->close(transport.context) == PBNS_OK);
    assert(transport.ops->open(transport.context) == PBNS_OK);
    uint8_t reopened[5] = {0};
    assert(transport.ops->receive(transport.context, (pbns_buffer){reopened, 0U, sizeof(reopened)},
                                  UINT32_C(50), &received) == PBNS_OK);
    assert(received == 3U);
    assert(reopened[0] == UINT8_C(0x80) && reopened[2] == UINT8_C(0x82));
    assert(fake.bulk_calls == 2U);
    pbns_usb_transport_destroy(owned);
}

static void test_receive_preserves_full_transfer_capacity(void) {
    static uint8_t received_bytes[PBNS_USB_TRANSFER_MAX] = {0};
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    fake.steps[0] = (fake_transfer_step){
        .status = PBNS_OK,
        .transferred = PBNS_USB_TRANSFER_MAX,
        .fill = 0x40U,
    };
    fake.step_count = 1U;

    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context,
                                  (pbns_buffer){received_bytes, 0U, sizeof(received_bytes)},
                                  UINT32_C(50), &received) == PBNS_OK);
    assert(received == sizeof(received_bytes));
    assert(fake.bulk_calls == 1U);
    assert(fake.observed_lengths[0] == PBNS_USB_TRANSFER_MAX);
    for (size_t index = 0U; index < sizeof(received_bytes); ++index) {
        assert(received_bytes[index] == (uint8_t)(UINT8_C(0x40) + (uint8_t)index));
    }
    assert(fake.allocation_count == 1U);
    pbns_usb_transport_destroy(owned);
}

static void test_cached_receive_rejects_zero_timeout_without_clock_or_usb(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    fake.steps[0] = (fake_transfer_step){.status = PBNS_OK, .transferred = 64U, .fill = 0x20U};
    fake.step_count = 1U;

    uint8_t first[5] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){first, 0U, sizeof(first)},
                                  UINT32_C(50), &received) == PBNS_OK);
    const size_t bulk_calls = fake.bulk_calls;
    const size_t now_calls = fake.now_calls;
    uint8_t retained[59] = {0};
    assert(transport.ops->receive(transport.context,
                                  (pbns_buffer){retained, 0U, sizeof(retained)}, 0U,
                                  &received) == PBNS_ERR_ARGUMENT);
    assert(received == 0U);
    assert(fake.bulk_calls == bulk_calls);
    assert(fake.now_calls == now_calls);
    assert(transport.ops->receive(transport.context,
                                  (pbns_buffer){retained, 0U, sizeof(retained)}, UINT32_C(1),
                                  &received) == PBNS_OK);
    assert(received == sizeof(retained));
    assert(fake.bulk_calls == bulk_calls);
    assert(fake.now_calls == now_calls);
    for (size_t index = 0U; index < sizeof(retained); ++index) {
        assert(retained[index] == (uint8_t)(UINT8_C(0x25) + (uint8_t)index));
    }
    pbns_usb_transport_destroy(owned);
}

static void test_receive_zlp_retry(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    fake.steps[0] = (fake_transfer_step){
        .status = PBNS_OK,
        .transferred = 0U,
        .elapsed_ms = UINT64_C(5),
    };
    fake.steps[1] = (fake_transfer_step){.status = PBNS_OK, .transferred = 2U, .fill = 0x40U};
    fake.step_count = 2U;

    uint8_t buffer[4] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(100), &received) == PBNS_OK);
    assert(received == 2U);
    assert(buffer[0] == UINT8_C(0x40) && buffer[1] == UINT8_C(0x41));
    assert(fake.bulk_calls == 2U);
    assert(fake.observed_timeouts[0] == UINT32_C(100));
    assert(fake.observed_timeouts[1] == UINT32_C(95));
    pbns_usb_transport_destroy(owned);

    const pbns_status errors[] = {PBNS_ERR_TRANSPORT, PBNS_ERR_TIMEOUT};
    for (size_t i = 0U; i < sizeof(errors) / sizeof(errors[0]); ++i) {
        fake_init(&fake);
        owned = NULL;
        transport = open_valid_transport(&fake, &owned);
        fake.steps[0] = (fake_transfer_step){.status = PBNS_OK, .transferred = 0U};
        fake.steps[1] = (fake_transfer_step){.status = errors[i]};
        fake.step_count = 2U;
        received = SIZE_MAX;
        assert(transport.ops->receive(transport.context,
                                      (pbns_buffer){buffer, 0U, sizeof(buffer)}, UINT32_C(100),
                                      &received) == errors[i]);
        assert(received == 0U);
        assert(fake.bulk_calls == 2U);
        pbns_usb_transport_destroy(owned);
    }
}

static void test_receive_zlp_retry_allows_four_then_payload(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    for (size_t i = 0U; i < 4U; ++i) {
        fake.steps[i] = (fake_transfer_step){.status = PBNS_OK, .transferred = 0U};
    }
    fake.steps[4] = (fake_transfer_step){.status = PBNS_OK, .transferred = 2U, .fill = 0x50U};
    fake.step_count = 5U;

    uint8_t buffer[4] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(100), &received) == PBNS_OK);
    assert(received == 2U);
    assert(buffer[0] == UINT8_C(0x50) && buffer[1] == UINT8_C(0x51));
    assert(fake.bulk_calls == 5U);
    pbns_usb_transport_destroy(owned);
}

static void test_receive_zlp_retry_rejects_fifth(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    for (size_t i = 0U; i < 5U; ++i) {
        fake.steps[i] = (fake_transfer_step){.status = PBNS_OK, .transferred = 0U};
    }
    fake.step_count = 5U;

    uint8_t buffer[4] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(100), &received) == PBNS_ERR_IO);
    assert(received == 0U);
    assert(fake.bulk_calls == 5U);
    pbns_usb_transport_destroy(owned);
}

static void test_transport_errors_and_stall_reset(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = NULL;
    pbns_transport transport = open_valid_transport(&fake, &owned);
    const uint8_t byte = UINT8_C(0xa5);
    fake.expected_send[0] = byte;
    fake.expected_send_len = 1U;
    fake.steps[0] = (fake_transfer_step){.status = PBNS_ERR_TRANSPORT};
    fake.step_count = 1U;
    assert(transport.ops->send(transport.context, (pbns_view){&byte, 1U}, UINT32_C(10)) ==
           PBNS_ERR_TRANSPORT);
    assert(fake.reset_calls == 0U);
    pbns_usb_transport_destroy(owned);

    fake_init(&fake);
    owned = NULL;
    transport = open_valid_transport(&fake, &owned);
    fake.expected_send[0] = byte;
    fake.expected_send_len = 1U;
    fake.steps[0] = (fake_transfer_step){
        .status = PBNS_ERR_TRANSPORT,
        .usb_status = PBNS_USB_TRANSFER_STALL,
    };
    fake.step_count = 1U;
    assert(transport.ops->send(transport.context, (pbns_view){&byte, 1U}, UINT32_C(10)) ==
           PBNS_ERR_TRANSPORT);
    assert(fake.reset_calls == 1U);
    pbns_usb_transport_destroy(owned);

    fake_init(&fake);
    owned = NULL;
    transport = open_valid_transport(&fake, &owned);
    fake.steps[0] = (fake_transfer_step){.status = PBNS_ERR_TIMEOUT};
    fake.step_count = 1U;
    uint8_t buffer[4] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(10), &received) == PBNS_ERR_TIMEOUT);
    assert(received == 0U);
    pbns_usb_transport_destroy(owned);
}

static void test_api_validation(void) {
    fake_usb fake;
    fake_init(&fake);
    pbns_usb_transport *owned = (void *)&fake;
    assert(pbns_usb_transport_create_from_io(NULL, &owned) == PBNS_ERR_ARGUMENT);
    assert(owned == NULL);
    pbns_usb_io io = fake_io(&fake);
    assert(pbns_usb_transport_create_from_io(&io, NULL) == PBNS_ERR_ARGUMENT);
    io.ops = NULL;
    owned = (void *)&fake;
    assert(pbns_usb_transport_create_from_io(&io, &owned) == PBNS_ERR_ARGUMENT);
    assert(owned == NULL);

    pbns_transport empty = pbns_usb_transport_as_transport(NULL);
    assert(empty.ops == NULL && empty.context == NULL);

    fake_init(&fake);
    pbns_transport transport = open_valid_transport(&fake, &owned);
    const uint8_t byte = 1U;
    uint8_t buffer[1] = {0};
    size_t received = SIZE_MAX;
    assert(transport.ops->open(NULL) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->close(NULL) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->send(NULL, (pbns_view){&byte, 1U}, UINT32_C(1)) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->send(transport.context, (pbns_view){NULL, 1U}, UINT32_C(1)) ==
           PBNS_ERR_ARGUMENT);
    assert(transport.ops->send(transport.context, (pbns_view){&byte, 1U}, 0U) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->send(transport.context, (pbns_view){NULL, 0U}, 0U) == PBNS_OK);
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)},
                                  UINT32_C(1), NULL) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->receive(transport.context, (pbns_buffer){buffer, 0U, sizeof(buffer)}, 0U,
                                  &received) == PBNS_ERR_ARGUMENT);
    assert(received == 0U);
    assert(transport.ops->limits(NULL, NULL) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->limits(transport.context, NULL) == PBNS_ERR_ARGUMENT);
    assert(transport.ops->cancel(NULL, NULL) == PBNS_ERR_ARGUMENT);
    pbns_usb_transport_destroy(owned);
}

static void test_zero_progress_and_closed_state(void) {
    fake_usb fake;
    fake_init(&fake);
    fake_add_valid_device(&fake);
    pbns_usb_transport *owned = NULL;
    assert(create_transport(&fake, &owned) == PBNS_OK);
    pbns_transport transport = pbns_usb_transport_as_transport(owned);
    const uint8_t byte = 1U;
    assert(transport.ops->send(transport.context, (pbns_view){&byte, 1U}, UINT32_C(10)) ==
           PBNS_ERR_STATE);
    assert(transport.ops->open(transport.context) == PBNS_OK);
    fake.expected_send[0] = byte;
    fake.expected_send_len = 1U;
    fake.steps[0] = (fake_transfer_step){.status = PBNS_OK, .transferred = 0U};
    fake.step_count = 1U;
    assert(transport.ops->send(transport.context, (pbns_view){&byte, 1U}, UINT32_C(10)) ==
           PBNS_ERR_IO);
    pbns_usb_transport_destroy(owned);
}

int main(void) {
    test_discovery_rejections();
    test_lifecycle_limits_and_allocation();
    test_control_line_failures();
    test_short_send_and_deadline();
    test_send_accepts_ciphertext_larger_than_pbns_frame();
    test_fragmented_receive_and_invalid_buffers();
    test_packet_aligned_receive_retains_surplus_and_close_discards_it();
    test_receive_preserves_full_transfer_capacity();
    test_cached_receive_rejects_zero_timeout_without_clock_or_usb();
    test_receive_zlp_retry();
    test_receive_zlp_retry_allows_four_then_payload();
    test_receive_zlp_retry_rejects_fifth();
    test_transport_errors_and_stall_reset();
    test_api_validation();
    test_zero_progress_and_closed_state();
    return 0;
}
