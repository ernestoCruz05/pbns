#ifndef PBNS_USB_IO_SHIM_H
#define PBNS_USB_IO_SHIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "PbnsUsbTransportLib.h"
#include "pbns/buffer.h"
#include "pbns/status.h"

#define PBNS_USB_VENDOR_ID UINT16_C(0xcafe)
#define PBNS_USB_PRODUCT_ID UINT16_C(0x4011)
#define PBNS_USB_CDC_DATA_CLASS UINT8_C(0x0a)
#define PBNS_USB_CDC_CONTROL_INTERFACE UINT8_C(0)
#define PBNS_USB_CDC_DATA_INTERFACE UINT8_C(1)
#define PBNS_USB_ENDPOINT_DIRECTION_IN UINT8_C(0x80)
#define PBNS_USB_ENDPOINT_TRANSFER_MASK UINT8_C(0x03)
#define PBNS_USB_ENDPOINT_TRANSFER_BULK UINT8_C(0x02)
#define PBNS_USB_TRANSFER_STALL UINT32_C(0x01)
#define PBNS_USB_ENDPOINT_MAX 32U
#define PBNS_USB_PRODUCT_MAX 32U
#define PBNS_USB_TRANSFER_MAX 16384U
#define PBNS_USB_RECEIVE_STAGING_MAX PBNS_USB_TRANSFER_MAX

typedef struct pbns_usb_endpoint {
    uint8_t address;
    uint8_t attributes;
    uint16_t max_packet_size;
} pbns_usb_endpoint;

typedef struct pbns_usb_device_description {
    void *device;
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t interface_number;
    uint8_t interface_class;
    pbns_view product;
    const pbns_usb_endpoint *endpoints;
    size_t endpoint_count;
} pbns_usb_device_description;

typedef pbns_status (*pbns_usb_device_visitor)(void *context,
                                               const pbns_usb_device_description *description);

typedef struct pbns_usb_io_ops {
    pbns_status (*enumerate)(void *context, pbns_usb_device_visitor visitor, void *visitor_context);
    pbns_status (*bulk)(void *context, void *device, uint8_t endpoint, uint8_t *bytes,
                        size_t *length, uint32_t timeout_ms, uint32_t *usb_status);
    pbns_status (*reset)(void *context, void *device);
    pbns_status (*set_connected)(void *context, void *device, bool connected);
    pbns_status (*now_ms)(void *context, uint64_t *now_ms);
    void *(*allocate)(void *context, size_t size);
    void (*deallocate)(void *context, void *allocation);
} pbns_usb_io_ops;

typedef struct pbns_usb_io {
    const pbns_usb_io_ops *ops;
    void *context;
} pbns_usb_io;

pbns_status pbns_usb_transport_create_from_io(const pbns_usb_io *io, pbns_usb_transport **result);

#if defined(PBNS_UEFI_BUILD)
#include <Uefi.h>

pbns_status pbns_usb_io_shim_init(EFI_BOOT_SERVICES *boot_services, pbns_usb_io *io);
#endif

#endif
