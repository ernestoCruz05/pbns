#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pico/unique_id.h"
#include "tusb.h"

#define PBNS_USB_VID UINT16_C(0xcafe)
#define PBNS_USB_PID UINT16_C(0x4011)
#define PBNS_USB_BCD UINT16_C(0x0200)
#define PBNS_STRING_CAPACITY 32U
#define PBNS_CONFIG_TOTAL_LENGTH (TUD_CONFIG_DESC_LEN + 2U * TUD_CDC_DESC_LEN)

enum interface_number {
  INTERFACE_CDC_DATA_CONTROL = 0,
  INTERFACE_CDC_DATA,
  INTERFACE_CDC_PROVISION_CONTROL,
  INTERFACE_CDC_PROVISION,
  INTERFACE_COUNT
};

enum string_index {
  STRING_LANGUAGE = 0,
  STRING_MANUFACTURER,
  STRING_PRODUCT,
  STRING_SERIAL,
  STRING_DATA_INTERFACE,
  STRING_PROVISION_INTERFACE,
  STRING_COUNT
};

static const tusb_desc_device_t device_descriptor = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = PBNS_USB_BCD,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = PBNS_USB_VID,
    .idProduct = PBNS_USB_PID,
    .bcdDevice = UINT16_C(0x0100),
    .iManufacturer = STRING_MANUFACTURER,
    .iProduct = STRING_PRODUCT,
    .iSerialNumber = STRING_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, INTERFACE_COUNT, 0, PBNS_CONFIG_TOTAL_LENGTH, 0,
                          100),
    TUD_CDC_DESCRIPTOR(INTERFACE_CDC_DATA_CONTROL, STRING_DATA_INTERFACE, 0x81,
                       8, 0x02, 0x82, 64),
    TUD_CDC_DESCRIPTOR(INTERFACE_CDC_PROVISION_CONTROL,
                       STRING_PROVISION_INTERFACE, 0x83, 8, 0x04, 0x84, 64),
};

static const char *const string_descriptors[STRING_COUNT] = {
    NULL, "PBNS Research", "PBNS Proxy v1", NULL, "PBNS Data", "PBNS Provision",
};

static uint16_t string_descriptor[PBNS_STRING_CAPACITY + 1U] = {0};
static char serial_number[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2U + 1U] = {0};

const uint8_t *tud_descriptor_device_cb(void) {
  return (const uint8_t *)&device_descriptor;
}

const uint8_t *tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  return configuration_descriptor;
}

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t language_id) {
  (void)language_id;
  size_t character_count = 0U;
  if (index == STRING_LANGUAGE) {
    string_descriptor[1] = UINT16_C(0x0409);
    character_count = 1U;
  } else {
    if (index >= STRING_COUNT) {
      return NULL;
    }
    const char *text = string_descriptors[index];
    if (index == STRING_SERIAL) {
      pico_get_unique_board_id_string(serial_number,
                                      (uint)sizeof(serial_number));
      text = serial_number;
    }
    if (text == NULL) {
      return NULL;
    }
    character_count = strlen(text);
    if (character_count > PBNS_STRING_CAPACITY) {
      character_count = PBNS_STRING_CAPACITY;
    }
    for (size_t position = 0U; position < character_count; ++position) {
      string_descriptor[position + 1U] = (uint16_t)(uint8_t)text[position];
    }
  }
  string_descriptor[0] = (uint16_t)(((uint16_t)TUSB_DESC_STRING << 8U) |
                                    (uint16_t)(2U * character_count + 2U));
  return string_descriptor;
}
