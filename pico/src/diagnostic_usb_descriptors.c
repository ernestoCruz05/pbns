#include "pbns_proxy/diagnostic_usb.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "pbns_proxy/diagnostic.h"
#include "pico/unique_id.h"
#include "tusb.h"

#define PBNS_DIAGNOSTIC_USB_VID UINT16_C(0xcafe)
#define PBNS_DIAGNOSTIC_USB_PID UINT16_C(0x40d1)
#define PBNS_DIAGNOSTIC_USB_BCD UINT16_C(0x0200)
#define PBNS_DIAGNOSTIC_STRING_CAPACITY 32U
#define PBNS_DIAGNOSTIC_CONFIG_TOTAL_LENGTH                                    \
  (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN)

enum interface_number {
  INTERFACE_CDC_CONTROL = 0,
  INTERFACE_CDC_DATA,
  INTERFACE_COUNT
};

enum string_index {
  STRING_LANGUAGE = 0,
  STRING_MANUFACTURER,
  STRING_PRODUCT,
  STRING_SERIAL,
  STRING_CDC_INTERFACE,
  STRING_COUNT
};

static tusb_desc_device_t device_descriptor = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = PBNS_DIAGNOSTIC_USB_BCD,
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = PBNS_DIAGNOSTIC_USB_VID,
    .idProduct = PBNS_DIAGNOSTIC_USB_PID,
    .bcdDevice = PBNS_DIAGNOSTIC_AWAITING_DTR,
    .iManufacturer = STRING_MANUFACTURER,
    .iProduct = STRING_PRODUCT,
    .iSerialNumber = STRING_SERIAL,
    .bNumConfigurations = 1,
};

static const uint8_t configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, INTERFACE_COUNT, 0,
                          PBNS_DIAGNOSTIC_CONFIG_TOTAL_LENGTH, 0, 100),
    TUD_CDC_DESCRIPTOR(INTERFACE_CDC_CONTROL, STRING_CDC_INTERFACE, 0x81, 8,
                       0x02, 0x82, 64),
};

static const char *const string_descriptors[STRING_COUNT] = {
    NULL, "PBNS Research",           "PBNS Network Diagnostic v1",
    NULL, "PBNS Diagnostic Trigger",
};

static uint16_t string_descriptor[PBNS_DIAGNOSTIC_STRING_CAPACITY + 1U] = {0};
static char serial_number[PICO_UNIQUE_BOARD_ID_SIZE_BYTES * 2U + 1U] = {0};

bool pbns_diagnostic_usb_set_bcd_device(uint16_t bcd_device) {
  const pbns_diagnostic_result result = (pbns_diagnostic_result)bcd_device;
  if (result != PBNS_DIAGNOSTIC_AWAITING_DTR &&
      !pbns_diagnostic_result_is_terminal(result)) {
    return false;
  }
  device_descriptor.bcdDevice = bcd_device;
  return true;
}

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
    if (character_count > PBNS_DIAGNOSTIC_STRING_CAPACITY) {
      character_count = PBNS_DIAGNOSTIC_STRING_CAPACITY;
    }
    for (size_t position = 0U; position < character_count; ++position) {
      string_descriptor[position + 1U] = (uint16_t)(uint8_t)text[position];
    }
  }
  string_descriptor[0] = (uint16_t)(((uint16_t)TUSB_DESC_STRING << 8U) |
                                    (uint16_t)(2U * character_count + 2U));
  return string_descriptor;
}
