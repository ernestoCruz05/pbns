#ifndef PBNS_USB_TRANSPORT_LIB_H
#define PBNS_USB_TRANSPORT_LIB_H

#include "pbns/transport.h"

typedef struct pbns_usb_transport pbns_usb_transport;

#if defined(PBNS_UEFI_BUILD) || defined(MDE_CPU_X64)
#include <Uefi.h>

pbns_status pbns_usb_transport_create(EFI_BOOT_SERVICES *boot_services,
                                      pbns_usb_transport **result);
#endif

void pbns_usb_transport_destroy(pbns_usb_transport *transport);
/* CDC0 é um fluxo ordenado inferior; só o wrapper TLS expõe limites ao broker. */
pbns_transport pbns_usb_transport_as_transport(pbns_usb_transport *transport);

#endif
