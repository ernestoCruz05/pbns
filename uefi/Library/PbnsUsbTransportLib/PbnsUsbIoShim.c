#include <Uefi.h>

#include <Library/PbnsUefiPlatformLib.h>
#include <Protocol/UsbIo.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "PbnsUsbIoShim.h"

#define PBNS_USB_CDC_REQUEST_TYPE UINT8_C(0x21)
#define PBNS_USB_CDC_SET_CONTROL_LINE_STATE UINT8_C(0x22)
#define PBNS_USB_CDC_DTR UINT16_C(0x0001)
#define PBNS_USB_CONTROL_TIMEOUT_MS UINT32_C(1000)

static pbns_status
map_transfer_status (
  EFI_STATUS  Status,
  UINT32      TransferStatus
  )
{
  if (!EFI_ERROR (Status) && TransferStatus == EFI_USB_NOERROR) {
    return PBNS_OK;
  }
  if (Status == EFI_TIMEOUT ||
      (TransferStatus & EFI_USB_ERR_TIMEOUT) != 0U) {
    return PBNS_ERR_TIMEOUT;
  }
  if (Status == EFI_OUT_OF_RESOURCES) {
    return PBNS_ERR_RESOURCE;
  }
  return PBNS_ERR_TRANSPORT;
}

static pbns_status
read_product (
  EFI_BOOT_SERVICES    *BootServices,
  EFI_USB_IO_PROTOCOL  *UsbIo,
  UINT8                StringId,
  UINT8                Product[PBNS_USB_PRODUCT_MAX],
  size_t               *ProductLength
  )
{
  *ProductLength = 0U;
  if (StringId == 0U) {
    return PBNS_OK;
  }

  UINT16     *Languages = NULL;
  UINT16     TableSize = 0U;
  EFI_STATUS Status = UsbIo->UsbGetSupportedLanguages (
                               UsbIo,
                               &Languages,
                               &TableSize
                               );
  if (EFI_ERROR (Status) || Languages == NULL ||
      TableSize < sizeof (*Languages) ||
      (TableSize % sizeof (*Languages)) != 0U) {
    return PBNS_OK;
  }

  size_t LanguageCount = TableSize / sizeof (*Languages);
  if (LanguageCount > PBNS_USB_PRODUCT_MAX) {
    LanguageCount = PBNS_USB_PRODUCT_MAX;
  }
  for (size_t Index = 0U; Index < LanguageCount; ++Index) {
    CHAR16 *String = NULL;
    Status = UsbIo->UsbGetStringDescriptor (
                      UsbIo,
                      Languages[Index],
                      StringId,
                      &String
                      );
    if (Status == EFI_OUT_OF_RESOURCES) {
      return PBNS_ERR_RESOURCE;
    }
    if (EFI_ERROR (Status) || String == NULL) {
      continue;
    }

    bool Valid = false;
    size_t Length = 0U;
    while (Length < PBNS_USB_PRODUCT_MAX) {
      if (String[Length] == L'\0') {
        Valid = true;
        break;
      }
      if (String[Length] > MAX_UINT8) {
        break;
      }
      Product[Length] = (UINT8)String[Length];
      ++Length;
    }
    EFI_STATUS FreeStatus = BootServices->FreePool (String);
    if (EFI_ERROR (FreeStatus)) {
      return PBNS_ERR_IO;
    }
    if (Valid) {
      *ProductLength = Length;
      return PBNS_OK;
    }
  }
  return PBNS_OK;
}

static pbns_status
visit_usb_interface (
  EFI_BOOT_SERVICES       *BootServices,
  EFI_HANDLE              DeviceHandle,
  EFI_USB_IO_PROTOCOL     *UsbIo,
  pbns_usb_device_visitor Visitor,
  void                    *VisitorContext
  )
{
  EFI_USB_DEVICE_DESCRIPTOR DeviceDescriptor;
  EFI_USB_INTERFACE_DESCRIPTOR InterfaceDescriptor;
  EFI_STATUS Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, &DeviceDescriptor);
  if (EFI_ERROR (Status)) {
    return PBNS_OK;
  }
  Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &InterfaceDescriptor);
  if (EFI_ERROR (Status)) {
    return PBNS_OK;
  }

  UINT8 Product[PBNS_USB_PRODUCT_MAX] = { 0 };
  size_t ProductLength = 0U;
  pbns_status PbnsStatus = PBNS_OK;
  if (DeviceDescriptor.IdVendor == PBNS_USB_VENDOR_ID &&
      DeviceDescriptor.IdProduct == PBNS_USB_PRODUCT_ID &&
      InterfaceDescriptor.InterfaceNumber == PBNS_USB_CDC_DATA_INTERFACE &&
      InterfaceDescriptor.InterfaceClass == PBNS_USB_CDC_DATA_CLASS) {
    PbnsStatus = read_product (
                   BootServices,
                   UsbIo,
                   DeviceDescriptor.StrProduct,
                   Product,
                   &ProductLength
                   );
    if (PbnsStatus != PBNS_OK) {
      return PbnsStatus;
    }
  }

  pbns_usb_endpoint Endpoints[PBNS_USB_ENDPOINT_MAX] = { 0 };
  size_t EndpointCount = InterfaceDescriptor.NumEndpoints;
  if (EndpointCount > PBNS_USB_ENDPOINT_MAX) {
    EndpointCount = 0U;
  }
  for (size_t Index = 0U; Index < EndpointCount; ++Index) {
    EFI_USB_ENDPOINT_DESCRIPTOR EndpointDescriptor;
    Status = UsbIo->UsbGetEndpointDescriptor (
                      UsbIo,
                      (UINT8)Index,
                      &EndpointDescriptor
                      );
    if (EFI_ERROR (Status)) {
      EndpointCount = 0U;
      break;
    }
    Endpoints[Index] = (pbns_usb_endpoint){
      .address = EndpointDescriptor.EndpointAddress,
      .attributes = EndpointDescriptor.Attributes,
      .max_packet_size = EndpointDescriptor.MaxPacketSize,
    };
  }

  const pbns_usb_device_description Description = {
    .device = DeviceHandle,
    .vendor_id = DeviceDescriptor.IdVendor,
    .product_id = DeviceDescriptor.IdProduct,
    .interface_number = InterfaceDescriptor.InterfaceNumber,
    .interface_class = InterfaceDescriptor.InterfaceClass,
    .product = { .ptr = Product, .len = ProductLength },
    .endpoints = Endpoints,
    .endpoint_count = EndpointCount,
  };
  return Visitor (VisitorContext, &Description);
}

static pbns_status
enumerate_interfaces (
  void                    *Context,
  pbns_usb_device_visitor Visitor,
  void                    *VisitorContext
  )
{
  EFI_BOOT_SERVICES *BootServices = Context;
  if (BootServices == NULL || Visitor == NULL) {
    return PBNS_ERR_ARGUMENT;
  }

  EFI_HANDLE *Handles = NULL;
  UINTN HandleCount = 0U;
  EFI_STATUS Status = BootServices->LocateHandleBuffer (
                                      ByProtocol,
                                      &gEfiUsbIoProtocolGuid,
                                      NULL,
                                      &HandleCount,
                                      &Handles
                                      );
  if (Status == EFI_NOT_FOUND) {
    return PBNS_OK;
  }
  if (Status == EFI_OUT_OF_RESOURCES) {
    return PBNS_ERR_RESOURCE;
  }
  if (EFI_ERROR (Status) || Handles == NULL) {
    return PBNS_ERR_TRANSPORT;
  }

  pbns_status Result = PBNS_OK;
  for (UINTN Index = 0U; Index < HandleCount; ++Index) {
    EFI_USB_IO_PROTOCOL *UsbIo = NULL;
    Status = BootServices->HandleProtocol (
                             Handles[Index],
                             &gEfiUsbIoProtocolGuid,
                             (VOID **)&UsbIo
                             );
    if (EFI_ERROR (Status) || UsbIo == NULL) {
      continue;
    }
    Result = visit_usb_interface (
               BootServices,
               Handles[Index],
               UsbIo,
               Visitor,
               VisitorContext
               );
    if (Result != PBNS_OK) {
      break;
    }
  }
  EFI_STATUS FreeStatus = BootServices->FreePool ((VOID *)Handles);
  if (Result == PBNS_OK && EFI_ERROR (FreeStatus)) {
    Result = PBNS_ERR_IO;
  }
  return Result;
}

static pbns_status
bulk_transfer (
  void      *Context,
  void      *Device,
  uint8_t   Endpoint,
  uint8_t   *Bytes,
  size_t    *Length,
  uint32_t  TimeoutMs,
  uint32_t  *UsbStatus
  )
{
  EFI_BOOT_SERVICES *BootServices = Context;
  if (BootServices == NULL || Device == NULL || Bytes == NULL || Length == NULL ||
      UsbStatus == NULL || TimeoutMs == 0U) {
    return PBNS_ERR_ARGUMENT;
  }

  EFI_USB_IO_PROTOCOL *UsbIo = NULL;
  EFI_STATUS Status = BootServices->HandleProtocol (
                                      (EFI_HANDLE)Device,
                                      &gEfiUsbIoProtocolGuid,
                                      (VOID **)&UsbIo
                                      );
  if (EFI_ERROR (Status) || UsbIo == NULL) {
    return PBNS_ERR_TRANSPORT;
  }
  UINTN TransferLength = *Length;
  UINT32 TransferStatus = EFI_USB_NOERROR;
  Status = UsbIo->UsbBulkTransfer (
                   UsbIo,
                   Endpoint,
                   Bytes,
                   &TransferLength,
                   TimeoutMs,
                   &TransferStatus
                   );
  *Length = TransferLength;
  *UsbStatus = (TransferStatus & EFI_USB_ERR_STALL) != 0U
                   ? PBNS_USB_TRANSFER_STALL
                   : 0U;
  return map_transfer_status (Status, TransferStatus);
}

static pbns_status
reset_device (
  void  *Context,
  void  *Device
  )
{
  EFI_BOOT_SERVICES *BootServices = Context;
  if (BootServices == NULL || Device == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  EFI_USB_IO_PROTOCOL *UsbIo = NULL;
  EFI_STATUS Status = BootServices->HandleProtocol (
                                      (EFI_HANDLE)Device,
                                      &gEfiUsbIoProtocolGuid,
                                      (VOID **)&UsbIo
                                      );
  if (EFI_ERROR (Status) || UsbIo == NULL) {
    return PBNS_ERR_TRANSPORT;
  }
  return EFI_ERROR (UsbIo->UsbPortReset (UsbIo))
             ? PBNS_ERR_TRANSPORT
             : PBNS_OK;
}

static pbns_status
set_connected (
  void  *Context,
  void  *Device,
  bool  Connected
  )
{
  EFI_BOOT_SERVICES *BootServices = Context;
  if (BootServices == NULL || Device == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  EFI_USB_IO_PROTOCOL *UsbIo = NULL;
  EFI_STATUS Status = BootServices->HandleProtocol (
                                      (EFI_HANDLE)Device,
                                      &gEfiUsbIoProtocolGuid,
                                      (VOID **)&UsbIo
                                      );
  if (EFI_ERROR (Status) || UsbIo == NULL) {
    return PBNS_ERR_TRANSPORT;
  }

  EFI_USB_DEVICE_REQUEST Request = {
    .RequestType = PBNS_USB_CDC_REQUEST_TYPE,
    .Request = PBNS_USB_CDC_SET_CONTROL_LINE_STATE,
    .Value = Connected ? PBNS_USB_CDC_DTR : 0U,
    .Index = PBNS_USB_CDC_CONTROL_INTERFACE,
    .Length = 0U,
  };
  UINT32 TransferStatus = EFI_USB_NOERROR;
  Status = UsbIo->UsbControlTransfer (
                    UsbIo,
                    &Request,
                    EfiUsbNoData,
                    PBNS_USB_CONTROL_TIMEOUT_MS,
                    NULL,
                    0U,
                    &TransferStatus
                    );
  return map_transfer_status (Status, TransferStatus);
}

static pbns_status
monotonic_ms (
  void      *Context,
  uint64_t  *NowMs
  )
{
  EFI_BOOT_SERVICES  *BootServices = Context;
  UINT64             Current = 0U;
  EFI_STATUS         Status;

  if (BootServices == NULL || NowMs == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *NowMs = 0U;
  Status = PbnsUefiMonotonicMs (BootServices, &Current);
  if (Status == EFI_INVALID_PARAMETER) {
    return PBNS_ERR_ARGUMENT;
  }
  if (Status == EFI_UNSUPPORTED) {
    return PBNS_ERR_UNSUPPORTED;
  }
  if (EFI_ERROR (Status)) {
    return PBNS_ERR_TRANSPORT;
  }
  *NowMs = (uint64_t)Current;
  return PBNS_OK;
}

static void *
allocate_context (
  void    *Context,
  size_t  Size
  )
{
  EFI_BOOT_SERVICES *BootServices = Context;
  if (BootServices == NULL || Size == 0U) {
    return NULL;
  }
  VOID *Allocation = NULL;
  EFI_STATUS Status = BootServices->AllocatePool (
                                      EfiLoaderData,
                                      Size,
                                      &Allocation
                                      );
  return EFI_ERROR (Status) ? NULL : Allocation;
}

static void
deallocate_context (
  void  *Context,
  void  *Allocation
  )
{
  EFI_BOOT_SERVICES *BootServices = Context;
  if (BootServices != NULL && Allocation != NULL) {
    (void)BootServices->FreePool (Allocation);
  }
}

static const pbns_usb_io_ops mUsbIoOps = {
  .enumerate = enumerate_interfaces,
  .bulk = bulk_transfer,
  .reset = reset_device,
  .set_connected = set_connected,
  .now_ms = monotonic_ms,
  .allocate = allocate_context,
  .deallocate = deallocate_context,
};

pbns_status
pbns_usb_io_shim_init (
  EFI_BOOT_SERVICES  *BootServices,
  pbns_usb_io        *Io
  )
{
  if (Io == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Io = (pbns_usb_io){ 0 };
  if (BootServices == NULL ||
      BootServices->AllocatePool == NULL ||
      BootServices->FreePool == NULL ||
      BootServices->LocateHandleBuffer == NULL ||
      BootServices->HandleProtocol == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *Io = (pbns_usb_io){ .ops = &mUsbIoOps, .context = BootServices };
  return PBNS_OK;
}
