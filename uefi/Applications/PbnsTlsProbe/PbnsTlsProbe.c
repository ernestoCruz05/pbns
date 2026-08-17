#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>

#include <stdbool.h>

#include "PbnsTlsTransportLib.h"
#include "pbns/tls_transport.h"

static const uint8_t FIXTURE_SPKI_SHA256[32] = {
    0xa0U, 0xd2U, 0x19U, 0x23U, 0xddU, 0xfcU, 0xcbU, 0xa1U, 0x2dU, 0x0aU, 0x7bU,
    0xbdU, 0x74U, 0x08U, 0x65U, 0x0cU, 0xb8U, 0xc5U, 0x4fU, 0x1bU, 0xe5U, 0x37U,
    0xfeU, 0x3aU, 0x7eU, 0x69U, 0xadU, 0xb1U, 0x37U, 0x6dU, 0xa1U, 0x06U,
};

static EFI_BOOT_SERVICES *backing_boot_services;
static UINTN allocation_calls;
static UINTN free_calls;
static UINTN fail_allocate_call;
static UINTN fail_free_first_call;
static UINTN fail_free_call_count;

static pbns_status local_open(void *context) {
  (void)context;
  return PBNS_OK;
}

static pbns_status local_close(void *context) {
  (void)context;
  return PBNS_OK;
}

static pbns_status local_send(void *context, pbns_view bytes,
                              uint32_t timeout_ms) {
  (void)context;
  (void)bytes;
  (void)timeout_ms;
  return PBNS_ERR_WOULD_BLOCK;
}

static pbns_status local_receive(void *context, pbns_buffer buffer,
                                 uint32_t timeout_ms, size_t *received) {
  (void)context;
  (void)buffer;
  (void)timeout_ms;
  if (received == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *received = 0U;
  return PBNS_ERR_WOULD_BLOCK;
}

static pbns_status local_cancel(void *context,
                                const pbns_request_id *request_id) {
  (void)context;
  (void)request_id;
  return PBNS_OK;
}

static pbns_status local_limits(void *context, pbns_frame_limits *limits) {
  (void)context;
  if (limits == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *limits = (pbns_frame_limits){
      .control_payload_max = PBNS_FRAME_V1_CONTROL_PAYLOAD_MAX,
      .data_payload_max = PBNS_FRAME_V1_DATA_PAYLOAD_MAX,
      .encoded_record_max = PBNS_FRAME_V1_WIRE_MAX,
  };
  return PBNS_OK;
}

static const pbns_transport_ops local_transport_ops = {
    .open = local_open,
    .close = local_close,
    .send = local_send,
    .receive = local_receive,
    .cancel = local_cancel,
    .limits = local_limits,
};

static EFI_STATUS EFIAPI probe_allocate_pool(EFI_MEMORY_TYPE pool_type,
                                             UINTN size, VOID **buffer) {
  ++allocation_calls;
  if (fail_allocate_call != 0U && allocation_calls == fail_allocate_call) {
    if (buffer != NULL) {
      *buffer = NULL;
    }
    return EFI_OUT_OF_RESOURCES;
  }
  return backing_boot_services->AllocatePool(pool_type, size, buffer);
}

static EFI_STATUS EFIAPI probe_free_pool(VOID *buffer) {
  ++free_calls;
  if (fail_free_first_call != 0U && free_calls >= fail_free_first_call &&
      free_calls - fail_free_first_call < fail_free_call_count) {
    return EFI_DEVICE_ERROR;
  }
  return backing_boot_services->FreePool(buffer);
}

static void clear_failures(void) {
  fail_allocate_call = 0U;
  fail_free_first_call = 0U;
  fail_free_call_count = 0U;
}

static bool create_valid(EFI_BOOT_SERVICES *boot_services,
                         PBNS_TLS_UEFI_TRANSPORT **transport) {
  const pbns_transport lower = {.ops = &local_transport_ops, .context = NULL};
  const pbns_tls_client_config config = {
      .expected_server_name = {.ptr = (const uint8_t *)"192.168.1.180",
                               .len = sizeof("192.168.1.180") - 1U},
      .pinned_leaf_spki_sha256 = {.ptr = FIXTURE_SPKI_SHA256,
                                  .len = sizeof(FIXTURE_SPKI_SHA256)},
      .handshake_timeout_ms = 1000U,
  };
  return PbnsTlsTransportCreate(boot_services, lower, &config, NULL,
                                transport) == PBNS_OK &&
         *transport != NULL;
}

static bool allocation_balance(PBNS_TLS_UEFI_TRANSPORT *transport,
                               size_t expected_count) {
  PBNS_TLS_UEFI_ALLOCATION_STATS stats = {0};
  return PbnsTlsTransportAllocationStats(transport, &stats) == PBNS_OK &&
         stats.allocation_count == expected_count &&
         stats.current_bytes <= PBNS_TLS_UEFI_POOL_CAP &&
         stats.peak_bytes <= PBNS_TLS_UEFI_POOL_CAP &&
         stats.release_failures == 0U;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle,
                           EFI_SYSTEM_TABLE *SystemTable) {
  (void)ImageHandle;
  if (SystemTable == NULL || SystemTable->BootServices == NULL) {
    Print(L"PBNS UEFI TLS LINK PROBE FAIL\r\n");
    return EFI_COMPROMISED_DATA;
  }
  backing_boot_services = SystemTable->BootServices;
  EFI_BOOT_SERVICES test_boot_services = *backing_boot_services;
  test_boot_services.AllocatePool = probe_allocate_pool;
  test_boot_services.FreePool = probe_free_pool;
  const pbns_transport lower = {.ops = &local_transport_ops, .context = NULL};
  EFI_BOOT_SERVICES no_tpl_boot_services = test_boot_services;
  no_tpl_boot_services.RaiseTPL = NULL;
  const pbns_tls_client_config valid_config = {
      .expected_server_name = {.ptr = (const uint8_t *)"192.168.1.180",
                               .len = sizeof("192.168.1.180") - 1U},
      .pinned_leaf_spki_sha256 = {.ptr = FIXTURE_SPKI_SHA256,
                                  .len = sizeof(FIXTURE_SPKI_SHA256)},
      .handshake_timeout_ms = 1000U,
  };
  const uint8_t short_pin[31] = {0};
  const pbns_tls_client_config short_pin_config = {
      .expected_server_name = valid_config.expected_server_name,
      .pinned_leaf_spki_sha256 = {.ptr = short_pin, .len = sizeof(short_pin)},
      .handshake_timeout_ms = valid_config.handshake_timeout_ms,
  };
  const pbns_tls_client_config null_pin_config = {
      .expected_server_name = valid_config.expected_server_name,
      .pinned_leaf_spki_sha256 = {.ptr = NULL, .len = 32U},
      .handshake_timeout_ms = valid_config.handshake_timeout_ms,
  };
  const pbns_tls_client_config zero_pin_config = {
      .expected_server_name = valid_config.expected_server_name,
      .pinned_leaf_spki_sha256 = {.ptr = NULL, .len = 0U},
      .handshake_timeout_ms = valid_config.handshake_timeout_ms,
  };
  const pbns_tls_client_config empty_endpoint_config = {
      .expected_server_name = {.ptr = NULL, .len = 0U},
      .pinned_leaf_spki_sha256 = valid_config.pinned_leaf_spki_sha256,
      .handshake_timeout_ms = valid_config.handshake_timeout_ms,
  };
  PBNS_TLS_UEFI_TRANSPORT *transport = NULL;
  bool passed =
      PbnsTlsTransportCreate(&no_tpl_boot_services, lower, &valid_config, NULL,
                             &transport) == PBNS_ERR_ARGUMENT &&
      transport == NULL &&
      PbnsTlsTransportCreate(&test_boot_services, lower, NULL, NULL,
                             &transport) == PBNS_ERR_ARGUMENT &&
      transport == NULL &&
      PbnsTlsTransportCreate(&test_boot_services, lower, &short_pin_config,
                             NULL, &transport) == PBNS_ERR_ARGUMENT &&
      transport == NULL &&
      PbnsTlsTransportCreate(&test_boot_services, lower, &null_pin_config, NULL,
                             &transport) == PBNS_ERR_ARGUMENT &&
      transport == NULL &&
      PbnsTlsTransportCreate(&test_boot_services, lower, &zero_pin_config, NULL,
                             &transport) == PBNS_ERR_ARGUMENT &&
      transport == NULL &&
      PbnsTlsTransportCreate(&test_boot_services, lower, &empty_endpoint_config,
                             NULL, &transport) == PBNS_ERR_ARGUMENT &&
      transport == NULL;

  clear_failures();
  fail_allocate_call = allocation_calls + 1U;
  passed = passed &&
           PbnsTlsTransportCreate(&test_boot_services, lower, &valid_config,
                                  NULL, &transport) == PBNS_ERR_RESOURCE &&
           transport == NULL;
  clear_failures();
  fail_allocate_call = allocation_calls + 2U;
  passed = passed &&
           PbnsTlsTransportCreate(&test_boot_services, lower, &valid_config,
                                  NULL, &transport) == PBNS_ERR_RESOURCE &&
           transport == NULL;
  clear_failures();
  fail_allocate_call = allocation_calls + 2U;
  fail_free_first_call = free_calls + 1U;
  fail_free_call_count = 1U;
  passed = passed &&
           PbnsTlsTransportCreate(&test_boot_services, lower, &valid_config,
                                  NULL, &transport) == PBNS_ERR_IO &&
           transport != NULL;
  PBNS_TLS_UEFI_ALLOCATION_STATS failed_create_stats = {0};
  pbns_view failed_create_region = {(const uint8_t *)(UINTN)1U, 1U};
  passed = passed &&
           PbnsTlsTransportAllocationStats(transport, &failed_create_stats) ==
               PBNS_OK &&
           failed_create_stats.allocation_count == 1U &&
           failed_create_stats.release_failures == 1U &&
           PbnsTlsTransportContextRegion(transport, &failed_create_region) ==
               EFI_NOT_READY &&
           failed_create_region.ptr == NULL &&
           failed_create_region.len == 0U &&
           PbnsTlsTransportDestroy(transport) == PBNS_OK;
  transport = NULL;
  clear_failures();

  PBNS_TLS_UEFI_TRANSPORT *second_transport = NULL;
  passed = passed && create_valid(&test_boot_services, &transport) &&
           allocation_balance(transport, 2U) &&
           PbnsTlsTransportCreate(&test_boot_services, lower, &valid_config,
                                  NULL, &second_transport) == PBNS_ERR_BUSY &&
           second_transport == NULL;
  const pbns_transport guarded_transport =
      PbnsTlsTransportAsTransport(transport);
  pbns_view tpl_region = {(const uint8_t *)(UINTN)1U, 1U};
  const EFI_TPL application_tpl = test_boot_services.RaiseTPL(TPL_CALLBACK);
  PBNS_TLS_UEFI_ALLOCATION_STATS rejected_stats = {0};
  const bool tpl_rejected =
      PbnsTlsTransportContextRegion(transport, &tpl_region) == EFI_NOT_READY &&
      tpl_region.ptr == NULL && tpl_region.len == 0U &&
      PbnsTlsTransportAsTransport(transport).ops == NULL &&
      PbnsTlsTransportAllocationStats(transport, &rejected_stats) ==
          PBNS_ERR_STATE &&
      PbnsTlsTransportDestroy(transport) == PBNS_ERR_STATE &&
      guarded_transport.ops->close(guarded_transport.context) == PBNS_ERR_STATE;
  test_boot_services.RestoreTPL(application_tpl);
  passed = passed && tpl_rejected;

  fail_free_first_call = free_calls + 1U;
  fail_free_call_count = 2U;
  passed = passed && PbnsTlsTransportDestroy(transport) == PBNS_ERR_IO;
  PBNS_TLS_UEFI_ALLOCATION_STATS failed_inner_stats = {0};
  passed = passed &&
           PbnsTlsTransportAllocationStats(transport, &failed_inner_stats) ==
               PBNS_OK &&
           failed_inner_stats.allocation_count == 2U &&
           failed_inner_stats.release_failures == 1U &&
           PbnsTlsTransportDestroy(transport) == PBNS_ERR_IO &&
           PbnsTlsTransportAllocationStats(transport, &failed_inner_stats) ==
               PBNS_OK &&
           failed_inner_stats.allocation_count == 2U &&
           failed_inner_stats.release_failures == 2U &&
           PbnsTlsTransportDestroy(transport) == PBNS_OK;
  transport = NULL;
  clear_failures();

  passed = passed && create_valid(&test_boot_services, &transport) &&
           allocation_balance(transport, 2U);
  fail_free_first_call = free_calls + 2U;
  fail_free_call_count = 2U;
  passed = passed && PbnsTlsTransportDestroy(transport) == PBNS_ERR_IO;
  PBNS_TLS_UEFI_ALLOCATION_STATS failed_context_stats = {0};
  passed = passed &&
           PbnsTlsTransportAllocationStats(transport, &failed_context_stats) ==
               PBNS_OK &&
           failed_context_stats.allocation_count == 1U &&
           failed_context_stats.release_failures == 1U &&
           PbnsTlsTransportDestroy(transport) == PBNS_ERR_IO &&
           PbnsTlsTransportAllocationStats(transport, &failed_context_stats) ==
               PBNS_OK &&
           failed_context_stats.allocation_count == 1U &&
           failed_context_stats.release_failures == 2U &&
           PbnsTlsTransportDestroy(transport) == PBNS_OK;
  transport = NULL;
  clear_failures();

  PBNS_TLS_UEFI_ALLOCATION_STATS runtime_stats = {0};
  pbns_view rejected_region = {(const uint8_t *)(UINTN)1U, 1U};
  passed = passed &&
           PbnsTlsTransportContextRegion(NULL, &rejected_region) ==
               EFI_INVALID_PARAMETER &&
           rejected_region.ptr == NULL && rejected_region.len == 0U &&
           PbnsTlsTransportContextRegion(NULL, NULL) == EFI_INVALID_PARAMETER;
  passed = passed && create_valid(&test_boot_services, &transport);
  pbns_view context_region = {0};
  passed = passed &&
           PbnsTlsTransportContextRegion(transport, NULL) ==
               EFI_INVALID_PARAMETER &&
           PbnsTlsTransportContextRegion(transport, &context_region) ==
               EFI_SUCCESS &&
           context_region.ptr == (const uint8_t *)transport &&
           context_region.len > 0U &&
           PbnsTlsTransportAsTransport(transport).ops != NULL &&
           PbnsTlsTransportAllocationStats(transport, &runtime_stats) == PBNS_OK;
  passed = passed && PbnsTlsTransportDestroy(transport) == PBNS_OK;
  transport = NULL;
  if (!passed) {
    Print(L"PBNS UEFI TLS LINK PROBE FAIL\r\n");
    return EFI_COMPROMISED_DATA;
  }
  Print(L"PBNS UEFI TLS POOL PEAK %Lu BYTES ALLOCATIONS %Lu PAGES 0\r\n",
        (UINT64)runtime_stats.peak_bytes,
        (UINT64)runtime_stats.peak_allocation_count);
  Print(L"PBNS UEFI TLS LINK PROBE PASS\r\n");
  return EFI_SUCCESS;
}
