#include <Uefi.h>

#include <CrtLibSupport.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PbnsIdentityLib.h>
#include <Library/PbnsUefiPlatformLib.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <mbedtls/ssl.h>

#include "PbnsTlsTransportContextRegionCore.h"
#include "PbnsTlsTransportLib.h"
#include "pbns/tls_handshake_observer.h"
#include "pbns/tls_policy.h"

#if MBEDTLS_SSL_IN_CONTENT_LEN > PBNS_TLS_UEFI_CONTENT_MAX
#error "PBNS TLS input content exceeds the UEFI adapter bound"
#endif

#if MBEDTLS_SSL_OUT_CONTENT_LEN > PBNS_TLS_UEFI_CONTENT_MAX
#error "PBNS TLS output content exceeds the UEFI adapter bound"
#endif

_Static_assert(PBNS_TLS_CERTIFICATE_DER_MAX <= 4096U,
               "The TLS certificate observer must remain bounded");
_Static_assert(PBNS_TLS_OBSERVER_ACCEPTED_CERTIFICATE_COUNT == 1U,
               "PBNS permits exactly one TLS leaf certificate");

typedef struct PBNS_TLS_UEFI_ALLOCATION {
  struct PBNS_TLS_UEFI_TRANSPORT *owner;
  size_t payload_size;
  size_t pool_size;
  struct PBNS_TLS_UEFI_ALLOCATION *pending_next;
} PBNS_TLS_UEFI_ALLOCATION;

struct PBNS_TLS_UEFI_TRANSPORT {
  EFI_BOOT_SERVICES *boot_services;
  PBNS_TPM_RANDOM_SOURCE tpm_random;
  pbns_tls_transport *inner;
  PBNS_TLS_UEFI_ALLOCATION_STATS allocation_stats;
  PBNS_TLS_UEFI_ALLOCATION *pending_allocations;
  bool have_tpm_random;
  bool inner_destroyed;
  bool destroying;
  bool operation_active;
};

/* O PBNS pré-arranque mantém uma sessão TLS; as chamadas públicas decorrem em
 * TPL_APPLICATION e o TPL protege cada transição do proprietário. */
static PBNS_TLS_UEFI_TRANSPORT *active_transport;
static EFI_BOOT_SERVICES *active_boot_services;
static bool transition_active;

static void wipe_bytes(void *bytes, size_t length) {
  volatile uint8_t *cursor = bytes;
  while (length > 0U) {
    *cursor++ = 0U;
    --length;
  }
}

static bool boot_services_valid(const EFI_BOOT_SERVICES *boot_services) {
  return boot_services != NULL && boot_services->AllocatePool != NULL &&
         boot_services->FreePool != NULL && boot_services->RaiseTPL != NULL &&
         boot_services->RestoreTPL != NULL;
}

static bool caller_at_application_tpl(EFI_BOOT_SERVICES *boot_services) {
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_HIGH_LEVEL);
  boot_services->RestoreTPL(old_tpl);
  return old_tpl == TPL_APPLICATION;
}

static pbns_status reserve_transition(EFI_BOOT_SERVICES *boot_services) {
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  const bool busy = active_transport != NULL || transition_active;
  if (!busy) {
    transition_active = true;
  }
  boot_services->RestoreTPL(old_tpl);
  return busy ? PBNS_ERR_BUSY : PBNS_OK;
}

static void release_transition(EFI_BOOT_SERVICES *boot_services) {
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  transition_active = false;
  boot_services->RestoreTPL(old_tpl);
}

static void publish_active(PBNS_TLS_UEFI_TRANSPORT *transport) {
  EFI_BOOT_SERVICES *const boot_services = transport->boot_services;
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  active_transport = transport;
  active_boot_services = boot_services;
  transition_active = false;
  boot_services->RestoreTPL(old_tpl);
}

static void clear_destroying(PBNS_TLS_UEFI_TRANSPORT *transport) {
  EFI_BOOT_SERVICES *const boot_services = transport->boot_services;
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  transport->destroying = false;
  boot_services->RestoreTPL(old_tpl);
}

static bool is_active(PBNS_TLS_UEFI_TRANSPORT *transport) {
  EFI_BOOT_SERVICES *const boot_services = active_boot_services;
  if (transport == NULL || !boot_services_valid(boot_services) ||
      !caller_at_application_tpl(boot_services)) {
    return false;
  }
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  const bool result = active_transport == transport && !transport->destroying;
  boot_services->RestoreTPL(old_tpl);
  return result;
}

static pbns_status begin_transport_operation(PBNS_TLS_UEFI_TRANSPORT *transport,
                                             pbns_transport *inner) {
  if (inner == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *inner = (pbns_transport){0};
  EFI_BOOT_SERVICES *const boot_services = active_boot_services;
  if (!boot_services_valid(boot_services) ||
      !caller_at_application_tpl(boot_services)) {
    return PBNS_ERR_STATE;
  }
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  pbns_status status = PBNS_ERR_STATE;
  if (active_transport == transport && !transport->destroying &&
      transport->inner != NULL) {
    if (transport->operation_active) {
      status = PBNS_ERR_BUSY;
    } else {
      transport->operation_active = true;
      *inner = pbns_tls_transport_as_transport(transport->inner);
      status = PBNS_OK;
    }
  }
  boot_services->RestoreTPL(old_tpl);
  return status;
}

static void end_transport_operation(PBNS_TLS_UEFI_TRANSPORT *transport) {
  EFI_BOOT_SERVICES *const boot_services = active_boot_services;
  if (!boot_services_valid(boot_services)) {
    return;
  }
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  if (active_transport == transport) {
    transport->operation_active = false;
  }
  boot_services->RestoreTPL(old_tpl);
}

static pbns_status uefi_transport_open(void *context) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  pbns_transport inner = {0};
  const pbns_status begin_status = begin_transport_operation(transport, &inner);
  if (begin_status != PBNS_OK) {
    return begin_status;
  }
  const pbns_status status = inner.ops->open(inner.context);
  end_transport_operation(transport);
  return status;
}

static pbns_status uefi_transport_close(void *context) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  pbns_transport inner = {0};
  const pbns_status begin_status = begin_transport_operation(transport, &inner);
  if (begin_status != PBNS_OK) {
    return begin_status;
  }
  const pbns_status status = inner.ops->close(inner.context);
  end_transport_operation(transport);
  return status;
}

static pbns_status uefi_transport_send(void *context, pbns_view bytes,
                                       uint32_t timeout_ms) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  pbns_transport inner = {0};
  const pbns_status begin_status = begin_transport_operation(transport, &inner);
  if (begin_status != PBNS_OK) {
    return begin_status;
  }
  const pbns_status status = inner.ops->send(inner.context, bytes, timeout_ms);
  end_transport_operation(transport);
  return status;
}

static pbns_status uefi_transport_receive(void *context, pbns_buffer buffer,
                                          uint32_t timeout_ms,
                                          size_t *received) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  pbns_transport inner = {0};
  const pbns_status begin_status = begin_transport_operation(transport, &inner);
  if (begin_status != PBNS_OK) {
    return begin_status;
  }
  const pbns_status status =
      inner.ops->receive(inner.context, buffer, timeout_ms, received);
  end_transport_operation(transport);
  return status;
}

static pbns_status uefi_transport_cancel(void *context,
                                         const pbns_request_id *request_id) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  pbns_transport inner = {0};
  const pbns_status begin_status = begin_transport_operation(transport, &inner);
  if (begin_status != PBNS_OK) {
    return begin_status;
  }
  const pbns_status status = inner.ops->cancel(inner.context, request_id);
  end_transport_operation(transport);
  return status;
}

static pbns_status uefi_transport_limits(void *context,
                                         pbns_frame_limits *limits) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  pbns_transport inner = {0};
  const pbns_status begin_status = begin_transport_operation(transport, &inner);
  if (begin_status != PBNS_OK) {
    return begin_status;
  }
  const pbns_status status = inner.ops->limits(inner.context, limits);
  end_transport_operation(transport);
  return status;
}

static const pbns_transport_ops uefi_transport_ops = {
    .open = uefi_transport_open,
    .close = uefi_transport_close,
    .send = uefi_transport_send,
    .receive = uefi_transport_receive,
    .cancel = uefi_transport_cancel,
    .limits = uefi_transport_limits,
};

static pbns_status random_fill(void *context, pbns_buffer output) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  if (transport == NULL || output.ptr == NULL || output.len != 0U ||
      output.cap == 0U) {
    return PBNS_ERR_ENTROPY;
  }
  /* A precedência EFI RNG e a única alternativa TPM ficam na política comum. */
  const PBNS_TPM_RANDOM_SOURCE *const fallback =
      transport->have_tpm_random ? &transport->tpm_random : NULL;
  return PbnsIdentityRandomFill(fallback, output) == PBNS_OK ? PBNS_OK
                                                             : PBNS_ERR_ENTROPY;
}

static pbns_status monotonic_ms(void *context, uint64_t *milliseconds) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  if (transport == NULL || milliseconds == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  /* O relógio CPU tem origem persistente; este adaptador nunca reinicia prazos.
   */
  return EFI_ERROR(PbnsUefiMonotonicMs(transport->boot_services, milliseconds))
             ? PBNS_ERR_IO
             : PBNS_OK;
}

static void *allocate_pool(void *context, size_t size) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  if (transport == NULL || !boot_services_valid(transport->boot_services) ||
      size == 0U || size > SIZE_MAX - sizeof(PBNS_TLS_UEFI_ALLOCATION)) {
    return NULL;
  }
  const size_t pool_size = sizeof(PBNS_TLS_UEFI_ALLOCATION) + size;
  if (transport->allocation_stats.allocation_count == 0U ||
      transport->allocation_stats.allocation_count - 1U >=
          PBNS_TLS_UEFI_PLATFORM_ALLOCATION_MAX ||
      pool_size > PBNS_TLS_UEFI_POOL_CAP ||
      transport->allocation_stats.current_bytes >
          PBNS_TLS_UEFI_POOL_CAP - pool_size ||
      pool_size > (size_t)MAX_UINTN) {
    return NULL;
  }
  VOID *pool = NULL;
  const EFI_STATUS status = transport->boot_services->AllocatePool(
      EfiBootServicesData, (UINTN)pool_size, &pool);
  if (EFI_ERROR(status) || pool == NULL) {
    return NULL;
  }
  PBNS_TLS_UEFI_ALLOCATION *const allocation = pool;
  *allocation = (PBNS_TLS_UEFI_ALLOCATION){
      .owner = transport,
      .payload_size = size,
      .pool_size = pool_size,
  };
  transport->allocation_stats.current_bytes += pool_size;
  ++transport->allocation_stats.allocation_count;
  if (transport->allocation_stats.current_bytes >
      transport->allocation_stats.peak_bytes) {
    transport->allocation_stats.peak_bytes =
        transport->allocation_stats.current_bytes;
  }
  if (transport->allocation_stats.allocation_count >
      transport->allocation_stats.peak_allocation_count) {
    transport->allocation_stats.peak_allocation_count =
        transport->allocation_stats.allocation_count;
  }
  return allocation + 1;
}

static void release_pool(void *context, void *payload, size_t size) {
  PBNS_TLS_UEFI_TRANSPORT *const transport = context;
  if (transport == NULL || payload == NULL ||
      !boot_services_valid(transport->boot_services)) {
    return;
  }
  PBNS_TLS_UEFI_ALLOCATION *const allocation =
      (PBNS_TLS_UEFI_ALLOCATION *)payload - 1;
  if (allocation->owner != transport || allocation->payload_size != size ||
      allocation->pool_size < sizeof(*allocation) ||
      allocation->pool_size > PBNS_TLS_UEFI_POOL_CAP ||
      allocation->pool_size - sizeof(*allocation) != size ||
      allocation->pool_size > transport->allocation_stats.current_bytes ||
      transport->allocation_stats.allocation_count == 0U) {
    return;
  }
  const size_t pool_size = allocation->pool_size;
  /* A limpeza antecede FreePool para não reter estado TLS em memória
   * reutilizada. */
  wipe_bytes(allocation, pool_size);
  const EFI_STATUS status = transport->boot_services->FreePool(allocation);
  if (EFI_ERROR(status)) {
    ++transport->allocation_stats.release_failures;
    /* Após falha sobrevivem apenas tamanho e ligação necessários ao retry. */
    allocation->pool_size = pool_size;
    allocation->pending_next = transport->pending_allocations;
    transport->pending_allocations = allocation;
    return;
  }
  transport->allocation_stats.current_bytes -= pool_size;
  --transport->allocation_stats.allocation_count;
}

static const pbns_tls_platform_ops platform_ops = {
    .random = random_fill,
    .monotonic_ms = monotonic_ms,
    .allocate = allocate_pool,
    .release = release_pool,
};

static bool lower_is_valid(pbns_transport lower) {
  return lower.ops != NULL && lower.ops->open != NULL &&
         lower.ops->close != NULL && lower.ops->send != NULL &&
         lower.ops->receive != NULL && lower.ops->cancel != NULL &&
         lower.ops->limits != NULL;
}

static pbns_status prevalidate_config(const pbns_tls_client_config *config) {
  if (config == NULL || config->handshake_timeout_ms == 0U) {
    return PBNS_ERR_ARGUMENT;
  }
  pbns_tls_certificate_policy policy = {0};
  const pbns_status status = pbns_tls_certificate_policy_init(
      &policy, config->expected_server_name, config->pinned_leaf_spki_sha256);
  pbns_tls_certificate_policy_wipe(&policy);
  return status;
}

static pbns_status
retry_pending_allocations(PBNS_TLS_UEFI_TRANSPORT *transport) {
  PBNS_TLS_UEFI_ALLOCATION **link = &transport->pending_allocations;
  bool failed = false;
  while (*link != NULL) {
    PBNS_TLS_UEFI_ALLOCATION *const allocation = *link;
    PBNS_TLS_UEFI_ALLOCATION *const next = allocation->pending_next;
    const size_t pool_size = allocation->pool_size;
    wipe_bytes(allocation, pool_size);
    const EFI_STATUS status = transport->boot_services->FreePool(allocation);
    if (EFI_ERROR(status)) {
      ++transport->allocation_stats.release_failures;
      allocation->pool_size = pool_size;
      allocation->pending_next = next;
      link = &allocation->pending_next;
      failed = true;
    } else {
      *link = next;
      transport->allocation_stats.current_bytes -= pool_size;
      --transport->allocation_stats.allocation_count;
    }
  }
  return failed ? PBNS_ERR_IO : PBNS_OK;
}

static void wipe_sensitive_context(PBNS_TLS_UEFI_TRANSPORT *transport) {
  wipe_bytes(&transport->tpm_random, sizeof(transport->tpm_random));
  transport->have_tpm_random = false;
  transport->inner = NULL;
}

static void prepare_context_free(PBNS_TLS_UEFI_TRANSPORT *transport) {
  EFI_BOOT_SERVICES *const boot_services = transport->boot_services;
  const PBNS_TLS_UEFI_ALLOCATION_STATS allocation_stats =
      transport->allocation_stats;
  const bool destroying = transport->destroying;
  /* Se FreePool falhar, só a posse não secreta abaixo pode sobreviver ao retry.
   */
  wipe_bytes(transport, sizeof(*transport));
  transport->boot_services = boot_services;
  transport->allocation_stats = allocation_stats;
  transport->inner_destroyed = true;
  transport->destroying = destroying;
}

pbns_status EFIAPI
PbnsTlsTransportCreate(EFI_BOOT_SERVICES *boot_services, pbns_transport lower,
                       const pbns_tls_client_config *config,
                       const PBNS_TPM_RANDOM_SOURCE *tpm_random,
                       PBNS_TLS_UEFI_TRANSPORT **result) {
  if (result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *result = NULL;
  if (!boot_services_valid(boot_services) || !lower_is_valid(lower)) {
    return PBNS_ERR_ARGUMENT;
  }
  if (!caller_at_application_tpl(boot_services)) {
    return PBNS_ERR_STATE;
  }
  const pbns_status config_status = prevalidate_config(config);
  if (config_status != PBNS_OK) {
    return config_status;
  }
  const pbns_status reservation = reserve_transition(boot_services);
  if (reservation != PBNS_OK) {
    return reservation;
  }
  if (sizeof(PBNS_TLS_UEFI_TRANSPORT) > PBNS_TLS_UEFI_POOL_CAP) {
    release_transition(boot_services);
    return PBNS_ERR_LIMIT;
  }
  VOID *pool = NULL;
  const EFI_STATUS allocation_status = boot_services->AllocatePool(
      EfiBootServicesData, sizeof(PBNS_TLS_UEFI_TRANSPORT), &pool);
  if (EFI_ERROR(allocation_status) || pool == NULL) {
    release_transition(boot_services);
    return PBNS_ERR_RESOURCE;
  }
  PBNS_TLS_UEFI_TRANSPORT *const transport = pool;
  SetMem(transport, sizeof(*transport), 0);
  transport->boot_services = boot_services;
  transport->allocation_stats = (PBNS_TLS_UEFI_ALLOCATION_STATS){
      .current_bytes = sizeof(*transport),
      .peak_bytes = sizeof(*transport),
      .allocation_count = 1U,
      .peak_allocation_count = 1U,
  };
  if (tpm_random != NULL && tpm_random->Fill != NULL) {
    transport->tpm_random = *tpm_random;
    transport->have_tpm_random = true;
  }
  pbns_tls_transport *inner = NULL;
  const pbns_status status = pbns_tls_transport_create(
      lower, config,
      (pbns_tls_platform){.ops = &platform_ops, .context = transport}, &inner);
  if (status != PBNS_OK) {
    wipe_sensitive_context(transport);
    transport->inner_destroyed = true;
    if (transport->pending_allocations != NULL) {
      publish_active(transport);
      *result = transport;
      return PBNS_ERR_IO;
    }
    prepare_context_free(transport);
    const EFI_STATUS free_status = boot_services->FreePool(transport);
    if (EFI_ERROR(free_status)) {
      ++transport->allocation_stats.release_failures;
      publish_active(transport);
      *result = transport;
      return PBNS_ERR_IO;
    }
    release_transition(boot_services);
    return status;
  }
  transport->inner = inner;
  publish_active(transport);
  *result = transport;
  return PBNS_OK;
}

pbns_transport EFIAPI
PbnsTlsTransportAsTransport(PBNS_TLS_UEFI_TRANSPORT *transport) {
  if (!is_active(transport) || transport->inner == NULL) {
    return (pbns_transport){0};
  }
  return (pbns_transport){.ops = &uefi_transport_ops, .context = transport};
}

EFI_STATUS EFIAPI PbnsTlsTransportContextRegion(
    PBNS_TLS_UEFI_TRANSPORT *Transport, pbns_view *Region) {
  if (Region == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Region = (pbns_view){0};
  const bool usable = is_active(Transport) && Transport->inner != NULL;
  const pbns_status status = pbns_tls_transport_context_region_core(
      Transport, sizeof(*Transport), usable, Region);
  switch (status) {
    case PBNS_OK:
      return EFI_SUCCESS;
    case PBNS_ERR_ARGUMENT:
      return EFI_INVALID_PARAMETER;
    case PBNS_ERR_STATE:
      return EFI_NOT_READY;
    default:
      return EFI_DEVICE_ERROR;
  }
}

pbns_status EFIAPI PbnsTlsTransportDestroy(PBNS_TLS_UEFI_TRANSPORT *transport) {
  if (transport == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  EFI_BOOT_SERVICES *const boot_services = active_boot_services;
  if (!boot_services_valid(boot_services) ||
      !caller_at_application_tpl(boot_services)) {
    return PBNS_ERR_STATE;
  }
  const EFI_TPL old_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  if (active_transport != transport || transport->destroying) {
    boot_services->RestoreTPL(old_tpl);
    return PBNS_ERR_STATE;
  }
  if (transport->operation_active) {
    boot_services->RestoreTPL(old_tpl);
    return PBNS_ERR_BUSY;
  }
  transport->destroying = true;
  boot_services->RestoreTPL(old_tpl);

  if (transport->pending_allocations != NULL &&
      retry_pending_allocations(transport) != PBNS_OK) {
    clear_destroying(transport);
    return PBNS_ERR_IO;
  }
  if (!transport->inner_destroyed) {
    const size_t failures_before = transport->allocation_stats.release_failures;
    pbns_tls_transport_destroy(transport->inner);
    transport->inner_destroyed = true;
    transport->inner = NULL;
    if (transport->pending_allocations != NULL ||
        transport->allocation_stats.release_failures != failures_before) {
      clear_destroying(transport);
      return PBNS_ERR_IO;
    }
  }
  const EFI_TPL final_tpl = boot_services->RaiseTPL(TPL_NOTIFY);
  prepare_context_free(transport);
  const EFI_STATUS free_status = boot_services->FreePool(transport);
  if (EFI_ERROR(free_status)) {
    ++transport->allocation_stats.release_failures;
    boot_services->RestoreTPL(final_tpl);
    clear_destroying(transport);
    return PBNS_ERR_IO;
  }
  active_transport = NULL;
  active_boot_services = NULL;
  boot_services->RestoreTPL(final_tpl);
  return PBNS_OK;
}

pbns_status EFIAPI
PbnsTlsTransportAllocationStats(PBNS_TLS_UEFI_TRANSPORT *transport,
                                PBNS_TLS_UEFI_ALLOCATION_STATS *result) {
  if (result == NULL) {
    return PBNS_ERR_ARGUMENT;
  }
  *result = (PBNS_TLS_UEFI_ALLOCATION_STATS){0};
  if (!is_active(transport)) {
    return PBNS_ERR_STATE;
  }
  *result = transport->allocation_stats;
  return PBNS_OK;
}
