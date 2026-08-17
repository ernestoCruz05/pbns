#ifndef PBNS_TLS_TRANSPORT_LIB_H
#define PBNS_TLS_TRANSPORT_LIB_H

#include <Uefi.h>

#include <stddef.h>

#include <Library/PbnsIdentityLib.h>

#include "pbns/status.h"
#include "pbns/tls_transport.h"
#include "pbns/transport.h"

#define PBNS_TLS_UEFI_POOL_CAP 65536U
#define PBNS_TLS_UEFI_CONTENT_MAX 16384U
#define PBNS_TLS_UEFI_PLATFORM_ALLOCATION_MAX 1U

/* Todas as operações, incluindo o transporte devolvido, exigem
 * TPL_APPLICATION e admitem apenas um proprietário activo. Se Create devolver
 * erro com *result não nulo, o chamador conserva a posse e repete Destroy até
 * obter PBNS_OK. PBNS_OK de Destroy termina a vida do objecto: o chamador põe
 * imediatamente o handle a NULL e não chama depois qualquer accessor. */
typedef struct PBNS_TLS_UEFI_TRANSPORT PBNS_TLS_UEFI_TRANSPORT;

typedef struct {
  size_t current_bytes;
  size_t peak_bytes;
  size_t allocation_count;
  size_t peak_allocation_count;
  size_t release_failures;
} PBNS_TLS_UEFI_ALLOCATION_STATS;

pbns_status EFIAPI PbnsTlsTransportCreate(
    EFI_BOOT_SERVICES *boot_services, pbns_transport lower,
    const pbns_tls_client_config *config,
    const PBNS_TPM_RANDOM_SOURCE *tpm_random, PBNS_TLS_UEFI_TRANSPORT **result);
pbns_transport EFIAPI
PbnsTlsTransportAsTransport(PBNS_TLS_UEFI_TRANSPORT *transport);
EFI_STATUS EFIAPI PbnsTlsTransportContextRegion(
    PBNS_TLS_UEFI_TRANSPORT *Transport, pbns_view *Region);
pbns_status EFIAPI PbnsTlsTransportDestroy(PBNS_TLS_UEFI_TRANSPORT *transport);
pbns_status EFIAPI PbnsTlsTransportAllocationStats(
    PBNS_TLS_UEFI_TRANSPORT *transport, PBNS_TLS_UEFI_ALLOCATION_STATS *result);

#endif
