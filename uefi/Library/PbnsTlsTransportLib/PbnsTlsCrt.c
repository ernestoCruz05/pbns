#include <Uefi.h>

#include <CrtLibSupport.h>
#include <Library/BaseLib.h>

#include <stdint.h>

#include <mbedtls/platform_time.h>

int strcmp(const char *left, const char *right) {
  const INTN result = AsciiStrCmp(left, right);
  if (result < 0) {
    return -1;
  }
  return result > 0 ? 1 : 0;
}

char *strchr(const char *string, int value) {
  const uint8_t target = (uint8_t)value;
  const char *cursor = string;
  for (;;) {
    if ((uint8_t)*cursor == target) {
      return (char *)(uintptr_t)(const void *)cursor;
    }
    if (*cursor == '\0') {
      return NULL;
    }
    ++cursor;
  }
}

time_t time(time_t *timer) {
  /* Antes do tempo autenticado, zero força a validação PBNS das flags
   * temporais sem confiar no RTC. */
  if (timer != NULL) {
    *timer = (time_t)0;
  }
  return (time_t)0;
}

mbedtls_ms_time_t mbedtls_ms_time(void) {
  /* A retoma TLS está desactivada; o prazo PBNS usa a callback monotónica. */
  return (mbedtls_ms_time_t)0;
}
