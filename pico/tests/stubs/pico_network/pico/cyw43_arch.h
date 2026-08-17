#ifndef PBNS_TEST_PICO_CYW43_ARCH_H
#define PBNS_TEST_PICO_CYW43_ARCH_H

#include <stdint.h>

#define CYW43_AUTH_WPA2_AES_PSK UINT32_C(0x00400004)
#define CYW43_NONE_PM UINT32_C(0)
#define CYW43_ITF_STA 0
#define CYW43_LINK_DOWN 0
#define CYW43_LINK_JOIN 1
#define CYW43_LINK_NOIP 2
#define CYW43_LINK_UP 3
#define CYW43_LINK_FAIL (-1)
#define CYW43_LINK_NONET (-2)
#define CYW43_LINK_BADAUTH (-3)

struct cyw43_t {
  uint32_t marker;
};

extern struct cyw43_t cyw43_state;

void cyw43_arch_lwip_begin(void);
void cyw43_arch_lwip_end(void);
int cyw43_arch_wifi_connect_async(const char *ssid, const char *psk,
                                  uint32_t authentication);
int cyw43_tcpip_link_status(struct cyw43_t *state, int interface_index);
int cyw43_wifi_leave(struct cyw43_t *state, int interface_index);
int cyw43_wifi_pm(struct cyw43_t *state, uint32_t power_management);
int cyw43_arch_init(void);
void cyw43_arch_enable_sta_mode(void);
void cyw43_arch_deinit(void);

#endif
