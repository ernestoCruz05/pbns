#ifndef PBNS_TEST_LWIP_ERR_H
#define PBNS_TEST_LWIP_ERR_H

#include <stdint.h>

typedef int8_t err_t;

enum {
  ERR_OK = 0,
  ERR_MEM = -1,
  ERR_RTE = -4,
  ERR_INPROGRESS = -5,
  ERR_ABRT = -13
};

#endif
