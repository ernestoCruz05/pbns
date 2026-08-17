#ifndef PBNS_MEMORY_COMPAT_H
#define PBNS_MEMORY_COMPAT_H

#include <Library/BaseMemoryLib.h>

/* O CopyMem da BaseMemoryLib preserva a sobreposição nos fontes importados. */
#define memmove CopyMem

#endif
