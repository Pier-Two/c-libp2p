#ifndef LIBP2P_MEMORY_H
#define LIBP2P_MEMORY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void *libp2p_memory_alloc(size_t size);
void *libp2p_memory_realloc(void *ptr, size_t size);
void libp2p_memory_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MEMORY_H */
