#include "util/memory.h"

#include <stdlib.h>

void *libp2p_memory_alloc(size_t size)
{
	return malloc(size);
}

void *libp2p_memory_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

void libp2p_memory_free(void *ptr)
{
	free(ptr);
}
