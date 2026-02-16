#include "gossipsub_internal.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

peer_id_t *gossipsub_peer_clone(const peer_id_t *src)
{
	peer_id_t *dup = NULL;
	if (!src)
		return NULL;
	if (peer_id_clone(src, &dup) != PEER_ID_OK)
		return NULL;
	return dup;
}

void gossipsub_peer_free(peer_id_t *pid)
{
	if (!pid)
		return;
	peer_id_free(pid);
}

int gossipsub_peer_equals(const peer_id_t *a, const peer_id_t *b)
{
	if (!a || !b)
		return 0;
	return peer_id_equal(a, b) == 1;
}

uint64_t gossipsub_now_ms(void)
{
#ifdef _WIN32
	return GetTickCount64();
#else
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
#endif
}

uint64_t gossipsub_random_u64(void)
{
	static atomic_uint_fast64_t state = 0;
	uint64_t current = atomic_load_explicit(&state, memory_order_relaxed);
	if (current == 0)
	{
		uint64_t seed = gossipsub_now_ms();
		if (seed == 0)
			seed = 88172645463393265ULL;
		current = seed ^ 0x9E3779B97F4A7C15ULL;
	}
	uint64_t next = current * 6364136223846793005ULL + 1ULL;
	atomic_store_explicit(&state, next, memory_order_relaxed);
	return next;
}
