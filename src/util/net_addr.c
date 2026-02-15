#include "util/net_addr.h"

#include <limits.h>

#ifdef _WIN32
#include <Ws2tcpip.h>
#define LIBP2P_AF_INET AF_INET
#define LIBP2P_AF_INET6 AF_INET6
#else
#define LIBP2P_AF_INET 2
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define LIBP2P_AF_INET6 30
#else
#define LIBP2P_AF_INET6 10
#endif

extern int inet_pton(int af, const char *src, void *dst);
extern const char *inet_ntop(int af, const void *src, char *dst, unsigned int size);
#endif

int libp2p_net_parse_ipv4(const char *text, uint8_t out[4])
{
	if ((text == NULL) || (out == NULL))
	{
		return -1;
	}
	return (inet_pton(LIBP2P_AF_INET, text, out) == 1) ? 0 : -1;
}

int libp2p_net_parse_ipv6(const char *text, uint8_t out[16])
{
	if ((text == NULL) || (out == NULL))
	{
		return -1;
	}
	return (inet_pton(LIBP2P_AF_INET6, text, out) == 1) ? 0 : -1;
}

int libp2p_net_ipv4_to_text(const uint8_t addr[4], char *out, size_t out_size)
{
	if ((addr == NULL) || (out == NULL) || (out_size == 0U) || (out_size > (size_t)UINT_MAX))
	{
		return -1;
	}
	return (inet_ntop(LIBP2P_AF_INET, addr, out, (unsigned int)out_size) != NULL) ? 0 : -1;
}

int libp2p_net_ipv6_to_text(const uint8_t addr[16], char *out, size_t out_size)
{
	if ((addr == NULL) || (out == NULL) || (out_size == 0U) || (out_size > (size_t)UINT_MAX))
	{
		return -1;
	}
	return (inet_ntop(LIBP2P_AF_INET6, addr, out, (unsigned int)out_size) != NULL) ? 0 : -1;
}
