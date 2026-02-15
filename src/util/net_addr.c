#include "util/net_addr.h"

#include <string.h>

#ifdef _WIN32
#include <Ws2tcpip.h>
#else
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-include-next"
#endif
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#include <netinet/in.h>
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
#include <sys/socket.h>

extern int inet_pton(int af, const char *src, void *dst);
extern const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);
#endif

int libp2p_net_parse_ipv4(const char *text, uint8_t out[4])
{
	if ((text == NULL) || (out == NULL))
	{
		return -1;
	}
	return (inet_pton(AF_INET, text, out) == 1) ? 0 : -1;
}

int libp2p_net_parse_ipv6(const char *text, uint8_t out[16])
{
	if ((text == NULL) || (out == NULL))
	{
		return -1;
	}
	return (inet_pton(AF_INET6, text, out) == 1) ? 0 : -1;
}

int libp2p_net_ipv4_to_text(const uint8_t addr[4], char *out, size_t out_size)
{
	if ((addr == NULL) || (out == NULL) || (out_size == 0U))
	{
		return -1;
	}
	return (inet_ntop(AF_INET, addr, out, out_size) != NULL) ? 0 : -1;
}

int libp2p_net_ipv6_to_text(const uint8_t addr[16], char *out, size_t out_size)
{
	if ((addr == NULL) || (out == NULL) || (out_size == 0U))
	{
		return -1;
	}
	return (inet_ntop(AF_INET6, addr, out, out_size) != NULL) ? 0 : -1;
}
