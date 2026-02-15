#ifndef LIBP2P_NET_ADDR_H
#define LIBP2P_NET_ADDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int libp2p_net_parse_ipv4(const char *text, uint8_t out[4]);
int libp2p_net_parse_ipv6(const char *text, uint8_t out[16]);
int libp2p_net_ipv4_to_text(const uint8_t addr[4], char *out, size_t out_size);
int libp2p_net_ipv6_to_text(const uint8_t addr[16], char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_NET_ADDR_H */
