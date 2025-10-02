#include "libp2p/transport.h"
#include "protocol/tcp/protocol_tcp.h"
#include "protocol/quic/protocol_quic.h"

int libp2p_transport_tcp(libp2p_transport_t **out)
{
    if (!out)
        return -1;
    libp2p_tcp_config_t cfg = libp2p_tcp_config_default();
    /* Teardown: wait briefly for accept/poll loop to observe closure to
     * reduce flakiness during shutdown while keeping tests fast. */
    cfg.close_timeout_ms = 500; /* 0.5s */
    cfg.accept_poll_ms = 100;
    *out = libp2p_tcp_transport_new(&cfg);
    return *out ? 0 : -1;
}

int libp2p_transport_quic(libp2p_transport_t **out)
{
    if (!out)
        return -1;
    libp2p_quic_config_t cfg = libp2p_quic_config_default();
    *out = libp2p_quic_transport_new(&cfg);
    return *out ? 0 : -1;
}
