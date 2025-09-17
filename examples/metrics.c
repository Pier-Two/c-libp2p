#include "metrics/protocol_metrics.h"
#include <stdio.h>

int main(void)
{
    libp2p_protocol_metrics_t *m = libp2p_protocol_metrics_new();
    libp2p_protocol_metrics_add_sent(m, 10);
    libp2p_protocol_metrics_add_received(m, 5);
    printf("sent=%zu received=%zu\n", m->bytes_sent, m->bytes_received);
    libp2p_protocol_metrics_free(m);
    return 0;
}
