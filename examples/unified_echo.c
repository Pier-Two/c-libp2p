#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *listen = "/ip4/127.0.0.1/tcp/0";
    for (int i = 1; i + 1 < argc; i++)
    {
        if (strcmp(argv[i], "--listen") == 0)
        {
            listen = argv[i + 1];
            i++;
        }
    }

    libp2p_host_builder_t *b = libp2p_host_builder_new();
    if (!b)
    {
        fprintf(stderr, "failed to alloc host builder\n");
        return 1;
    }
    (void)libp2p_host_builder_listen_addr(b, listen);
    (void)libp2p_host_builder_transport(b, "tcp");
    (void)libp2p_host_builder_security(b, "noise");
    (void)libp2p_host_builder_muxer(b, "yamux");

    libp2p_host_t *h = NULL;
    if (libp2p_host_builder_build(b, &h) != 0 || !h)
    {
        fprintf(stderr, "failed to build host\n");
        libp2p_host_builder_free(b);
        return 1;
    }
    libp2p_host_builder_free(b);

    if (libp2p_host_start(h) != 0)
    {
        fprintf(stderr, "failed to start host\n");
        libp2p_host_free(h);
        return 1;
    }

    /* Minimal demo: start and immediately stop */
    if (libp2p_host_stop(h) != 0)
    {
        fprintf(stderr, "failed to stop host\n");
        libp2p_host_free(h);
        return 1;
    }
    libp2p_host_free(h);
    return 0;
}
