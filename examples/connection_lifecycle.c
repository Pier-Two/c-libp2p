#include "node/keep_alive.h"
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    libp2p_keep_alive_t *ka = libp2p_keep_alive_new(1);
    if (!ka)
        return 1;
    printf("expired=%d\n", libp2p_keep_alive_expired(ka));
    sleep(2);
    printf("expired after sleep=%d\n", libp2p_keep_alive_expired(ka));
    libp2p_keep_alive_free(ka);
    return 0;
}
