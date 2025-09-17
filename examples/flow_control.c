#include "libp2p/flow_control.h"
#include <stdio.h>

int main(void)
{
    libp2p_flow_control_t *fc = libp2p_flow_control_new(10);
    if (!fc)
        return 1;
    printf("available=%zu\n", fc->available);
    libp2p_flow_control_consume(fc, 4);
    printf("after consume=4 available=%zu\n", fc->available);
    libp2p_flow_control_release(fc, 2);
    printf("after release=2 available=%zu\n", fc->available);
    libp2p_flow_control_free(fc);
    return 0;
}
