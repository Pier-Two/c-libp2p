#include "libp2p/security.h"

int libp2p_security_noise(libp2p_security_t **out)
{
    if (!out)
        return -1;
    libp2p_noise_config_t cfg = libp2p_noise_config_default();
    *out = libp2p_noise_security_new(&cfg);
    return *out ? 0 : -1;
}

int libp2p_security_tls(libp2p_security_t **out)
{
    (void)out;
    /* TLS not available in this build; explicitly return error. */
    return -1;
}
