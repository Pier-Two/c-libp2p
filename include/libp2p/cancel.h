#ifndef LIBP2P_CANCEL_H
#define LIBP2P_CANCEL_H

#include <stdatomic.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_cancel_token
{
    _Atomic int canceled;
} libp2p_cancel_token_t;

static inline libp2p_cancel_token_t *libp2p_cancel_token_new(void)
{
    libp2p_cancel_token_t *t = (libp2p_cancel_token_t *)malloc(sizeof(*t));
    if (!t)
        return NULL;
    atomic_store(&t->canceled, 0);
    return t;
}

static inline void libp2p_cancel_token_cancel(libp2p_cancel_token_t *t)
{
    if (t)
        atomic_store(&t->canceled, 1);
}

static inline void libp2p_cancel_token_free(libp2p_cancel_token_t *t)
{
    if (t)
        free(t);
}

static inline int libp2p_cancel_token_is_canceled(const libp2p_cancel_token_t *t)
{
    return t ? atomic_load(&((libp2p_cancel_token_t *)t)->canceled) != 0 : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_CANCEL_H */
