#include <stdlib.h>
#include <string.h>

#include "host_internal.h"
#include "libp2p/events.h"
#include "libp2p/identify.h"
#include "libp2p/lpmsg.h"
#include "libp2p/peerstore.h"
#include "libp2p/protocol.h"
#include "protocol/identify/protocol_identify.h"

struct libp2p_identify_service
{
    libp2p_host_t *host;
    libp2p_identify_opts_t opts;
};

typedef struct
{
    libp2p_stream_t *s;
    int rc;
} __id_open_cbctx_t;
static void __id_on_open_cb(libp2p_stream_t *s2, void *ud2, int err2)
{
    __id_open_cbctx_t *c2 = (__id_open_cbctx_t *)ud2;
    if (!c2)
        return;
    c2->s = s2;
    c2->rc = err2;
}

int libp2p_identify_new(libp2p_host_t *host, const libp2p_identify_opts_t *opts, libp2p_identify_service_t **out)
{
    if (!host || !out)
        return LIBP2P_ERR_NULL_PTR;
    libp2p_identify_service_t *svc = (libp2p_identify_service_t *)calloc(1, sizeof(*svc));
    if (!svc)
        return LIBP2P_ERR_INTERNAL;
    svc->host = host;
    if (opts && opts->struct_size == sizeof(*opts))
        svc->opts = *opts;
    else
        memset(&svc->opts, 0, sizeof(svc->opts));
    *out = svc;
    return 0;
}

void libp2p_identify_ctrl_free(libp2p_identify_service_t *id)
{
    if (!id)
        return;
    free(id);
}

/* Internal: read a single LP-framed Identify message from a stream and update peerstore. */
static int read_and_apply_identify(libp2p_identify_service_t *svc, libp2p_stream_t *s, const peer_id_t *peer)
{
    if (!svc || !svc->host || !s || !peer)
        return LIBP2P_ERR_NULL_PTR;
    uint8_t *buf = (uint8_t *)malloc(64 * 1024);
    if (!buf)
        return LIBP2P_ERR_INTERNAL;
    ssize_t n = libp2p_lp_recv(s, buf, 64 * 1024);
    if (n <= 0)
    {
        free(buf);
        return LIBP2P_ERR_INTERNAL;
    }

    libp2p_identify_t *id = NULL;
    int rc = libp2p_identify_message_decode(buf, (size_t)n, &id);
    free(buf);
    if (rc != 0 || !id)
        return LIBP2P_ERR_INTERNAL;

    if (svc->host->peerstore)
    {
        if (id->public_key && id->public_key_len)
            (void)libp2p_peerstore_set_public_key(svc->host->peerstore, peer, id->public_key, id->public_key_len);
        if (id->num_protocols && id->protocols)
        {
            if (libp2p_peerstore_set_protocols(svc->host->peerstore, peer, (const char *const *)id->protocols, id->num_protocols) == 0)
                libp2p__notify_peer_protocols_updated(svc->host, peer, (const char *const *)id->protocols, id->num_protocols);
        }
        /* listenAddrs are binary multiaddr bytes on the wire; parse accordingly */
        for (size_t i = 0; i < id->num_listen_addrs; i++)
        {
            const uint8_t *bytes = id->listen_addrs[i];
            size_t blen = id->listen_addrs_lens[i];
            if (!bytes || !blen)
                continue;
            int ma_err = 0;
            multiaddr_t *ma = multiaddr_new_from_bytes(bytes, blen, &ma_err);
            if (ma)
            {
                (void)libp2p_peerstore_add_addr(svc->host->peerstore, peer, ma, 10 * 60 * 1000);
                multiaddr_free(ma);
            }
        }
    }

    /* Emit observed address candidate if provided */
    if (id->observed_addr && id->observed_addr_len)
    {
        /* observedAddr is also binary multiaddr bytes; convert to string for event */
        int ma_err = 0;
        multiaddr_t *oma = multiaddr_new_from_bytes(id->observed_addr, id->observed_addr_len, &ma_err);
        if (oma)
        {
            int serr = 0;
            char *ostr = multiaddr_to_str(oma, &serr);
            if (ostr && serr == MULTIADDR_SUCCESS)
            {
                libp2p_event_t evt = {0};
                evt.kind = LIBP2P_EVT_NEW_EXTERNAL_ADDR_CANDIDATE;
                evt.u.new_external_addr_candidate.addr = ostr;
                libp2p_event_publish(svc->host, &evt);
                free(ostr);
            }
            multiaddr_free(oma);
        }
    }

    libp2p_identify_free(id);
    return 0;
}

int libp2p_identify_request(libp2p_identify_service_t *id, const peer_id_t *peer)
{
    if (!id || !id->host || !peer)
        return LIBP2P_ERR_NULL_PTR;
    /* Open a stream to the peer for /ipfs/id/1.0.0 using peerstore addrs. */
    libp2p_stream_t *s = NULL;
    int rc = 0;
    /* Fallback path: invoke open_stream again with a capturing callback to get the handle. */
    __id_open_cbctx_t c = (__id_open_cbctx_t){0};
    rc = libp2p_host_open_stream(id->host, peer, LIBP2P_IDENTIFY_PROTO_ID, __id_on_open_cb, &c);
    if (rc != 0 || c.rc != 0 || !c.s)
        return rc ? rc : (c.rc ? c.rc : LIBP2P_ERR_INTERNAL);

    s = c.s;
    int apply_rc = read_and_apply_identify(id, s, peer);
    libp2p_stream_close(s);
    return apply_rc;
}
