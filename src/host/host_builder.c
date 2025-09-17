#include "libp2p/host_builder.h"
#include <stdlib.h>
#include <string.h>
#include "multiformats/multiaddr/multiaddr.h"

typedef struct list_node
{
    char *s;
    struct list_node *next;
} list_node_t;

struct libp2p_host_builder
{
    list_node_t *listen_addrs;
    list_node_t *transports;
    list_node_t *securities;
    list_node_t *muxers;
    int num_threads;
    int ms_timeout;
    int ms_enable_ls;
    int max_inbound_conns;
    int max_outbound_conns;
    int per_conn_max_inbound_streams;
    int per_conn_max_outbound_streams;
    int cm_low_water;
    int cm_high_water;
    int cm_grace_ms;
    uint32_t flags;
    int flags_set;
};

/* --- Validation helpers -------------------------------------------------- */
static int is_supported_transport(const char *name)
{
    if (!name)
        return 0;
    /* Currently only TCP transport is built-in */
    return strcmp(name, "tcp") == 0;
}

static int is_supported_security(const char *name)
{
    if (!name)
        return 0;
    /* Currently only Noise security is built-in */
    return strcmp(name, "noise") == 0;
}

static int is_supported_muxer(const char *name)
{
    if (!name)
        return 0;
    /* yamux and mplex supported */
    return (strcmp(name, "yamux") == 0) || (strcmp(name, "mplex") == 0);
}

static int validate_listen_addrs(const list_node_t *n)
{
    while (n)
    {
        if (!n->s || n->s[0] == '\0')
            return LIBP2P_ERR_UNSUPPORTED;
        int ma_err = 0;
        multiaddr_t *ma = multiaddr_new_from_str(n->s, &ma_err);
        if (!ma || ma_err != 0)
        {
            if (ma)
                multiaddr_free(ma);
            return LIBP2P_ERR_UNSUPPORTED;
        }
        multiaddr_free(ma);
        n = n->next;
    }
    return 0;
}

static int validate_named_list(const list_node_t *n, int (*is_supported)(const char *))
{
    while (n)
    {
        if (!n->s || n->s[0] == '\0')
            return LIBP2P_ERR_UNSUPPORTED;
        if (!is_supported(n->s))
            return LIBP2P_ERR_UNSUPPORTED;
        n = n->next;
    }
    return 0;
}

static void list_free(list_node_t *n)
{
    while (n)
    {
        list_node_t *nx = n->next;
        free(n->s);
        free(n);
        n = nx;
    }
}

static void free_owned_string_array(const char *const *arr, size_t len)
{
    if (!arr)
        return;
    for (size_t i = 0; i < len; i++)
        free((void *)arr[i]);
    free((void *)arr);
}

static int list_push(list_node_t **head, const char *s)
{
    if (!head || !s)
        return LIBP2P_ERR_NULL_PTR;
    list_node_t *n = (list_node_t *)calloc(1, sizeof(*n));
    if (!n)
        return LIBP2P_ERR_INTERNAL;
    n->s = strdup(s);
    if (!n->s)
    {
        free(n);
        return LIBP2P_ERR_INTERNAL;
    }
    n->next = *head;
    *head = n;
    return 0;
}

libp2p_host_builder_t *libp2p_host_builder_new(void)
{
    libp2p_host_builder_t *b = (libp2p_host_builder_t *)calloc(1, sizeof(*b));
    return b;
}

void libp2p_host_builder_free(libp2p_host_builder_t *b)
{
    if (!b)
        return;
    list_free(b->listen_addrs);
    list_free(b->transports);
    list_free(b->securities);
    list_free(b->muxers);
    free(b);
}

int libp2p_host_builder_listen_addr(libp2p_host_builder_t *b, const char *maddr)
{
    return b ? list_push(&b->listen_addrs, maddr) : LIBP2P_ERR_NULL_PTR;
}

int libp2p_host_builder_transport(libp2p_host_builder_t *b, const char *name) { return b ? list_push(&b->transports, name) : LIBP2P_ERR_NULL_PTR; }

int libp2p_host_builder_security(libp2p_host_builder_t *b, const char *name) { return b ? list_push(&b->securities, name) : LIBP2P_ERR_NULL_PTR; }

int libp2p_host_builder_muxer(libp2p_host_builder_t *b, const char *name) { return b ? list_push(&b->muxers, name) : LIBP2P_ERR_NULL_PTR; }

int libp2p_host_builder_threads(libp2p_host_builder_t *b, int num_threads)
{
    if (!b)
        return LIBP2P_ERR_NULL_PTR;
    b->num_threads = num_threads;
    return 0;
}

int libp2p_host_builder_multistream(libp2p_host_builder_t *b, int handshake_timeout_ms, bool enable_ls)
{
    if (!b)
        return LIBP2P_ERR_NULL_PTR;
    b->ms_timeout = handshake_timeout_ms;
    b->ms_enable_ls = enable_ls ? 1 : 0;
    return 0;
}

int libp2p_host_builder_flags(libp2p_host_builder_t *b, uint32_t flags)
{
    if (!b)
        return LIBP2P_ERR_NULL_PTR;
    b->flags = flags;
    b->flags_set = 1;
    return 0;
}

int libp2p_host_builder_max_conns(libp2p_host_builder_t *b, int inbound, int outbound)
{
    if (!b)
        return LIBP2P_ERR_NULL_PTR;
    b->max_inbound_conns = inbound;
    b->max_outbound_conns = outbound;
    return 0;
}

int libp2p_host_builder_per_conn_stream_caps(libp2p_host_builder_t *b, int inbound, int outbound)
{
    if (!b)
        return LIBP2P_ERR_NULL_PTR;
    b->per_conn_max_inbound_streams = inbound;
    b->per_conn_max_outbound_streams = outbound;
    return 0;
}

int libp2p_host_builder_conn_manager(libp2p_host_builder_t *b, int low_water, int high_water, int grace_ms)
{
    if (!b)
        return LIBP2P_ERR_NULL_PTR;
    b->cm_low_water = low_water;
    b->cm_high_water = high_water;
    b->cm_grace_ms = grace_ms;
    return 0;
}

static size_t list_count(const list_node_t *n)
{
    size_t c = 0;
    while (n)
    {
        c++;
        n = n->next;
    }
    return c;
}

static int list_to_array(const list_node_t *n, char ***out_arr, size_t *out_len)
{
    size_t c = list_count(n);
    if (out_len)
        *out_len = c;
    if (!out_arr)
        return 0;
    if (c == 0)
    {
        *out_arr = NULL;
        return 0;
    }
    char **arr = (char **)calloc(c, sizeof(*arr));
    if (!arr)
    {
        if (out_len)
            *out_len = 0;
        *out_arr = NULL;
        return LIBP2P_ERR_INTERNAL;
    }

    size_t i = 0;
    const list_node_t *it = n;
    while (it)
    {
        if (it->s)
        {
            arr[i] = strdup(it->s);
            if (!arr[i])
            {
                for (size_t j = 0; j < i; j++)
                    free(arr[j]);
                free(arr);
                if (out_len)
                    *out_len = 0;
                *out_arr = NULL;
                return LIBP2P_ERR_INTERNAL;
            }
        }
        else
        {
            arr[i] = NULL;
        }
        i++;
        it = it->next;
    }

    *out_arr = arr;
    return 0;
}

int libp2p_host_builder_build(const libp2p_host_builder_t *b, libp2p_host_t **out)
{
    if (!b || !out)
        return LIBP2P_ERR_NULL_PTR;
    /* Validate dynamic lists up-front for clearer errors */
    int vrc;
    vrc = validate_listen_addrs(b->listen_addrs);
    if (vrc != 0)
        return vrc;
    vrc = validate_named_list(b->transports, is_supported_transport);
    if (vrc != 0)
        return vrc;
    vrc = validate_named_list(b->securities, is_supported_security);
    if (vrc != 0)
        return vrc;
    vrc = validate_named_list(b->muxers, is_supported_muxer);
    if (vrc != 0)
        return vrc;
    libp2p_host_options_t o;
    libp2p_host_options_default(&o);
    if (b->num_threads > 0)
        o.num_runtime_threads = b->num_threads;
    if (b->ms_timeout > 0)
        o.multiselect_handshake_timeout_ms = b->ms_timeout;
    o.multiselect_enable_ls = b->ms_enable_ls ? true : false;
    /* Only override flags if the user explicitly set them via builder API.
     * This allows callers to pass 0 to disable defaults. */
    if (b->flags_set)
        o.flags = b->flags;

    /* limits & policies */
    if (b->max_inbound_conns > 0)
        o.max_inbound_conns = b->max_inbound_conns;
    if (b->max_outbound_conns > 0)
        o.max_outbound_conns = b->max_outbound_conns;
    if (b->per_conn_max_inbound_streams > 0)
        o.per_conn_max_inbound_streams = b->per_conn_max_inbound_streams;
    if (b->per_conn_max_outbound_streams > 0)
        o.per_conn_max_outbound_streams = b->per_conn_max_outbound_streams;

    int rc = list_to_array(b->listen_addrs, (char ***)&o.listen_addrs, &o.num_listen_addrs);
    if (rc != 0)
        goto cleanup_arrays;
    rc = list_to_array(b->securities, (char ***)&o.security_proposals, &o.num_security_proposals);
    if (rc != 0)
        goto cleanup_arrays;
    rc = list_to_array(b->muxers, (char ***)&o.muxer_proposals, &o.num_muxer_proposals);
    if (rc != 0)
        goto cleanup_arrays;
    rc = list_to_array(b->transports, (char ***)&o.transport_names, &o.num_transport_names);
    if (rc != 0)
        goto cleanup_arrays;

    libp2p_host_t *h = NULL;
    rc = libp2p_host_new(&o, &h);
    /* free temporary arrays after libp2p_host_new deep-copies them */
cleanup_arrays:
    free_owned_string_array(o.listen_addrs, o.num_listen_addrs);
    o.listen_addrs = NULL;
    o.num_listen_addrs = 0;
    free_owned_string_array(o.security_proposals, o.num_security_proposals);
    o.security_proposals = NULL;
    o.num_security_proposals = 0;
    free_owned_string_array(o.muxer_proposals, o.num_muxer_proposals);
    o.muxer_proposals = NULL;
    o.num_muxer_proposals = 0;
    free_owned_string_array(o.transport_names, o.num_transport_names);
    o.transport_names = NULL;
    o.num_transport_names = 0;
    if (rc != 0)
        return rc;

    /* Attach connection manager if configured */
    if (b->cm_low_water > 0 || b->cm_high_water > 0 || b->cm_grace_ms > 0)
    {
        libp2p_conn_mgr_t *cm = NULL;
        if (libp2p_conn_mgr_new(b->cm_low_water, b->cm_high_water, b->cm_grace_ms, &cm) == 0 && cm)
        {
            (void)libp2p_host_set_conn_manager(h, cm);
        }
    }

    *out = h;
    return 0;
}
