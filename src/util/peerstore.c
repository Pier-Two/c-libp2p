#include "libp2p/debug_trace.h"
#include "libp2p/peerstore.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct addr_node
{
    multiaddr_t *addr;
    int ttl_ms; /* advisory */
    struct addr_node *next;
} addr_node_t;

typedef struct peer_entry
{
    peer_id_t pid; /* owned copy */
    addr_node_t *addrs;
    uint8_t *pubkey_pb;
    size_t pubkey_pb_len;
    char **protocols;
    size_t n_protocols;
    struct peer_entry *next;
} peer_entry_t;

struct libp2p_peerstore
{
    pthread_mutex_t mtx;
    peer_entry_t *head;
};

static int peer_id_clone(const peer_id_t *in, peer_id_t *out)
{
    if (!in || !out || !in->bytes || in->size == 0)
        return -1;
    out->bytes = (uint8_t *)malloc(in->size);
    if (!out->bytes)
        return -1;
    memcpy(out->bytes, in->bytes, in->size);
    out->size = in->size;
    return 0;
}

libp2p_peerstore_t *libp2p_peerstore_new(void)
{
    libp2p_peerstore_t *ps = (libp2p_peerstore_t *)calloc(1, sizeof(*ps));
    if (!ps)
        return NULL;
    if (pthread_mutex_init(&ps->mtx, NULL) != 0)
    {
        free(ps);
        return NULL;
    }
    return ps;
}

void libp2p_peerstore_free(libp2p_peerstore_t *ps)
{
    if (!ps)
        return;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = ps->head;
    while (e)
    {
        peer_entry_t *next = e->next;
        if (e->pid.bytes)
            free(e->pid.bytes);
        if (e->pubkey_pb)
            free(e->pubkey_pb);
        if (e->protocols)
        {
            for (size_t i = 0; i < e->n_protocols; i++)
                free(e->protocols[i]);
            free(e->protocols);
        }
        addr_node_t *an = e->addrs;
        while (an)
        {
            addr_node_t *nx = an->next;
            multiaddr_free(an->addr);
            free(an);
            an = nx;
        }
        free(e);
        e = next;
    }
    pthread_mutex_unlock(&ps->mtx);
    pthread_mutex_destroy(&ps->mtx);
    free(ps);
}

static peer_entry_t *find_entry_unlocked(libp2p_peerstore_t *ps, const peer_id_t *peer)
{
    for (peer_entry_t *e = ps->head; e; e = e->next)
    {
        if (peer_id_equals(&e->pid, peer) == 1)
            return e;
    }
    return NULL;
}

int libp2p_peerstore_add_addr(libp2p_peerstore_t *ps, const peer_id_t *peer, const multiaddr_t *addr, int ttl_ms)
{
    if (!ps || !peer || !addr)
        return -1;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = find_entry_unlocked(ps, peer);
    if (!e)
    {
        e = (peer_entry_t *)calloc(1, sizeof(*e));
        if (!e)
        {
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        if (peer_id_clone(peer, &e->pid) != 0)
        {
            free(e);
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        e->next = ps->head;
        ps->head = e;
    }
    /* Deduplicate by string form to avoid storing identical addresses repeatedly. */
    int s_err_new = 0;
    char *new_s = multiaddr_to_str(addr, &s_err_new);
    if (s_err_new != MULTIADDR_SUCCESS)
        new_s = NULL; /* fall back to best-effort without string compare */
    if (new_s)
    {
        for (addr_node_t *it = e->addrs; it; it = it->next)
        {
            int s_err_old = 0;
            char *old_s = multiaddr_to_str(it->addr, &s_err_old);
            int same = (s_err_old == MULTIADDR_SUCCESS && old_s && strcmp(old_s, new_s) == 0);
            if (old_s)
                free(old_s);
            if (same)
            {
                /* Refresh TTL and exit: already present. */
                it->ttl_ms = ttl_ms;
                free(new_s);
                pthread_mutex_unlock(&ps->mtx);
                return 0;
            }
        }
    }

    int err = 0;
    multiaddr_t *copy = multiaddr_copy(addr, &err);
    if (!copy)
    {
        if (new_s)
            free(new_s);
        pthread_mutex_unlock(&ps->mtx);
        return -1;
    }
    addr_node_t *an = (addr_node_t *)calloc(1, sizeof(*an));
    if (!an)
    {
        multiaddr_free(copy);
        if (new_s)
            free(new_s);
        pthread_mutex_unlock(&ps->mtx);
        return -1;
    }
    an->addr = copy;
    an->ttl_ms = ttl_ms;
    an->next = e->addrs;
    e->addrs = an;
    if (new_s)
        free(new_s);
    pthread_mutex_unlock(&ps->mtx);
    return 0;
}

int libp2p_peerstore_get_addrs(const libp2p_peerstore_t *ps_const, const peer_id_t *peer, const multiaddr_t ***out_addrs, size_t *out_len)
{
    if (!ps_const || !peer || !out_addrs || !out_len)
        return -1;
    libp2p_peerstore_t *ps = (libp2p_peerstore_t *)ps_const;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = find_entry_unlocked(ps, peer);
    if (!e)
    {
        pthread_mutex_unlock(&ps->mtx);
        *out_addrs = NULL;
        *out_len = 0;
        return 0;
    }
    size_t count = 0;
    for (addr_node_t *an = e->addrs; an; an = an->next)
        count++;
    const multiaddr_t **arr = count ? (const multiaddr_t **)calloc(count, sizeof(*arr)) : NULL;
    if (count && !arr)
    {
        pthread_mutex_unlock(&ps->mtx);
        return -1;
    }
    size_t i = 0;
    int err = 0;
    for (addr_node_t *an = e->addrs; an; an = an->next)
    {
        arr[i++] = multiaddr_copy(an->addr, &err);
        if (err != MULTIADDR_SUCCESS)
        {
            /* rollback partially allocated */
            for (size_t j = 0; j < i; j++)
                multiaddr_free((multiaddr_t *)arr[j]);
            free((void *)arr);
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
    }
    pthread_mutex_unlock(&ps->mtx);
    *out_addrs = arr;
    *out_len = count;
    return 0;
}

void libp2p_peerstore_free_addrs(const multiaddr_t **addrs, size_t len)
{
    if (!addrs)
        return;
    for (size_t i = 0; i < len; i++)
        multiaddr_free((multiaddr_t *)addrs[i]);
    free((void *)addrs);
}

int libp2p_peerstore_set_public_key(libp2p_peerstore_t *ps, const peer_id_t *peer, const uint8_t *pubkey_pb, size_t pubkey_pb_len)
{
    if (!ps || !peer || !pubkey_pb || pubkey_pb_len == 0)
        return -1;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = find_entry_unlocked(ps, peer);
    if (!e)
    {
        e = (peer_entry_t *)calloc(1, sizeof(*e));
        if (!e)
        {
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        if (peer_id_clone(peer, &e->pid) != 0)
        {
            free(e);
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        e->next = ps->head;
        ps->head = e;
    }
    uint8_t *copy = (uint8_t *)malloc(pubkey_pb_len);
    if (!copy)
    {
        pthread_mutex_unlock(&ps->mtx);
        return -1;
    }
    memcpy(copy, pubkey_pb, pubkey_pb_len);
    if (e->pubkey_pb)
        free(e->pubkey_pb);
    e->pubkey_pb = copy;
    e->pubkey_pb_len = pubkey_pb_len;
    pthread_mutex_unlock(&ps->mtx);
    return 0;
}

int libp2p_peerstore_get_public_key(const libp2p_peerstore_t *ps_const, const peer_id_t *peer, uint8_t **out_pb, size_t *out_len)
{
    if (!ps_const || !peer || !out_pb || !out_len)
        return -1;
    libp2p_peerstore_t *ps = (libp2p_peerstore_t *)ps_const;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = find_entry_unlocked(ps, peer);
    if (!e || !e->pubkey_pb || e->pubkey_pb_len == 0)
    {
        pthread_mutex_unlock(&ps->mtx);
        *out_pb = NULL;
        *out_len = 0;
        return 0;
    }
    uint8_t *copy = (uint8_t *)malloc(e->pubkey_pb_len);
    if (!copy)
    {
        pthread_mutex_unlock(&ps->mtx);
        return -1;
    }
    memcpy(copy, e->pubkey_pb, e->pubkey_pb_len);
    size_t len = e->pubkey_pb_len;
    pthread_mutex_unlock(&ps->mtx);
    *out_pb = copy;
    *out_len = len;
    return 0;
}

int libp2p_peerstore_set_protocols(libp2p_peerstore_t *ps, const peer_id_t *peer, const char *const *protocols, size_t n_protocols)
{
    if (!ps || !peer)
        return -1;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = find_entry_unlocked(ps, peer);
    if (!e)
    {
        e = (peer_entry_t *)calloc(1, sizeof(*e));
        if (!e)
        {
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        if (peer_id_clone(peer, &e->pid) != 0)
        {
            free(e);
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        e->next = ps->head;
        ps->head = e;
    }
    /* Replace list */
    if (e->protocols)
    {
        for (size_t i = 0; i < e->n_protocols; i++)
            free(e->protocols[i]);
        free(e->protocols);
        e->protocols = NULL;
        e->n_protocols = 0;
    }
    if (protocols && n_protocols > 0)
    {
        char **tmp = (char **)calloc(n_protocols, sizeof(char *));
        if (!tmp)
        {
            pthread_mutex_unlock(&ps->mtx);
            return -1;
        }
        size_t cnt = 0;
        for (size_t i = 0; i < n_protocols; i++)
        {
            const char *p = protocols[i];
            if (!p)
                continue;
            int dup = 0;
            for (size_t j = 0; j < cnt; j++)
            {
                if (tmp[j] && strcmp(tmp[j], p) == 0)
                {
                    dup = 1;
                    break;
                }
            }
            if (dup)
                continue;
            tmp[cnt] = strdup(p);
            if (!tmp[cnt])
            {
                for (size_t k = 0; k < cnt; k++)
                    free(tmp[k]);
                free(tmp);
                pthread_mutex_unlock(&ps->mtx);
                return -1;
            }
            cnt++;
        }
        e->protocols = tmp;
        e->n_protocols = cnt;
    }
    size_t out_count = e->n_protocols;
    pthread_mutex_unlock(&ps->mtx);
    char pid_buf[128];
    if (peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
        snprintf(pid_buf, sizeof(pid_buf), "<unknown>");
    LIBP2P_TRACE("idpush", "peerstore set protocols peer=%s count=%zu", pid_buf, out_count);
    return 0;
}

int libp2p_peerstore_get_protocols(const libp2p_peerstore_t *ps_const, const peer_id_t *peer, const char ***out_protocols, size_t *out_len)
{
    if (!ps_const || !peer || !out_protocols || !out_len)
        return -1;
    libp2p_peerstore_t *ps = (libp2p_peerstore_t *)ps_const;
    pthread_mutex_lock(&ps->mtx);
    peer_entry_t *e = find_entry_unlocked(ps, peer);
    if (!e || e->n_protocols == 0)
    {
        pthread_mutex_unlock(&ps->mtx);
        *out_protocols = NULL;
        *out_len = 0;
        char pid_buf[128];
        if (peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
            snprintf(pid_buf, sizeof(pid_buf), "<unknown>");
        LIBP2P_TRACE("idpush", "peerstore get protocols miss peer=%s", pid_buf);
        return 0;
    }
    const char **arr = (const char **)calloc(e->n_protocols, sizeof(*arr));
    if (!arr)
    {
        pthread_mutex_unlock(&ps->mtx);
        return -1;
    }
    for (size_t i = 0; i < e->n_protocols; i++)
        arr[i] = e->protocols[i] ? strdup(e->protocols[i]) : NULL;
    size_t result_count = e->n_protocols;
    pthread_mutex_unlock(&ps->mtx);
    *out_protocols = arr;
    *out_len = result_count;
    char pid_buf[128];
    if (peer_id_to_string(peer, PEER_ID_FMT_BASE58_LEGACY, pid_buf, sizeof(pid_buf)) < 0)
        snprintf(pid_buf, sizeof(pid_buf), "<unknown>");
    LIBP2P_TRACE("idpush", "peerstore get protocols peer=%s count=%zu", pid_buf, result_count);
    return 0;
}

void libp2p_peerstore_free_protocols(const char **protocols, size_t len)
{
    if (!protocols)
        return;
    for (size_t i = 0; i < len; i++)
        free((void *)protocols[i]);
    free((void *)protocols);
}
