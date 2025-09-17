#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "proto_select_internal.h"

typedef struct candidate_item
{
    const char *id;
    int has_version;
    version_triplet_t v;
} candidate_item_t;

static int cmp_candidates_desc(const void *a, const void *b)
{
    const candidate_item_t *ca = (const candidate_item_t *)a;
    const candidate_item_t *cb = (const candidate_item_t *)b;
    if (ca->has_version && cb->has_version)
    {
        if (ca->v.major != cb->v.major)
            return cb->v.major - ca->v.major;
        if (ca->v.minor != cb->v.minor)
            return cb->v.minor - ca->v.minor;
        if (ca->v.patch != cb->v.patch)
            return cb->v.patch - ca->v.patch;
        return 0;
    }
    if (ca->has_version && !cb->has_version)
        return -1;
    if (!ca->has_version && cb->has_version)
        return 1;
    return strcmp(cb->id, ca->id);
}

static int parse_uint_strict(const char *s, size_t len, int *out)
{
    if (!s || !out || len == 0)
        return LIBP2P_ERR_INTERNAL;
    long acc = 0;
    for (size_t i = 0; i < len; i++)
    {
        unsigned char ch = (unsigned char)s[i];
        if (!isdigit(ch))
            return LIBP2P_ERR_INTERNAL;
        int digit = ch - '0';
        if (acc > (LONG_MAX - digit) / 10)
            return LIBP2P_ERR_INTERNAL; /* overflow */
        acc = acc * 10 + digit;
        if (acc > INT_MAX)
            return LIBP2P_ERR_INTERNAL; /* overflow for int */
    }
    *out = (int)acc;
    return 0;
}

static int parse_version_triplet_span(const char *s, size_t len, version_triplet_t *out)
{
    if (!s || !out)
        return LIBP2P_ERR_NULL_PTR;
    if (len == 0)
        return LIBP2P_ERR_INTERNAL;
    /* Expect: MAJOR[.MINOR[.PATCH]] with digits only */
    size_t pos = 0;
    int parts[3] = {0, 0, 0};
    int nparts = 0;
    while (pos < len && nparts < 3)
    {
        /* read number */
        size_t start = pos;
        while (pos < len && isdigit((unsigned char)s[pos]))
            pos++;
        if (pos == start)
            return LIBP2P_ERR_INTERNAL; /* no digits */
        if (parse_uint_strict(s + start, pos - start, &parts[nparts]) != 0)
            return LIBP2P_ERR_INTERNAL;
        nparts++;
        if (pos == len)
            break;
        if (s[pos] != '.')
            return LIBP2P_ERR_INTERNAL; /* invalid separator */
        pos++; /* skip '.' */
        if (pos == len)
        {
            /* trailing '.' not allowed */
            return LIBP2P_ERR_INTERNAL;
        }
    }
    if (pos != len)
        return LIBP2P_ERR_INTERNAL; /* trailing garbage or too many parts */
    if (nparts == 0)
        return LIBP2P_ERR_INTERNAL;
    out->major = parts[0];
    out->minor = (nparts > 1) ? parts[1] : 0;
    out->patch = (nparts > 2) ? parts[2] : 0;
    return 0;
}

int parse_version_triplet(const char *s, version_triplet_t *out)
{
    if (!s || !out)
        return LIBP2P_ERR_NULL_PTR;
    size_t len = strlen(s);
    return parse_version_triplet_span(s, len, out);
}

int extract_version_from_id(const char *protocol_id, const char *base_path, version_triplet_t *out)
{
    if (!protocol_id || !out)
        return LIBP2P_ERR_NULL_PTR;
    const char *start = NULL;
    if (base_path)
    {
        size_t blen = strlen(base_path);
        if (strncmp(protocol_id, base_path, blen) != 0)
            return LIBP2P_ERR_INTERNAL; /* base_path not matched; out of scope */
        start = protocol_id + blen;
    }
    else
    {
        const char *slash = strrchr(protocol_id, '/');
        start = slash ? slash + 1 : protocol_id;
    }
    return parse_version_triplet(start, out);
}

static int version_ge(const version_triplet_t *a, const version_triplet_t *b)
{
    if (a->major != b->major)
        return a->major > b->major;
    if (a->minor != b->minor)
        return a->minor >= b->minor ? (a->minor > b->minor) : 0;
    return a->patch >= b->patch;
}

static int version_lt(const version_triplet_t *a, const version_triplet_t *b)
{
    if (a->major != b->major)
        return a->major < b->major;
    if (a->minor != b->minor)
        return a->minor < b->minor;
    return a->patch < b->patch;
}

static const char *skip_ws(const char *p)
{
    while (p && *p && isspace((unsigned char)*p))
        p++;
    return p;
}

static const char *rskip_ws(const char *start, const char *end)
{
    /* move end left while space, end is exclusive */
    while (end > start && isspace((unsigned char)end[-1]))
        end--;
    return end;
}

int parse_semver_range(const char *pattern, semver_range_t *out)
{
    if (!pattern || !out)
        return LIBP2P_ERR_NULL_PTR;
    memset(out, 0, sizeof(*out));

    const char *p = skip_ws(pattern);
    size_t plen = strlen(p);
    const char *endp = p + plen;

    if (*p == '^')
    {
        p = skip_ws(p + 1);
        const char *vend = rskip_ws(p, endp);
        version_triplet_t v = (version_triplet_t){0};
        if (parse_version_triplet_span(p, (size_t)(vend - p), &v) != 0)
            return LIBP2P_ERR_INTERNAL;
        out->has_low = 1;
        out->low = v;
        out->has_high = 1;
        out->high.major = v.major + 1;
        out->high.minor = 0;
        out->high.patch = 0;
        return 0;
    }
    if (*p == '~')
    {
        const char *q = skip_ws(p + 1);
        const char *vend = rskip_ws(q, endp);
        version_triplet_t v = (version_triplet_t){0};
        if (parse_version_triplet_span(q, (size_t)(vend - q), &v) != 0)
            return LIBP2P_ERR_INTERNAL;
        out->has_low = 1;
        out->low = v;
        out->has_high = 1;
        out->high.major = v.major;
        out->high.minor = v.minor + 1;
        out->high.patch = 0;
        /* Special case: pattern is just "~MAJOR" (no '.') */
        if (v.minor == 0 && v.patch == 0)
        {
            /* Check if original substring had no '.' */
            const char *dot = memchr(q, '.', (size_t)(vend - q));
            if (dot == NULL)
            {
                out->high.major = v.major + 1;
                out->high.minor = 0;
                out->high.patch = 0;
            }
        }
        return 0;
    }

    /* Comparator forms: ">=x.y.z", ">x.y", "<=x", "<x" possibly two clauses */
    if (memchr(p, '>', (size_t)(endp - p)) || memchr(p, '<', (size_t)(endp - p)))
    {
        semver_range_t r = {0};
        int clauses = 0;
        const char *cur = p;
        while (cur < endp && clauses < 2)
        {
            cur = skip_ws(cur);
            if (cur >= endp)
                break;
            const char *tok_start = cur;
            while (cur < endp && !isspace((unsigned char)*cur))
                cur++;
            const char *tok_end = cur; /* exclusive */
            if (tok_end <= tok_start)
                break;
            size_t tlen = (size_t)(tok_end - tok_start);
            /* Determine operator */
            int op_len = 0; /* 2 for ">=", "<=", 1 for ">" or "<" */
            if (tlen >= 2 && tok_start[0] == '>' && tok_start[1] == '=') op_len = 2;
            else if (tlen >= 2 && tok_start[0] == '<' && tok_start[1] == '=') op_len = 2;
            else if (tlen >= 1 && (tok_start[0] == '>' || tok_start[0] == '<')) op_len = 1;
            else return LIBP2P_ERR_INTERNAL;
            version_triplet_t vtmp = {0};
            if (op_len >= (int)tlen)
                return LIBP2P_ERR_INTERNAL; /* missing version */
            if (parse_version_triplet_span(tok_start + op_len, tlen - (size_t)op_len, &vtmp) != 0)
                return LIBP2P_ERR_INTERNAL;
            if (tok_start[0] == '>' && op_len == 2)
            {
                r.has_low = 1;
                r.low = vtmp;
            }
            else if (tok_start[0] == '>' && op_len == 1)
            {
                r.has_low = 1;
                r.low.major = vtmp.major;
                r.low.minor = vtmp.minor;
                r.low.patch = vtmp.patch + 1;
            }
            else if (tok_start[0] == '<' && op_len == 2)
            {
                r.has_high = 1;
                r.high.major = vtmp.major;
                r.high.minor = vtmp.minor;
                r.high.patch = vtmp.patch + 1;
            }
            else if (tok_start[0] == '<' && op_len == 1)
            {
                r.has_high = 1;
                r.high = vtmp;
            }
            clauses++;
        }
        *out = r;
        return (r.has_low || r.has_high) ? 0 : LIBP2P_ERR_INTERNAL;
    }

    /* Star range: MAJOR.* with optional surrounding whitespace */
    {
        const char *q = p;
        q = skip_ws(q);
        const char *qend = rskip_ws(q, endp);
        const char *cur = q;
        /* parse MAJOR */
        const char *maj_start = cur;
        while (cur < qend && isdigit((unsigned char)*cur)) cur++;
        if (cur > maj_start)
        {
            int major = 0;
            if (parse_uint_strict(maj_start, (size_t)(cur - maj_start), &major) == 0)
            {
                const char *after_num = cur;
                while (after_num < qend && isspace((unsigned char)*after_num)) after_num++;
                if (after_num < qend && *after_num == '.')
                {
                    after_num++;
                    while (after_num < qend && isspace((unsigned char)*after_num)) after_num++;
                    if (after_num < qend && *after_num == '*')
                    {
                        after_num++;
                        while (after_num < qend && isspace((unsigned char)*after_num)) after_num++;
                        if (after_num == qend)
                        {
                            out->has_low = 1;
                            out->low.major = major;
                            out->low.minor = 0;
                            out->low.patch = 0;
                            out->has_high = 1;
                            out->high.major = major + 1;
                            out->high.minor = 0;
                            out->high.patch = 0;
                            return 0;
                        }
                    }
                }
            }
        }
    }

    /* Exact version */
    {
        const char *q = skip_ws(p);
        const char *vend = rskip_ws(q, endp);
        version_triplet_t v = {0};
        if (parse_version_triplet_span(q, (size_t)(vend - q), &v) == 0)
        {
            out->exact = 1;
            out->exact_v = v;
            return 0;
        }
    }

    return LIBP2P_ERR_UNSUPPORTED;
}

int semver_in_range(const version_triplet_t *v, const semver_range_t *r)
{
    if (r->exact)
        return (v->major == r->exact_v.major && v->minor == r->exact_v.minor && v->patch == r->exact_v.patch);
    if (r->has_low)
    {
        if (!version_ge(v, &r->low))
            return 0;
    }
    if (r->has_high)
    {
        if (!version_lt(v, &r->high))
            return 0;
    }
    return 1;
}

int build_prefix_candidates(libp2p_host_t *host, const char *prefix, const char ***out_list, size_t *out_len)
{
    if (!host || !prefix || !out_list || !out_len)
        return LIBP2P_ERR_NULL_PTR;
    pthread_mutex_lock(&host->mtx);
    size_t count = 0;
    for (protocol_entry_t *e = host->protocols; e; e = e->next)
        if (e->def.protocol_id && strncmp(e->def.protocol_id, prefix, strlen(prefix)) == 0)
            count++;
    if (count == 0)
    {
        pthread_mutex_unlock(&host->mtx);
        *out_list = NULL;
        *out_len = 0;
        return 0;
    }
    candidate_item_t *items = (candidate_item_t *)calloc(count, sizeof(*items));
    if (!items)
    {
        pthread_mutex_unlock(&host->mtx);
        return LIBP2P_ERR_INTERNAL;
    }
    size_t idx = 0;
    for (protocol_entry_t *e = host->protocols; e; e = e->next)
    {
        if (e->def.protocol_id && strncmp(e->def.protocol_id, prefix, strlen(prefix)) == 0)
        {
            items[idx].id = e->def.protocol_id;
            version_triplet_t v;
            if (extract_version_from_id(e->def.protocol_id, prefix, &v) == 0)
            {
                items[idx].has_version = 1;
                items[idx].v = v;
            }
            else
            {
                items[idx].has_version = 0;
            }
            idx++;
        }
    }
    pthread_mutex_unlock(&host->mtx);
    qsort(items, count, sizeof(*items), cmp_candidates_desc);
    const char **arr = (const char **)calloc(count + 1, sizeof(*arr));
    if (!arr)
    {
        free(items);
        return LIBP2P_ERR_INTERNAL;
    }
    for (size_t i = 0; i < count; i++)
        arr[i] = items[i].id;
    arr[count] = NULL;
    free(items);
    *out_list = arr;
    *out_len = count;
    return 0;
}

int build_semver_candidates(libp2p_host_t *host, const char *base_path, const char *range_pattern, const char ***out_list, size_t *out_len)
{
    if (!host || !base_path || !range_pattern || !out_list || !out_len)
        return LIBP2P_ERR_NULL_PTR;
    semver_range_t range;
    int pr = parse_semver_range(range_pattern, &range);
    if (pr != 0)
        return pr;
    pthread_mutex_lock(&host->mtx);
    size_t count = 0;
    for (protocol_entry_t *e = host->protocols; e; e = e->next)
        if (e->def.protocol_id && strncmp(e->def.protocol_id, base_path, strlen(base_path)) == 0)
            count++;
    candidate_item_t *items = count ? (candidate_item_t *)calloc(count, sizeof(*items)) : NULL;
    size_t idx = 0;
    for (protocol_entry_t *e = host->protocols; e; e = e->next)
    {
        if (e->def.protocol_id && strncmp(e->def.protocol_id, base_path, strlen(base_path)) == 0)
        {
            version_triplet_t vtmp;
            if (extract_version_from_id(e->def.protocol_id, base_path, &vtmp) == 0 && semver_in_range(&vtmp, &range))
            {
                items[idx].id = e->def.protocol_id;
                items[idx].has_version = 1;
                items[idx].v = vtmp;
                idx++;
            }
        }
    }
    pthread_mutex_unlock(&host->mtx);
    if (idx == 0)
    {
        free(items);
        *out_list = NULL;
        *out_len = 0;
        return 0;
    }
    qsort(items, idx, sizeof(*items), cmp_candidates_desc);
    const char **arr = (const char **)calloc(idx + 1, sizeof(*arr));
    if (!arr)
    {
        free(items);
        return LIBP2P_ERR_INTERNAL;
    }
    for (size_t i = 0; i < idx; i++)
        arr[i] = items[i].id;
    arr[idx] = NULL;
    free(items);
    *out_list = arr;
    *out_len = idx;
    return 0;
}

int build_proposals_from_selector(libp2p_host_t *host, const libp2p_proto_selector_t *sel, const char ***out_list, size_t *out_len, int *out_dynamic)
{
    if (!host || !sel || !out_list || !out_len || !out_dynamic)
        return LIBP2P_ERR_NULL_PTR;
    switch (sel->kind)
    {
        case LIBP2P_PROTO_SELECT_EXACT:
        {
            if (!sel->exact_id)
                return LIBP2P_ERR_NULL_PTR;
            const char **arr = (const char **)calloc(2, sizeof(*arr));
            if (!arr)
                return LIBP2P_ERR_INTERNAL;
            arr[0] = sel->exact_id;
            arr[1] = NULL;
            *out_list = arr;
            *out_len = 1;
            *out_dynamic = 1;
            return 0;
        }
        case LIBP2P_PROTO_SELECT_LIST:
        {
            if (!sel->id_list || sel->id_list_len == 0)
                return LIBP2P_ERR_NULL_PTR;
            const char **arr = (const char **)calloc(sel->id_list_len + 1, sizeof(*arr));
            if (!arr)
                return LIBP2P_ERR_INTERNAL;
            for (size_t i = 0; i < sel->id_list_len; i++)
                arr[i] = sel->id_list[i];
            arr[sel->id_list_len] = NULL;
            *out_list = arr;
            *out_len = sel->id_list_len;
            *out_dynamic = 1;
            return 0;
        }
        case LIBP2P_PROTO_SELECT_PREFIX:
        {
            if (!sel->prefix)
                return LIBP2P_ERR_NULL_PTR;
            size_t n = 0;
            const char **arr = NULL;
            int rc = build_prefix_candidates(host, sel->prefix, &arr, &n);
            if (rc)
                return rc;
            if (!arr || n == 0)
                return LIBP2P_ERR_PROTO_NEGOTIATION_FAILED;
            *out_list = arr;
            *out_len = n;
            *out_dynamic = 1;
            return 0;
        }
        case LIBP2P_PROTO_SELECT_SEMVER:
        {
            if (!sel->base_path || !sel->semver_range)
                return LIBP2P_ERR_NULL_PTR;
            size_t n = 0;
            const char **arr = NULL;
            int rc = build_semver_candidates(host, sel->base_path, sel->semver_range, &arr, &n);
            if (rc)
                return rc;
            if (!arr || n == 0)
                return LIBP2P_ERR_PROTO_NEGOTIATION_FAILED;
            *out_list = arr;
            *out_len = n;
            *out_dynamic = 1;
            return 0;
        }
        default:
            return LIBP2P_ERR_UNSUPPORTED;
    }
}
