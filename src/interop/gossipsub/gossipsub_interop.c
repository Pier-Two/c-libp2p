#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "libp2p/dial.h"
#include "libp2p/host.h"
#include "libp2p/host_builder.h"
#include "libp2p/peer.h"
#include "libp2p/runtime.h"
#include "multiformats/unsigned_varint/unsigned_varint.h"
#include "peer_id/peer_id.h"
#include "peer_id/peer_id_ed25519.h"
#include "peer_id/peer_id_proto.h"
#include "protocol/gossipsub/gossipsub.h"
#include "protocol/gossipsub/message.h"

#include "jsmn.h"
#include "eddsa.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define HEARTBEAT_DEFAULT_NS (1000000000.0)
#define MAX_PEER_ID_STR 128

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
    int has_d;
    int d;
    int has_d_lo;
    int d_lo;
    int has_d_hi;
    int d_hi;
    int has_d_score;
    int d_score;
    int has_d_out;
    int d_out;
    int has_d_lazy;
    int d_lazy;
    int has_gossip_factor;
    double gossip_factor;
    int has_history_length;
    int history_length;
    int has_history_gossip;
    int history_gossip;
    int has_gossip_retransmission;
    int gossip_retransmission;
    int has_heartbeat_initial_delay_ns;
    double heartbeat_initial_delay_ns;
    int has_heartbeat_interval_ns;
    double heartbeat_interval_ns;
    int has_fanout_ttl_ns;
    double fanout_ttl_ns;
    int has_prune_peers;
    int prune_peers;
    int has_prune_backoff_ns;
    double prune_backoff_ns;
    int has_unsubscribe_backoff_ns;
    double unsubscribe_backoff_ns;
    int has_connectors;
    int connectors;
    int has_max_pending_connections;
    int max_pending_connections;
    int has_connection_timeout_ns;
    double connection_timeout_ns;
    int has_direct_connect_ticks;
    int direct_connect_ticks;
    int has_direct_connect_initial_delay_ns;
    double direct_connect_initial_delay_ns;
    int has_opportunistic_graft_ticks;
    int opportunistic_graft_ticks;
    int has_opportunistic_graft_peers;
    int opportunistic_graft_peers;
    int has_graft_flood_threshold_ns;
    double graft_flood_threshold_ns;
    int has_max_ihave_length;
    int max_ihave_length;
    int has_max_ihave_messages;
    int max_ihave_messages;
    int has_max_idontwant_length;
    int max_idontwant_length;
    int has_max_idontwant_messages;
    int max_idontwant_messages;
    int has_iwant_followup_time_ns;
    double iwant_followup_time_ns;
    int has_idontwant_message_threshold;
    int idontwant_message_threshold;
    int has_idontwant_message_ttl_ns;
    double idontwant_message_ttl_ns;
} gossipsub_params_t;

typedef enum
{
    INSTR_CONNECT,
    INSTR_IF_NODE_ID_EQUALS,
    INSTR_WAIT_UNTIL,
    INSTR_PUBLISH,
    INSTR_SUBSCRIBE,
    INSTR_SET_TOPIC_VALIDATION_DELAY,
    INSTR_INIT_GOSSIPSUB
} instruction_type_t;

struct instruction;

typedef struct instruction
{
    instruction_type_t type;
    union
    {
        struct
        {
            int *targets;
            size_t target_count;
        } connect;
        struct
        {
            int node_id;
            struct instruction *inner;
        } conditional;
        struct
        {
            int elapsed_seconds;
        } wait;
        struct
        {
            int message_id;
            int message_size_bytes;
            char *topic;
        } publish;
        struct
        {
            char *topic;
        } subscribe;
        struct
        {
            char *topic;
            double delay_seconds;
        } validation_delay;
        struct
        {
            gossipsub_params_t params;
        } init;
    } data;
} instruction_t;

typedef struct
{
    instruction_t *items;
    size_t count;
} script_t;

struct context;

typedef struct topic_state
{
    char *name;
    double validation_delay_seconds;
    libp2p_gossipsub_validator_handle_t *validator;
    pthread_mutex_t lock;
    struct topic_state *next;
    struct context *ctx;
} topic_state_t;

typedef struct context
{
    libp2p_host_t *host;
    libp2p_gossipsub_t *gs;
    int node_id;
    char peer_id_str[MAX_PEER_ID_STR];
    struct timespec start_mono;
    topic_state_t *topics;
} context_t;

typedef struct
{
    const char *json;
    jsmntok_t *tokens;
    size_t token_count;
} json_doc_t;

static void free_instruction(instruction_t *instr);
static void free_script(script_t *script);
static void free_topic_states(topic_state_t *head);

static void fatal_perror(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void fatal_msg(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0)
    {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf)
    {
        fclose(f);
        return NULL;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz)
    {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    if (out_len)
        *out_len = (size_t)sz;
    return buf;
}

static int json_skip(const json_doc_t *doc, int index)
{
    if (index < 0 || (size_t)index >= doc->token_count)
        return -1;
    const jsmntok_t *tok = &doc->tokens[index];
    int i = index + 1;
    if (tok->type == JSMN_OBJECT)
    {
        for (int j = 0; j < tok->size; ++j)
        {
            i = json_skip(doc, i);
            if (i < 0)
                return -1;
            i = json_skip(doc, i);
            if (i < 0)
                return -1;
        }
        return i;
    }
    if (tok->type == JSMN_ARRAY)
    {
        for (int j = 0; j < tok->size; ++j)
        {
            i = json_skip(doc, i);
            if (i < 0)
                return -1;
        }
        return i;
    }
    return index + 1;
}

static int json_token_equals(const json_doc_t *doc, const jsmntok_t *tok, const char *s)
{
    size_t len = (size_t)(tok->end - tok->start);
    return (tok->type == JSMN_STRING && strlen(s) == len && strncmp(doc->json + tok->start, s, len) == 0);
}

static int json_object_get(const json_doc_t *doc, int obj_index, const char *key)
{
    if (obj_index < 0 || (size_t)obj_index >= doc->token_count)
        return -1;
    const jsmntok_t *obj = &doc->tokens[obj_index];
    if (obj->type != JSMN_OBJECT)
        return -1;
    int i = obj_index + 1;
    for (int j = 0; j < obj->size; ++j)
    {
        const jsmntok_t *key_tok = &doc->tokens[i];
        int value_index = json_skip(doc, i);
        if (value_index < 0)
            return -1;
        if (json_token_equals(doc, key_tok, key))
            return i + 1;
        i = value_index;
    }
    return -1;
}

static char *json_strdup_token(const json_doc_t *doc, const jsmntok_t *tok)
{
    size_t len = (size_t)(tok->end - tok->start);
    char *out = (char *)malloc(len + 1);
    if (!out)
        return NULL;
    memcpy(out, doc->json + tok->start, len);
    out[len] = '\0';
    return out;
}

static int json_parse_int(const json_doc_t *doc, const jsmntok_t *tok, int *out)
{
    if (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)
        return -1;
    char *str = json_strdup_token(doc, tok);
    if (!str)
        return -1;
    char *end = NULL;
    long val = strtol(str, &end, 10);
    int rc = 0;
    if (end == str || *end != '\0')
        rc = -1;
    else
        *out = (int)val;
    free(str);
    return rc;
}

static int json_parse_double(const json_doc_t *doc, const jsmntok_t *tok, double *out)
{
    if (tok->type != JSMN_PRIMITIVE && tok->type != JSMN_STRING)
        return -1;
    char *str = json_strdup_token(doc, tok);
    if (!str)
        return -1;
    char *end = NULL;
    double val = strtod(str, &end);
    int rc = 0;
    if (end == str || *end != '\0')
        rc = -1;
    else
        *out = val;
    free(str);
    return rc;
}

static int parse_gossipsub_params(const json_doc_t *doc, int obj_index, gossipsub_params_t *out)
{
    memset(out, 0, sizeof(*out));
    if (obj_index < 0)
        return 0;
    const jsmntok_t *obj = &doc->tokens[obj_index];
    if (obj->type != JSMN_OBJECT)
        return -1;
#define PARSE_INT_FIELD(field_name, member)                                                                                                   \
    do                                                                                                                                         \
    {                                                                                                                                          \
        int tok_index = json_object_get(doc, obj_index, field_name);                                                                           \
        if (tok_index >= 0)                                                                                                                    \
        {                                                                                                                                      \
            if (json_parse_int(doc, &doc->tokens[tok_index], &out->member) != 0)                                                               \
                return -1;                                                                                                                     \
            out->has_##member = 1;                                                                                                             \
        }                                                                                                                                      \
    } while (0)

#define PARSE_DOUBLE_FIELD(field_name, member)                                                                                                \
    do                                                                                                                                         \
    {                                                                                                                                          \
        int tok_index = json_object_get(doc, obj_index, field_name);                                                                           \
        if (tok_index >= 0)                                                                                                                    \
        {                                                                                                                                      \
            if (json_parse_double(doc, &doc->tokens[tok_index], &out->member) != 0)                                                            \
                return -1;                                                                                                                     \
            out->has_##member = 1;                                                                                                             \
        }                                                                                                                                      \
    } while (0)

    PARSE_INT_FIELD("D", d);
    PARSE_INT_FIELD("Dlo", d_lo);
    PARSE_INT_FIELD("Dhi", d_hi);
    PARSE_INT_FIELD("Dscore", d_score);
    PARSE_INT_FIELD("Dout", d_out);
    PARSE_INT_FIELD("Dlazy", d_lazy);
    PARSE_DOUBLE_FIELD("GossipFactor", gossip_factor);
    PARSE_INT_FIELD("HistoryLength", history_length);
    PARSE_INT_FIELD("HistoryGossip", history_gossip);
    PARSE_INT_FIELD("GossipRetransmission", gossip_retransmission);
    PARSE_DOUBLE_FIELD("HeartbeatInitialDelay", heartbeat_initial_delay_ns);
    PARSE_DOUBLE_FIELD("HeartbeatInterval", heartbeat_interval_ns);
    PARSE_DOUBLE_FIELD("FanoutTTL", fanout_ttl_ns);
    PARSE_INT_FIELD("PrunePeers", prune_peers);
    PARSE_DOUBLE_FIELD("PruneBackoff", prune_backoff_ns);
    PARSE_DOUBLE_FIELD("UnsubscribeBackoff", unsubscribe_backoff_ns);
    PARSE_INT_FIELD("Connectors", connectors);
    PARSE_INT_FIELD("MaxPendingConnections", max_pending_connections);
    PARSE_DOUBLE_FIELD("ConnectionTimeout", connection_timeout_ns);
    PARSE_INT_FIELD("DirectConnectTicks", direct_connect_ticks);
    PARSE_DOUBLE_FIELD("DirectConnectInitialDelay", direct_connect_initial_delay_ns);
    PARSE_INT_FIELD("OpportunisticGraftTicks", opportunistic_graft_ticks);
    PARSE_INT_FIELD("OpportunisticGraftPeers", opportunistic_graft_peers);
    PARSE_DOUBLE_FIELD("GraftFloodThreshold", graft_flood_threshold_ns);
    PARSE_INT_FIELD("MaxIHaveLength", max_ihave_length);
    PARSE_INT_FIELD("MaxIHaveMessages", max_ihave_messages);
    PARSE_INT_FIELD("MaxIDontWantLength", max_idontwant_length);
    PARSE_INT_FIELD("MaxIDontWantMessages", max_idontwant_messages);
    PARSE_DOUBLE_FIELD("IWantFollowupTime", iwant_followup_time_ns);
    PARSE_INT_FIELD("IDontWantMessageThreshold", idontwant_message_threshold);
    PARSE_DOUBLE_FIELD("IDontWantMessageTTL", idontwant_message_ttl_ns);

#undef PARSE_INT_FIELD
#undef PARSE_DOUBLE_FIELD
    return 0;
}

static int parse_instruction_recursive(const json_doc_t *doc, int index, instruction_t *out, int *next_index);

static int parse_connect_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    const jsmntok_t *obj = &doc->tokens[index];
    if (obj->type != JSMN_OBJECT)
        return -1;
    int arr_index = json_object_get(doc, index, "connectTo");
    if (arr_index < 0)
        return -1;
    const jsmntok_t *arr = &doc->tokens[arr_index];
    if (arr->type != JSMN_ARRAY)
        return -1;
    size_t count = (size_t)arr->size;
    int *targets = NULL;
    if (count > 0)
    {
        targets = (int *)calloc(count, sizeof(int));
        if (!targets)
            return -1;
    }
    int tok_idx = arr_index + 1;
    for (size_t i = 0; i < count; ++i)
    {
        if (json_parse_int(doc, &doc->tokens[tok_idx], &targets[i]) != 0)
        {
            free(targets);
            return -1;
        }
        tok_idx = json_skip(doc, tok_idx);
        if (tok_idx < 0)
        {
            free(targets);
            return -1;
        }
    }
    out->type = INSTR_CONNECT;
    out->data.connect.targets = targets;
    out->data.connect.target_count = count;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_if_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    int node_id_index = json_object_get(doc, index, "nodeID");
    if (node_id_index < 0)
        return -1;
    int node_id = 0;
    if (json_parse_int(doc, &doc->tokens[node_id_index], &node_id) != 0)
        return -1;
    int inner_index = json_object_get(doc, index, "instruction");
    if (inner_index < 0)
        return -1;
    instruction_t *inner = (instruction_t *)calloc(1, sizeof(*inner));
    if (!inner)
        return -1;
    int inner_next = 0;
    if (parse_instruction_recursive(doc, inner_index, inner, &inner_next) != 0)
    {
        free_instruction(inner);
        free(inner);
        return -1;
    }
    (void)inner_next;
    out->type = INSTR_IF_NODE_ID_EQUALS;
    out->data.conditional.node_id = node_id;
    out->data.conditional.inner = inner;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_wait_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    int elapsed_index = json_object_get(doc, index, "elapsedSeconds");
    if (elapsed_index < 0)
        return -1;
    int value = 0;
    if (json_parse_int(doc, &doc->tokens[elapsed_index], &value) != 0)
        return -1;
    out->type = INSTR_WAIT_UNTIL;
    out->data.wait.elapsed_seconds = value;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_publish_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    int message_id_index = json_object_get(doc, index, "messageID");
    int message_size_index = json_object_get(doc, index, "messageSizeBytes");
    int topic_index = json_object_get(doc, index, "topicID");
    if (message_id_index < 0 || message_size_index < 0 || topic_index < 0)
        return -1;
    int message_id = 0;
    int message_size = 0;
    if (json_parse_int(doc, &doc->tokens[message_id_index], &message_id) != 0 ||
        json_parse_int(doc, &doc->tokens[message_size_index], &message_size) != 0)
        return -1;
    char *topic = json_strdup_token(doc, &doc->tokens[topic_index]);
    if (!topic)
        return -1;
    out->type = INSTR_PUBLISH;
    out->data.publish.message_id = message_id;
    out->data.publish.message_size_bytes = message_size;
    out->data.publish.topic = topic;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_subscribe_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    int topic_index = json_object_get(doc, index, "topicID");
    if (topic_index < 0)
        return -1;
    char *topic = json_strdup_token(doc, &doc->tokens[topic_index]);
    if (!topic)
        return -1;
    out->type = INSTR_SUBSCRIBE;
    out->data.subscribe.topic = topic;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_validation_delay_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    int topic_index = json_object_get(doc, index, "topicID");
    int delay_index = json_object_get(doc, index, "delaySeconds");
    if (topic_index < 0 || delay_index < 0)
        return -1;
    char *topic = json_strdup_token(doc, &doc->tokens[topic_index]);
    if (!topic)
        return -1;
    double delay = 0.0;
    if (json_parse_double(doc, &doc->tokens[delay_index], &delay) != 0)
    {
        free(topic);
        return -1;
    }
    out->type = INSTR_SET_TOPIC_VALIDATION_DELAY;
    out->data.validation_delay.topic = topic;
    out->data.validation_delay.delay_seconds = delay;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_init_instruction(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    int params_index = json_object_get(doc, index, "gossipSubParams");
    gossipsub_params_t params;
    memset(&params, 0, sizeof(params));
    if (params_index >= 0)
    {
        if (parse_gossipsub_params(doc, params_index, &params) != 0)
            return -1;
    }
    out->type = INSTR_INIT_GOSSIPSUB;
    out->data.init.params = params;
    *next_index = json_skip(doc, index);
    return (*next_index < 0) ? -1 : 0;
}

static int parse_instruction_recursive(const json_doc_t *doc, int index, instruction_t *out, int *next_index)
{
    const jsmntok_t *obj = &doc->tokens[index];
    if (obj->type != JSMN_OBJECT)
        return -1;
    int type_index = json_object_get(doc, index, "type");
    if (type_index < 0)
        return -1;
    char *type = json_strdup_token(doc, &doc->tokens[type_index]);
    if (!type)
        return -1;
    int rc = -1;
    if (strcmp(type, "connect") == 0)
        rc = parse_connect_instruction(doc, index, out, next_index);
    else if (strcmp(type, "ifNodeIDEquals") == 0)
        rc = parse_if_instruction(doc, index, out, next_index);
    else if (strcmp(type, "waitUntil") == 0)
        rc = parse_wait_instruction(doc, index, out, next_index);
    else if (strcmp(type, "publish") == 0)
        rc = parse_publish_instruction(doc, index, out, next_index);
    else if (strcmp(type, "subscribeToTopic") == 0)
        rc = parse_subscribe_instruction(doc, index, out, next_index);
    else if (strcmp(type, "setTopicValidationDelay") == 0)
        rc = parse_validation_delay_instruction(doc, index, out, next_index);
    else if (strcmp(type, "initGossipSub") == 0)
        rc = parse_init_instruction(doc, index, out, next_index);
    free(type);
    return rc;
}

static int parse_script(const json_doc_t *doc, int array_index, script_t *out)
{
    const jsmntok_t *arr = &doc->tokens[array_index];
    if (arr->type != JSMN_ARRAY)
        return -1;
    size_t count = (size_t)arr->size;
    instruction_t *items = NULL;
    if (count > 0)
    {
        items = (instruction_t *)calloc(count, sizeof(*items));
        if (!items)
            return -1;
    }
    int tok_idx = array_index + 1;
    for (size_t i = 0; i < count; ++i)
    {
        int next_idx = 0;
        if (parse_instruction_recursive(doc, tok_idx, &items[i], &next_idx) != 0)
        {
            for (size_t j = 0; j <= i; ++j)
                free_instruction(&items[j]);
            free(items);
            return -1;
        }
        tok_idx = next_idx;
    }
    out->items = items;
    out->count = count;
    return 0;
}

static void free_instruction(instruction_t *instr)
{
    if (!instr)
        return;
    switch (instr->type)
    {
        case INSTR_CONNECT:
            free(instr->data.connect.targets);
            instr->data.connect.targets = NULL;
            instr->data.connect.target_count = 0;
            break;
        case INSTR_IF_NODE_ID_EQUALS:
            if (instr->data.conditional.inner)
            {
                free_instruction(instr->data.conditional.inner);
                free(instr->data.conditional.inner);
                instr->data.conditional.inner = NULL;
            }
            break;
        case INSTR_PUBLISH:
            free(instr->data.publish.topic);
            instr->data.publish.topic = NULL;
            break;
        case INSTR_SUBSCRIBE:
            free(instr->data.subscribe.topic);
            instr->data.subscribe.topic = NULL;
            break;
        case INSTR_SET_TOPIC_VALIDATION_DELAY:
            free(instr->data.validation_delay.topic);
            instr->data.validation_delay.topic = NULL;
            break;
        case INSTR_WAIT_UNTIL:
        case INSTR_INIT_GOSSIPSUB:
            break;
    }
}

static void free_script(script_t *script)
{
    if (!script || !script->items)
        return;
    for (size_t i = 0; i < script->count; ++i)
        free_instruction(&script->items[i]);
    free(script->items);
    script->items = NULL;
    script->count = 0;
}

static void free_topic_states(topic_state_t *head)
{
    topic_state_t *curr = head;
    while (curr)
    {
        topic_state_t *next = curr->next;
        if (curr->validator && curr->ctx && curr->ctx->gs)
        {
            libp2p_gossipsub_remove_validator(curr->ctx->gs, curr->validator);
            curr->validator = NULL;
        }
        free(curr->name);
        pthread_mutex_destroy(&curr->lock);
        free(curr);
        curr = next;
    }
}

static void format_timestamp(char *buf, size_t buf_len)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char temp[64];
    strftime(temp, sizeof(temp), "%Y-%m-%dT%H:%M:%S", &tm);
    long nanosec = ts.tv_nsec;
    snprintf(buf, buf_len, "%s.%06ldZ", temp, nanosec / 1000);
}

static void json_print_string(FILE *out, const char *value)
{
    fputc('"', out);
    for (const char *p = value; p && *p; ++p)
    {
        unsigned char c = (unsigned char)*p;
        switch (c)
        {
            case '"':
            case '\\':
                fputc('\\', out);
                fputc(c, out);
                break;
            case '\b':
                fputs("\\b", out);
                break;
            case '\f':
                fputs("\\f", out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (c < 0x20)
                    fprintf(out, "\\u%04x", c);
                else
                    fputc(c, out);
        }
    }
    fputc('"', out);
}

typedef void (*log_body_fn)(FILE *, void *);

static void log_json_event(const char *msg, log_body_fn body_fn, void *user_data)
{
    char timestamp[64];
    format_timestamp(timestamp, sizeof(timestamp));
    pthread_mutex_lock(&log_mutex);
    fputs("{\"time\":", stdout);
    json_print_string(stdout, timestamp);
    fputs(",\"msg\":", stdout);
    json_print_string(stdout, msg);
    if (body_fn)
        body_fn(stdout, user_data);
    fputs("}\n", stdout);
    fflush(stdout);
    pthread_mutex_unlock(&log_mutex);
}

typedef struct
{
    const context_t *ctx;
    const char *peer_id_str;
} peer_log_ctx_t;

static void peer_log_body(FILE *out, void *user_data)
{
    peer_log_ctx_t *ctx = (peer_log_ctx_t *)user_data;
    fputs(",\"id\":", out);
    json_print_string(out, ctx->peer_id_str);
    fprintf(out, ",\"node_id\":%d", ctx->ctx->node_id);
}

static void log_peer_id_event(const context_t *ctx, const char *peer_id_str)
{
    peer_log_ctx_t body = { .ctx = ctx, .peer_id_str = peer_id_str };
    log_json_event("PeerID", peer_log_body, &body);
}

typedef struct
{
    const context_t *ctx;
    const char *topic;
    const char *from_peer;
    const char *message_id;
} msg_log_ctx_t;

static void message_log_body(FILE *out, void *user_data)
{
    msg_log_ctx_t *b = (msg_log_ctx_t *)user_data;
    fputs(",\"id\":", out);
    json_print_string(out, b->message_id);
    if (b->topic)
    {
        fputs(",\"topic\":", out);
        json_print_string(out, b->topic);
    }
    if (b->from_peer)
    {
        fputs(",\"from\":", out);
        json_print_string(out, b->from_peer);
    }
    fprintf(out, ",\"node_id\":%d", b->ctx->node_id);
}

static void log_received_message_event(const context_t *ctx,
                                       const char *topic,
                                       const char *from_peer,
                                       const char *message_id_str)
{
    msg_log_ctx_t body = { ctx, topic, from_peer, message_id_str };
    log_json_event("Received Message", message_log_body, &body);
}

typedef struct
{
    uint8_t *bytes;
    size_t len;
} buffer_t;

static void buffer_free(buffer_t *buf)
{
    if (!buf)
        return;
    free(buf->bytes);
    buf->bytes = NULL;
    buf->len = 0;
}

static int build_private_key_protobuf(uint64_t key_type, const uint8_t *key_data, size_t key_len, buffer_t *out)
{
    if (!out)
        return -1;
    out->bytes = NULL;
    out->len = 0;
    if (!key_data || key_len == 0)
        return -1;
    uint8_t type_buf[10];
    uint8_t len_buf[10];
    size_t type_size = 0;
    size_t len_size = 0;
    if (unsigned_varint_encode(key_type, type_buf, sizeof(type_buf), &type_size) != UNSIGNED_VARINT_OK)
        return -1;
    if (unsigned_varint_encode((uint64_t)key_len, len_buf, sizeof(len_buf), &len_size) != UNSIGNED_VARINT_OK)
        return -1;
    size_t total = 1 + type_size + 1 + len_size + key_len;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf)
        return -1;
    size_t offset = 0;
    buf[offset++] = 0x08;
    memcpy(buf + offset, type_buf, type_size);
    offset += type_size;
    buf[offset++] = 0x12;
    memcpy(buf + offset, len_buf, len_size);
    offset += len_size;
    memcpy(buf + offset, key_data, key_len);
    out->bytes = buf;
    out->len = total;
    return 0;
}

static int derive_node_identity(int node_id, buffer_t *priv_key_pb, char peer_id_str[MAX_PEER_ID_STR])
{
    if (priv_key_pb)
    {
        priv_key_pb->bytes = NULL;
        priv_key_pb->len = 0;
    }
    if (peer_id_str)
        peer_id_str[0] = '\0';
    uint8_t seed[32] = {0};
    for (int i = 0; i < 8; ++i)
        seed[i] = (uint8_t)((node_id >> (8 * i)) & 0xFF);
    uint8_t pub[32];
    ed25519_genpub(pub, seed);
    uint8_t priv_concat[64];
    memcpy(priv_concat, seed, 32);
    memcpy(priv_concat + 32, pub, 32);
    buffer_t pb = {0};
    if (build_private_key_protobuf(PEER_ID_ED25519_KEY_TYPE, priv_concat, sizeof(priv_concat), &pb) != 0)
        return -1;
    if (priv_key_pb)
        *priv_key_pb = pb;
    if (peer_id_str)
    {
        libp2p_private_key_t sk = {
            .bytes = pb.bytes,
            .len = pb.len,
        };
        libp2p_peer_id_t *pid = NULL;
        if (libp2p_peer_id_from_private_key(&sk, &pid) != 0)
        {
            buffer_free(&pb);
            return -1;
        }
        if (libp2p_peer_id_to_string(pid, peer_id_str, MAX_PEER_ID_STR) < 0)
        {
            libp2p_peer_id_free(pid);
            buffer_free(&pb);
            return -1;
        }
        libp2p_peer_id_free(pid);
    }
    if (!priv_key_pb)
        buffer_free(&pb);
    return 0;
}

static int get_hostname_node_id(int *out_node_id)
{
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0)
        return -1;
    int node_id = 0;
    if (sscanf(hostname, "node%d", &node_id) != 1)
        return -1;
    *out_node_id = node_id;
    return 0;
}

static void nanosleep_seconds(double seconds)
{
    if (seconds <= 0.0)
        return;
    struct timespec req;
    req.tv_sec = (time_t)seconds;
    req.tv_nsec = (long)((seconds - req.tv_sec) * 1e9);
    while (nanosleep(&req, &req) != 0 && errno == EINTR)
        ;
}

static void wait_until_elapsed(const context_t *ctx, int elapsed_seconds)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double start = ctx->start_mono.tv_sec + ctx->start_mono.tv_nsec / 1e9;
    double current = now.tv_sec + now.tv_nsec / 1e9;
    double target = start + elapsed_seconds;
    double diff = target - current;
    if (diff > 0)
        nanosleep_seconds(diff);
}

static topic_state_t *find_topic_state(context_t *ctx, const char *topic, bool create_if_missing)
{
    topic_state_t *prev = NULL;
    topic_state_t *curr = ctx->topics;
    while (curr)
    {
        if (strcmp(curr->name, topic) == 0)
            return curr;
        prev = curr;
        curr = curr->next;
    }
    if (!create_if_missing)
        return NULL;
    topic_state_t *state = (topic_state_t *)calloc(1, sizeof(*state));
    if (!state)
        return NULL;
    state->name = strdup(topic);
    if (!state->name)
    {
        free(state);
        return NULL;
    }
    pthread_mutex_init(&state->lock, NULL);
    state->ctx = ctx;
    state->next = NULL;
    if (prev)
        prev->next = state;
    else
        ctx->topics = state;
    return state;
}

static libp2p_err_t message_id_fn(const libp2p_gossipsub_message_t *msg,
                                  uint8_t **out_id,
                                  size_t *out_len,
                                  void *user_data)
{
    (void)user_data;
    if (!msg || !out_id || !out_len || !msg->data || msg->data_len < 8)
        return LIBP2P_ERR_UNSUPPORTED;
    uint8_t *buf = (uint8_t *)malloc(8);
    if (!buf)
        return LIBP2P_ERR_INTERNAL;
    memcpy(buf, msg->data, 8);
    *out_id = buf;
    *out_len = 8;
    return LIBP2P_ERR_OK;
}

static libp2p_gossipsub_validation_result_t validator_cb(const libp2p_gossipsub_message_t *msg, void *user_data)
{
    topic_state_t *state = (topic_state_t *)user_data;
    if (!state || !msg)
        return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
    double delay = 0.0;
    pthread_mutex_lock(&state->lock);
    delay = state->validation_delay_seconds;
    pthread_mutex_unlock(&state->lock);
    if (delay > 0.0)
        nanosleep_seconds(delay);
    uint64_t msg_id = 0;
    if (msg->data && msg->data_len >= 8)
    {
        for (int i = 0; i < 8; ++i)
            msg_id = (msg_id << 8) | msg->data[i];
    }
    char id_buf[32];
    snprintf(id_buf, sizeof(id_buf), "%" PRIu64, msg_id);
    char from_buf[MAX_PEER_ID_STR];
    from_buf[0] = '\0';
    if (msg->from)
        libp2p_peer_id_to_string((const libp2p_peer_id_t *)msg->from, from_buf, sizeof(from_buf));
    log_received_message_event(state->ctx,
                               msg->topic.topic ? msg->topic.topic : NULL,
                               (msg->from && from_buf[0]) ? from_buf : NULL,
                               id_buf);
    return LIBP2P_GOSSIPSUB_VALIDATION_ACCEPT;
}

static int resolve_node_address(int node_id, char *addr_buf, size_t addr_buf_len, int *is_ipv6)
{
    char hostname[64];
    snprintf(hostname, sizeof(hostname), "node%d", node_id);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0)
        return -1;
    int found = -1;
    for (struct addrinfo *p = res; p; p = p->ai_next)
    {
        void *addr_ptr = NULL;
        if (p->ai_family == AF_INET)
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
            addr_ptr = &sin->sin_addr;
            if (inet_ntop(AF_INET, addr_ptr, addr_buf, (socklen_t)addr_buf_len))
            {
                *is_ipv6 = 0;
                found = 0;
                break;
            }
        }
        else if (p->ai_family == AF_INET6)
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)p->ai_addr;
            addr_ptr = &sin6->sin6_addr;
            if (inet_ntop(AF_INET6, addr_ptr, addr_buf, (socklen_t)addr_buf_len))
            {
                *is_ipv6 = 1;
                found = 0;
                break;
            }
        }
    }
    freeaddrinfo(res);
    return found;
}

static int connect_to_node(context_t *ctx, int target_node)
{
    char addr[INET6_ADDRSTRLEN];
    int is_ipv6 = 0;
    if (resolve_node_address(target_node, addr, sizeof(addr), &is_ipv6) != 0)
    {
        fprintf(stderr, "Failed to resolve node%d\n", target_node);
        return -1;
    }
    char peer_id_str[MAX_PEER_ID_STR];
    if (derive_node_identity(target_node, NULL, peer_id_str) != 0)
    {
        fprintf(stderr, "Failed to derive peer ID for node%d\n", target_node);
        return -1;
    }
    char maddr[256];
    if (is_ipv6)
        snprintf(maddr, sizeof(maddr), "/ip6/%s/tcp/9000/p2p/%s", addr, peer_id_str);
    else
        snprintf(maddr, sizeof(maddr), "/ip4/%s/tcp/9000/p2p/%s", addr, peer_id_str);
    libp2p_peer_id_t *pid = NULL;
    if (libp2p_peer_id_from_string(peer_id_str, &pid) != 0)
    {
        fprintf(stderr, "Failed to parse peer ID %s\n", peer_id_str);
        return -1;
    }
    if (libp2p_host_add_peer_addr_str(ctx->host, pid, maddr, 60000) != 0)
    {
        libp2p_peer_id_free(pid);
        fprintf(stderr, "Failed to add peer address %s\n", maddr);
        return -1;
    }
    if (libp2p_gossipsub_peering_add(ctx->gs, pid) != LIBP2P_ERR_OK)
    {
        libp2p_peer_id_free(pid);
        fprintf(stderr, "Failed to add gossipsub peering for %s\n", peer_id_str);
        return -1;
    }
    libp2p_peer_id_free(pid);
    return 0;
}

static double ns_to_ms(double ns)
{
    return ns / 1e6;
}

static int apply_gossipsub_params(const gossipsub_params_t *params, libp2p_gossipsub_config_t *cfg)
{
    if (!params || !cfg)
        return -1;
    if (params->has_d)
        cfg->d = params->d;
    if (params->has_d_lo)
        cfg->d_lo = params->d_lo;
    if (params->has_d_hi)
        cfg->d_hi = params->d_hi;
    if (params->has_d_score)
        cfg->d_score = params->d_score;
    if (params->has_d_out)
        cfg->d_out = params->d_out;
    if (params->has_d_lazy)
        cfg->d_lazy = params->d_lazy;
    if (params->has_gossip_factor)
    {
        int percent = (int)lrint(params->gossip_factor * 100.0);
        if (percent < 0)
            percent = 0;
        cfg->gossip_factor_percent = percent;
    }
    if (params->has_history_length)
        cfg->message_cache_length = (size_t)params->history_length;
    if (params->has_history_gossip)
        cfg->message_cache_gossip = (size_t)params->history_gossip;
    if (params->has_prune_peers)
        cfg->px_peer_target = (size_t)params->prune_peers;
    if (params->has_prune_backoff_ns)
        cfg->prune_backoff_ms = (int)llround(ns_to_ms(params->prune_backoff_ns));
    if (params->has_heartbeat_interval_ns)
        cfg->heartbeat_interval_ms = (int)llround(ns_to_ms(params->heartbeat_interval_ns));
    if (params->has_opportunistic_graft_ticks)
    {
        double hb_ms = cfg->heartbeat_interval_ms > 0 ? cfg->heartbeat_interval_ms : ns_to_ms(HEARTBEAT_DEFAULT_NS);
        cfg->opportunistic_graft_interval_ms = (int)llround(hb_ms * params->opportunistic_graft_ticks);
    }
    if (params->has_opportunistic_graft_peers)
        cfg->opportunistic_graft_peers = params->opportunistic_graft_peers;
    if (params->has_graft_flood_threshold_ns)
        cfg->graft_flood_threshold_ms = (int)llround(ns_to_ms(params->graft_flood_threshold_ns));
    if (params->has_max_ihave_length)
        cfg->max_ihave_length = (size_t)params->max_ihave_length;
    if (params->has_max_ihave_messages)
        cfg->max_ihave_messages = (size_t)params->max_ihave_messages;
    if (params->has_iwant_followup_time_ns)
        cfg->iwant_followup_time_ms = (int)llround(ns_to_ms(params->iwant_followup_time_ns));
    return 0;
}

static int subscribe_topic(context_t *ctx, const char *topic_name)
{
    topic_state_t *state = find_topic_state(ctx, topic_name, true);
    if (!state)
        return -1;
    libp2p_gossipsub_topic_config_t topic_cfg;
    memset(&topic_cfg, 0, sizeof(topic_cfg));
    topic_cfg.struct_size = sizeof(topic_cfg);
    topic_cfg.descriptor.struct_size = sizeof(topic_cfg.descriptor);
    topic_cfg.descriptor.topic = topic_name;
    topic_cfg.message_id_fn = message_id_fn;
    topic_cfg.message_id_user_data = NULL;
    if (libp2p_gossipsub_subscribe(ctx->gs, &topic_cfg) != LIBP2P_ERR_OK)
        return -1;
    if (!state->validator)
    {
        libp2p_gossipsub_validator_def_t def;
        memset(&def, 0, sizeof(def));
        def.struct_size = sizeof(def);
        def.type = LIBP2P_GOSSIPSUB_VALIDATOR_SYNC;
        def.sync_fn = validator_cb;
        def.user_data = state;
        if (libp2p_gossipsub_add_validator(ctx->gs, topic_name, &def, &state->validator) != LIBP2P_ERR_OK)
            return -1;
    }
    return 0;
}

static int publish_message(context_t *ctx, const instruction_t *instr)
{
    const char *topic = instr->data.publish.topic;
    int size = instr->data.publish.message_size_bytes;
    if (size < 8)
    {
        fprintf(stderr, "publish message size too small\n");
        return -1;
    }
    uint8_t *data = (uint8_t *)calloc(1, (size_t)size);
    if (!data)
        return -1;
    uint64_t msg_id = (uint64_t)instr->data.publish.message_id;
    for (int i = 0; i < 8; ++i)
        data[i] = (uint8_t)((msg_id >> (56 - 8 * i)) & 0xFF);
    libp2p_gossipsub_message_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.topic.struct_size = sizeof(msg.topic);
    msg.topic.topic = topic;
    msg.data = data;
    msg.data_len = (size_t)size;
    libp2p_err_t rc = libp2p_gossipsub_publish(ctx->gs, &msg);
    free(data);
    if (rc != LIBP2P_ERR_OK)
    {
        fprintf(stderr, "libp2p_gossipsub_publish failed (%d)\n", rc);
        return -1;
    }
    return 0;
}

static int execute_instruction(context_t *ctx, const instruction_t *instr)
{
    switch (instr->type)
    {
        case INSTR_CONNECT:
            for (size_t i = 0; i < instr->data.connect.target_count; ++i)
            {
                if (connect_to_node(ctx, instr->data.connect.targets[i]) != 0)
                    return -1;
            }
            break;
        case INSTR_IF_NODE_ID_EQUALS:
            if (ctx->node_id == instr->data.conditional.node_id)
                return execute_instruction(ctx, instr->data.conditional.inner);
            break;
        case INSTR_WAIT_UNTIL:
            wait_until_elapsed(ctx, instr->data.wait.elapsed_seconds);
            break;
        case INSTR_PUBLISH:
            return publish_message(ctx, instr);
        case INSTR_SUBSCRIBE:
            if (subscribe_topic(ctx, instr->data.subscribe.topic) != 0)
                return -1;
            break;
        case INSTR_SET_TOPIC_VALIDATION_DELAY:
        {
            topic_state_t *state = find_topic_state(ctx, instr->data.validation_delay.topic, true);
            if (!state)
                return -1;
            pthread_mutex_lock(&state->lock);
            state->validation_delay_seconds = instr->data.validation_delay.delay_seconds;
            pthread_mutex_unlock(&state->lock);
            break;
        }
        case INSTR_INIT_GOSSIPSUB:
            /* Handled prior to execution loop */
            break;
    }
    return 0;
}

static int execute_script(context_t *ctx, const script_t *script)
{
    for (size_t i = 0; i < script->count; ++i)
    {
        const instruction_t *instr = &script->items[i];
        if (instr->type == INSTR_INIT_GOSSIPSUB)
            continue;
        if (execute_instruction(ctx, instr) != 0)
            return -1;
    }
    return 0;
}

static int init_gossipsub(context_t *ctx, const gossipsub_params_t *params)
{
    libp2p_gossipsub_config_t cfg;
    if (libp2p_gossipsub_config_default(&cfg) != LIBP2P_ERR_OK)
        return -1;
    if (params)
        (void)apply_gossipsub_params(params, &cfg);
    libp2p_gossipsub_t *gs = NULL;
    if (libp2p_gossipsub_new(ctx->host, &cfg, &gs) != LIBP2P_ERR_OK || !gs)
        return -1;
    if (libp2p_gossipsub_start(gs) != LIBP2P_ERR_OK)
    {
        libp2p_gossipsub_free(gs);
        return -1;
    }
    ctx->gs = gs;
    return 0;
}

static int run(const char *params_path)
{
    size_t json_len = 0;
    char *json = read_file(params_path, &json_len);
    if (!json)
    {
        fprintf(stderr, "Failed to read params file %s\n", params_path);
        return -1;
    }
    size_t token_capacity = 1024;
    jsmntok_t *tokens = NULL;
    int parsed = 0;
    for (;;)
    {
        tokens = (jsmntok_t *)realloc(tokens, token_capacity * sizeof(jsmntok_t));
        if (!tokens)
        {
            free(json);
            return -1;
        }
        jsmn_parser parser;
        jsmn_init(&parser);
        parsed = jsmn_parse(&parser, json, json_len, tokens, (unsigned int)token_capacity);
        if (parsed == JSMN_ERROR_NOMEM)
        {
            token_capacity *= 2;
            continue;
        }
        if (parsed < 0)
        {
            free(tokens);
            free(json);
            fprintf(stderr, "Failed to parse params JSON (%d)\n", parsed);
            return -1;
        }
        break;
    }
    json_doc_t doc = {
        .json = json,
        .tokens = tokens,
        .token_count = (size_t)parsed,
    };
    if (doc.token_count == 0 || doc.tokens[0].type != JSMN_OBJECT)
    {
        free(tokens);
        free(json);
        fprintf(stderr, "Params JSON root must be an object\n");
        return -1;
    }
    int script_index = json_object_get(&doc, 0, "script");
    if (script_index < 0)
    {
        free(tokens);
        free(json);
        fprintf(stderr, "Params JSON missing script\n");
        return -1;
    }
    script_t script;
    memset(&script, 0, sizeof(script));
    if (parse_script(&doc, script_index, &script) != 0)
    {
        free(tokens);
        free(json);
        fprintf(stderr, "Failed to parse script instructions\n");
        return -1;
    }

    int node_id = 0;
    if (get_hostname_node_id(&node_id) != 0)
    {
        free_script(&script);
        free(tokens);
        free(json);
        fprintf(stderr, "Unable to determine node ID from hostname\n");
        return -1;
    }

    context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.node_id = node_id;
    clock_gettime(CLOCK_MONOTONIC, &ctx.start_mono);

    libp2p_host_builder_t *builder = libp2p_host_builder_new();
    if (!builder)
    {
        free_script(&script);
        free(tokens);
        free(json);
        return -1;
    }
    (void)libp2p_host_builder_listen_addr(builder, "/ip4/0.0.0.0/tcp/9000");
    (void)libp2p_host_builder_transport(builder, "tcp");
    (void)libp2p_host_builder_security(builder, "noise");
    (void)libp2p_host_builder_muxer(builder, "yamux");
    (void)libp2p_host_builder_multistream(builder, 5000, true);
    (void)libp2p_host_builder_flags(builder, LIBP2P_HOST_F_AUTO_IDENTIFY_INBOUND | LIBP2P_HOST_F_AUTO_IDENTIFY_OUTBOUND);

    libp2p_host_t *host = NULL;
    if (libp2p_host_builder_build(builder, &host) != 0 || !host)
    {
        libp2p_host_builder_free(builder);
        free_script(&script);
        free(tokens);
        free(json);
        return -1;
    }
    libp2p_host_builder_free(builder);
    ctx.host = host;

    buffer_t priv_pb = {0};
    if (derive_node_identity(node_id, &priv_pb, ctx.peer_id_str) != 0)
    {
        buffer_free(&priv_pb);
        libp2p_host_free(host);
        free_script(&script);
        free(tokens);
        free(json);
        return -1;
    }
    if (libp2p_host_set_private_key(host, priv_pb.bytes, priv_pb.len) != 0)
    {
        buffer_free(&priv_pb);
        libp2p_host_free(host);
        free_script(&script);
        free(tokens);
        free(json);
        return -1;
    }
    buffer_free(&priv_pb);

    if (libp2p_host_start(host) != 0)
    {
        libp2p_host_free(host);
        free_script(&script);
        free(tokens);
        free(json);
        return -1;
    }

    gossipsub_params_t init_params;
    memset(&init_params, 0, sizeof(init_params));
    bool has_init = false;
    for (size_t i = 0; i < script.count; ++i)
    {
        if (script.items[i].type == INSTR_INIT_GOSSIPSUB)
        {
            init_params = script.items[i].data.init.params;
            has_init = true;
            break;
        }
    }
    if (init_gossipsub(&ctx, has_init ? &init_params : NULL) != 0)
    {
        libp2p_host_stop(host);
        libp2p_host_free(host);
        free_topic_states(ctx.topics);
        free_script(&script);
        free(tokens);
        free(json);
        return -1;
    }

    log_peer_id_event(&ctx, ctx.peer_id_str);

    int rc = execute_script(&ctx, &script);

    libp2p_gossipsub_stop(ctx.gs);
    libp2p_gossipsub_free(ctx.gs);
    libp2p_host_stop(host);
    libp2p_host_free(host);
    free_topic_states(ctx.topics);
    free_script(&script);
    free(tokens);
    free(json);
    return rc;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s --params <path>\n", prog);
}

int main(int argc, char **argv)
{
    const char *params_path = NULL;
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--params") == 0 && i + 1 < argc)
        {
            params_path = argv[++i];
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            usage(argv[0]);
            return EXIT_SUCCESS;
        }
        else
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }
    if (!params_path)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (run(params_path) != 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}
