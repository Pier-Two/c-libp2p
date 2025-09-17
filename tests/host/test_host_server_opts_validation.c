/* Tests for server option overrides struct_size validation and unlisten cleanup. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libp2p/host.h"
#include "libp2p/protocol_listen.h"
#include "libp2p/protocol.h"

/* Access host internals to inspect proto_cfgs for testing */
#include "src/host/host_internal.h"

static void print_case(const char *name, int ok)
{
    printf("TEST: %-60s | %s\n", name, ok ? "PASS" : "FAIL");
}

static void dummy_on_open(libp2p_stream_t *s, void *ud)
{
    (void)s; (void)ud;
}

int main(void)
{
    int failures = 0;

    libp2p_host_options_t o; libp2p_host_options_default(&o);
    libp2p_host_t *host = NULL;
    if (libp2p_host_new(&o, &host) != 0 || !host)
        return 1;

    /* ----- Partial overrides: invalid struct_size should be rejected ----- */
    {
        const char *pid = "/opts-test/1.0.0";
        libp2p_protocol_def_t def = {
            .protocol_id = pid,
            .read_mode = LIBP2P_READ_PULL,
            .on_open = dummy_on_open
        };
        libp2p_proto_listener_t lst = {
            .kind = LIBP2P_PROTO_LISTEN_EXACT,
            .exact_id = pid,
            .id_list = NULL,
            .id_list_len = 0,
            .prefix = NULL,
            .base_path = NULL,
            .semver_range = NULL,
        };
        libp2p_protocol_server_opts_t opts = {0};
        opts.struct_size = sizeof(libp2p_protocol_server_opts_t) - 1; /* partial */
        opts.read_mode = LIBP2P_READ_PULL;
        opts.handshake_timeout_ms = 1234;

        libp2p_protocol_server_t *srv = NULL;
        int rc = libp2p_host_listen_selected(host, &lst, &def, &opts, &srv);
        int ok = (rc == LIBP2P_ERR_UNSUPPORTED) && (srv == NULL);
        print_case("reject partial server opts (strict struct_size)", ok);
        failures += ok ? 0 : 1;
    }

    /* Ensure no proto_cfgs leaked from previous attempt */
    if (host->proto_cfgs != NULL) {
        print_case("no proto_cfgs after rejected partial opts", 0);
        libp2p_host_free(host);
        return 1;
    } else {
        print_case("no proto_cfgs after rejected partial opts", 1);
    }

    /* ----- Exact registration: set + remove per-protocol overrides ----- */
    {
        const char *pid = "/opts-test/2.0.0";
        libp2p_protocol_def_t def = {
            .protocol_id = pid,
            .read_mode = LIBP2P_READ_PULL,
            .on_open = dummy_on_open
        };
        libp2p_proto_listener_t lst = {
            .kind = LIBP2P_PROTO_LISTEN_EXACT,
            .exact_id = pid,
            .id_list = NULL,
            .id_list_len = 0,
            .prefix = NULL,
            .base_path = NULL,
            .semver_range = NULL,
        };
        libp2p_protocol_server_opts_t opts = {0};
        opts.struct_size = sizeof(opts);
        opts.read_mode = LIBP2P_READ_PUSH;
        opts.handshake_timeout_ms = 2222;
        opts.require_identified_peer = true;

        libp2p_protocol_server_t *srv = NULL;
        int rc = libp2p_host_listen_selected(host, &lst, &def, &opts, &srv);
        int ok1 = (rc == 0 && srv != NULL);
        print_case("exact listen with full opts accepted", ok1);
        failures += ok1 ? 0 : 1;

        /* Check proto_cfgs contains our protocol */
        int found = 0;
        for (proto_server_cfg_t *pc = host->proto_cfgs; pc; pc = pc->next)
            if (pc->proto && strcmp(pc->proto, pid) == 0)
                { found = 1; break; }
        print_case("per-protocol cfg inserted for exact id", found);
        failures += found ? 0 : 1;

        /* Unlisten should remove overrides */
        if (srv)
            libp2p_host_unlisten(host, srv);

        int still_present = 0;
        for (proto_server_cfg_t *pc = host->proto_cfgs; pc; pc = pc->next)
            if (pc->proto && strcmp(pc->proto, pid) == 0)
                { still_present = 1; break; }
        print_case("unlisten removes per-protocol cfg for exact", !still_present);
        failures += (!still_present) ? 0 : 1;
    }

    /* ----- Matcher registration: ensure no per-protocol overrides leak ----- */
    {
        const char *prefix = "/matcher-x/";
        libp2p_protocol_def_t def = {
            .protocol_id = NULL, /* ignored for matchers */
            .read_mode = LIBP2P_READ_PULL,
            .on_open = dummy_on_open
        };
        libp2p_proto_listener_t lst = {
            .kind = LIBP2P_PROTO_LISTEN_PREFIX,
            .exact_id = NULL,
            .id_list = NULL,
            .id_list_len = 0,
            .prefix = prefix,
            .base_path = NULL,
            .semver_range = NULL,
        };
        libp2p_protocol_server_opts_t opts = {0};
        opts.struct_size = sizeof(opts);
        opts.read_mode = LIBP2P_READ_PUSH;
        opts.handshake_timeout_ms = 3333;
        opts.require_identified_peer = true;

        libp2p_protocol_server_t *srv = NULL;
        int rc = libp2p_host_listen_selected(host, &lst, &def, &opts, &srv);
        int ok1 = (rc == 0 && srv != NULL);
        print_case("prefix matcher listen accepted", ok1);
        failures += ok1 ? 0 : 1;

        /* Matchers should not create per-protocol cfg entries */
        int any_cfg = (host->proto_cfgs != NULL);
        print_case("no per-protocol cfg created by matcher", !any_cfg);
        failures += (!any_cfg) ? 0 : 1;

        if (srv)
            libp2p_host_unlisten(host, srv);

        /* And none should appear after unlisten */
        any_cfg = (host->proto_cfgs != NULL);
        print_case("no per-protocol cfg after matcher unlisten", !any_cfg);
        failures += (!any_cfg) ? 0 : 1;
    }

    libp2p_host_free(host);
    return failures ? 1 : 0;
}

