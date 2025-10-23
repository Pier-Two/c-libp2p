#include "test_gossipsub_service_common.h"

int gossipsub_service_run_cleanup_tests(gossipsub_service_test_env_t *env)
{
    if (!env || !env->gs)
        return 0;

    libp2p_gossipsub_t *gs = env->gs;
    int failures = 0;

    if (env->async_handle)
    {
        libp2p_err_t err = libp2p_gossipsub_remove_validator(gs, env->async_handle);
        int ok = (err == LIBP2P_ERR_OK);
        print_result("gossipsub_remove_async_validator", ok);
        if (!ok)
            failures++;
        env->async_handle = NULL;
    }

    if (env->sync_handle)
    {
        libp2p_err_t err = libp2p_gossipsub_remove_validator(gs, env->sync_handle);
        int ok = (err == LIBP2P_ERR_OK);
        print_result("gossipsub_remove_sync_validator", ok);
        if (!ok)
            failures++;
        env->sync_handle = NULL;
    }

    libp2p_err_t err = libp2p_gossipsub_unsubscribe(gs, "test/topic");
    int ok = (err == LIBP2P_ERR_OK);
    print_result("gossipsub_unsubscribe", ok);
    if (!ok)
        failures++;

    return failures;
}
