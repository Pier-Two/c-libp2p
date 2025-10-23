#include "test_gossipsub_service_common.h"

int main(void)
{
    gossipsub_service_test_env_t env = { 0 };
    int failures = 0;

    failures += gossipsub_service_run_setup(&env);
    if (env.fatal_failure)
    {
        gossipsub_service_free_env(&env);
        return 1;
    }

    failures += gossipsub_service_run_subscription_mesh_tests(&env);
    failures += gossipsub_service_run_heartbeat_and_gossip_tests(&env);
    failures += gossipsub_service_run_px_and_opportunistic_tests(&env);
    failures += gossipsub_service_run_scoring_tests(&env);
    failures += gossipsub_service_run_explicit_peer_tests(&env);
    failures += gossipsub_service_run_cleanup_tests(&env);

    gossipsub_service_free_env(&env);
    return failures ? 1 : 0;
}
