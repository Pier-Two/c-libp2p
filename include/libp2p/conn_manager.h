#ifndef LIBP2P_CONN_MANAGER_H
#define LIBP2P_CONN_MANAGER_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct libp2p_conn_mgr libp2p_conn_mgr_t;

/* Sketch API; implementation optional */
int libp2p_conn_mgr_new(int low_water, int high_water, int grace_ms, libp2p_conn_mgr_t **out);
void libp2p_conn_mgr_free(libp2p_conn_mgr_t *cm);

/* Accessors for host integration */
int libp2p_conn_mgr_get_params(const libp2p_conn_mgr_t *cm, int *low_water, int *high_water, int *grace_ms);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_CONN_MANAGER_H */
