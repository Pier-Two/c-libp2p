#include "libp2p/error_map.h"

libp2p_err_t libp2p_error_from_transport(libp2p_transport_err_t e)
{
    switch (e)
    {
        case LIBP2P_TRANSPORT_OK:
            return LIBP2P_ERR_OK;
        case LIBP2P_TRANSPORT_ERR_NULL_PTR:
            return LIBP2P_ERR_NULL_PTR;
        case LIBP2P_TRANSPORT_ERR_UNSUPPORTED:
            return LIBP2P_ERR_UNSUPPORTED;
        case LIBP2P_TRANSPORT_ERR_DIAL_FAIL:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_TRANSPORT_ERR_LISTEN_FAIL:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_TRANSPORT_ERR_CLOSED:
            return LIBP2P_ERR_CLOSED;
        case LIBP2P_TRANSPORT_ERR_INTERNAL:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_TRANSPORT_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_TRANSPORT_ERR_SOCKOPT_OPT_NOT_SUPPORTED:
            return LIBP2P_ERR_UNSUPPORTED;
        case LIBP2P_TRANSPORT_ERR_SOCKOPT_PERMISSION:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_TRANSPORT_ERR_SOCKOPT_INVALID_ARG:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_TRANSPORT_ERR_SOCKOPT_NO_RESOURCES:
            return LIBP2P_ERR_AGAIN;
        case LIBP2P_TRANSPORT_ERR_SOCKOPT_OTHER_FAIL:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_TRANSPORT_ERR_INVALID_ARG:
            return LIBP2P_ERR_INTERNAL;
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

libp2p_err_t libp2p_error_from_listener(libp2p_listener_err_t e)
{
    switch (e)
    {
        case LIBP2P_LISTENER_OK:
            return LIBP2P_ERR_OK;
        case LIBP2P_LISTENER_ERR_NULL_PTR:
            return LIBP2P_ERR_NULL_PTR;
        case LIBP2P_LISTENER_ERR_AGAIN:
            return LIBP2P_ERR_AGAIN;
        case LIBP2P_LISTENER_ERR_CLOSED:
            return LIBP2P_ERR_CLOSED;
        case LIBP2P_LISTENER_ERR_INTERNAL:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_LISTENER_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_LISTENER_ERR_BACKOFF:
            return LIBP2P_ERR_AGAIN;
        case LIBP2P_LISTENER_ERR_MUTEX:
            return LIBP2P_ERR_INTERNAL;
        case LIBP2P_LISTENER_ERR_OVERFLOW:
            return LIBP2P_ERR_INTERNAL;
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

libp2p_err_t libp2p_error_from_upgrader(libp2p_upgrader_err_t e)
{
    switch (e)
    {
        case LIBP2P_UPGRADER_OK:
            return LIBP2P_ERR_OK;
        case LIBP2P_UPGRADER_ERR_NULL_PTR:
            return LIBP2P_ERR_NULL_PTR;
        case LIBP2P_UPGRADER_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_UPGRADER_ERR_SECURITY:
            return LIBP2P_ERR_PROTO_NEGOTIATION_FAILED;
        case LIBP2P_UPGRADER_ERR_MUXER:
            return LIBP2P_ERR_PROTO_NEGOTIATION_FAILED;
        case LIBP2P_UPGRADER_ERR_HANDSHAKE:
            return LIBP2P_ERR_PROTO_NEGOTIATION_FAILED;
        case LIBP2P_UPGRADER_ERR_INTERNAL:
            return LIBP2P_ERR_INTERNAL;
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}

libp2p_err_t libp2p_error_from_multiselect(libp2p_multiselect_err_t e)
{
    switch (e)
    {
        case LIBP2P_MULTISELECT_OK:
            return LIBP2P_ERR_OK;
        case LIBP2P_MULTISELECT_ERR_TIMEOUT:
            return LIBP2P_ERR_TIMEOUT;
        case LIBP2P_MULTISELECT_ERR_UNAVAIL:
            return LIBP2P_ERR_PROTO_NEGOTIATION_FAILED;
        case LIBP2P_MULTISELECT_ERR_NULL_PTR:
            return LIBP2P_ERR_NULL_PTR;
        case LIBP2P_MULTISELECT_ERR_PROTO_MAL:
        case LIBP2P_MULTISELECT_ERR_IO:
        case LIBP2P_MULTISELECT_ERR_INTERNAL:
        default:
            return LIBP2P_ERR_INTERNAL;
    }
}
