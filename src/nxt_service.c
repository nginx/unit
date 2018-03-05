
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


static const nxt_service_t  nxt_services[] = {

#if (NXT_HAVE_KQUEUE)
    { "engine", "kqueue", &nxt_kqueue_engine },
#endif

#if (NXT_HAVE_EPOLL_EDGE)
    { "engine", "epoll", &nxt_epoll_edge_engine },
    { "engine", "epoll_edge", &nxt_epoll_edge_engine },
    { "engine", "epoll_level", &nxt_epoll_level_engine },

#elif (NXT_HAVE_EPOLL)
    { "engine", "epoll", &nxt_epoll_level_engine },
    { "engine", "epoll_level", &nxt_epoll_level_engine },
#endif

#if (NXT_HAVE_EVENTPORT)
    { "engine", "eventport", &nxt_eventport_engine },
#endif

#if (NXT_HAVE_DEVPOLL)
    { "engine", "devpoll", &nxt_devpoll_engine },
    { "engine", "/dev/poll", &nxt_devpoll_engine },
#endif

#if (NXT_HAVE_POLLSET)
    { "engine", "pollset", &nxt_pollset_engine },
#endif

    { "engine", "poll", &nxt_poll_engine },
    { "engine", "select", &nxt_select_engine },

#if (NXT_HAVE_OPENSSL)
    { "SSL/TLS", "OpenSSL", &nxt_openssl_lib },
    { "SSL/TLS", "openssl", &nxt_openssl_lib },
#endif

#if (NXT_HAVE_GNUTLS)
    { "SSL/TLS", "GnuTLS", &nxt_gnutls_lib },
    { "SSL/TLS", "gnutls", &nxt_gnutls_lib },
#endif

#if (NXT_HAVE_CYASSL)
    { "SSL/TLS", "CyaSSL", &nxt_cyassl_lib },
    { "SSL/TLS", "cyassl", &nxt_cyassl_lib },
#endif

};


nxt_array_t *
nxt_services_init(nxt_mp_t *mp)
{
    nxt_uint_t           n;
    nxt_array_t          *services;
    nxt_service_t        *s;
    const nxt_service_t  *service;

    services = nxt_array_create(mp, 32, sizeof(nxt_service_t));

    if (nxt_fast_path(services != NULL)) {

        service = nxt_services;
        n = nxt_nitems(nxt_services);

        while (n != 0) {
            s = nxt_array_add(services);
            if (nxt_slow_path(s == NULL)) {
                return NULL;
            }

            *s = *service;

            service++;
            n--;
        }
    }

    return services;
}


nxt_int_t
nxt_service_add(nxt_array_t *services, const nxt_service_t *service)
{
    nxt_uint_t     n;
    nxt_service_t  *s;

    s = services->elts;
    n = services->nelts;

    while (n != 0) {
        if (nxt_strcmp(s->type, service->type) != 0) {
            goto next;
        }

        if (nxt_strcmp(s->name, service->name) != 0) {
            goto next;
        }

        nxt_thread_log_alert("service \"%s:%s\" is duplicate",
                             service->type, service->name);
        return NXT_ERROR;

    next:

        s++;
        n--;
    }

    s = nxt_array_add(services);
    if (nxt_fast_path(s != NULL)) {
        *s = *service;
        return NXT_OK;
    }

    return NXT_ERROR;
}


const void *
nxt_service_get(nxt_array_t *services, const char *type, const char *name)
{
    nxt_uint_t           n;
    const nxt_service_t  *s;

    if (services != NULL) {
        s = services->elts;
        n = services->nelts;

    } else {
        s = nxt_services;
        n = nxt_nitems(nxt_services);
    }

    while (n != 0) {
        if (nxt_strcmp(s->type, type) == 0) {

            if (name == NULL) {
                return s->service;
            }

            if (nxt_strcmp(s->name, name) == 0) {
                return s->service;
            }
        }

        s++;
        n--;
    }

    nxt_thread_log_alert("service \"%s%s%s\" not found",
                         type, (name != NULL) ? ":" : "", name);

    return NULL;
}
