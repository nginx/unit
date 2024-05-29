
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_router.h>
#include <nxt_unit.h>


static nxt_int_t nxt_external_start(nxt_task_t *task, nxt_process_data_t *data);


nxt_app_module_t  nxt_external_module = {
    0,
    NULL,
    nxt_string("external"),
    "*",
    NULL,
    0,
    NULL,
    nxt_external_start,
};


extern char  **environ;


nxt_inline nxt_int_t
nxt_external_fd_no_cloexec(nxt_task_t *task, nxt_socket_t fd)
{
    int  res, flags;

    if (fd == -1) {
        return NXT_OK;
    }

    flags = fcntl(fd, F_GETFD);

    if (nxt_slow_path(flags == -1)) {
        nxt_alert(task, "fcntl(%d, F_GETFD) failed %E", fd, nxt_errno);
        return NXT_ERROR;
    }

    flags &= ~FD_CLOEXEC;

    res = fcntl(fd, F_SETFD, flags);

    if (nxt_slow_path(res == -1)) {
        nxt_alert(task, "fcntl(%d, F_SETFD) failed %E", fd, nxt_errno);
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
nxt_external_start(nxt_task_t *task, nxt_process_data_t *data)
{
    char                     **argv;
    u_char                   buf[256];
    u_char                   *p, *end;
    uint32_t                 index;
    size_t                   size;
    nxt_str_t                str;
    nxt_int_t                rc;
    nxt_uint_t               i, argc;
    nxt_port_t               *my_port, *proto_port, *router_port;
    nxt_runtime_t            *rt;
    nxt_conf_value_t         *value;
    nxt_common_app_conf_t    *conf;
    nxt_external_app_conf_t  *c;

    rt = task->thread->runtime;
    conf = data->app;

    proto_port = rt->port_by_type[NXT_PROCESS_PROTOTYPE];
    router_port = rt->port_by_type[NXT_PROCESS_ROUTER];
    my_port = nxt_runtime_port_find(rt, nxt_pid, 0);

    if (nxt_slow_path(proto_port == NULL || my_port == NULL
                      || router_port == NULL))
    {
        return NXT_ERROR;
    }

    rc = nxt_external_fd_no_cloexec(task, proto_port->pair[1]);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_external_fd_no_cloexec(task, router_port->pair[1]);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_external_fd_no_cloexec(task, my_port->pair[0]);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_external_fd_no_cloexec(task, my_port->pair[1]);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_external_fd_no_cloexec(task, conf->shared_port_fd);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    rc = nxt_external_fd_no_cloexec(task, conf->shared_queue_fd);
    if (nxt_slow_path(rc != NXT_OK)) {
        return NXT_ERROR;
    }

    end = buf + sizeof(buf);

    p = nxt_sprintf(buf, end,
                    "%s;%uD;"
                    "%PI,%ud,%d;"
                    "%PI,%ud,%d;"
                    "%PI,%ud,%d,%d;"
                    "%d,%d;"
                    "%d,%z,%uD,%Z",
                    NXT_VERSION, my_port->process->stream,
                    proto_port->pid, proto_port->id, proto_port->pair[1],
                    router_port->pid, router_port->id, router_port->pair[1],
                    my_port->pid, my_port->id, my_port->pair[0],
                                               my_port->pair[1],
                    conf->shared_port_fd, conf->shared_queue_fd,
                    2, conf->shm_limit, conf->request_limit);

    if (nxt_slow_path(p == end)) {
        nxt_alert(task, "internal error: buffer too small for NXT_UNIT_INIT");

        return NXT_ERROR;
    }

    nxt_debug(task, "update "NXT_UNIT_INIT_ENV"=%s", buf);

    rc = setenv(NXT_UNIT_INIT_ENV, (char *) buf, 1);
    if (nxt_slow_path(rc == -1)) {
        nxt_alert(task, "setenv("NXT_UNIT_INIT_ENV", %s) failed %E", buf,
                  nxt_errno);

        return NXT_ERROR;
    }

    c = &conf->u.external;

    argc = 2;
    size = 0;

    if (c->arguments != NULL) {

        for (index = 0; /* void */ ; index++) {
            value = nxt_conf_get_array_element(c->arguments, index);
            if (value == NULL) {
                break;
            }

            nxt_conf_get_string(value, &str);

            size += str.length + 1;
            argc++;
        }
    }

    argv = nxt_malloc(argc * sizeof(argv[0]) + size);
    if (nxt_slow_path(argv == NULL)) {
        nxt_alert(task, "failed to allocate arguments");
        return NXT_ERROR;
    }

    argv[0] = c->executable;
    i = 1;

    if (c->arguments != NULL) {
        p = (u_char *) &argv[argc];

        for (index = 0; /* void */ ; index++) {
            value = nxt_conf_get_array_element(c->arguments, index);
            if (value == NULL) {
                break;
            }

            argv[i++] = (char *) p;

            nxt_conf_get_string(value, &str);

            p = nxt_cpymem(p, str.start, str.length);
            *p++ = '\0';
        }
    }

    argv[i] = NULL;

    (void) execve(c->executable, argv, environ);

    nxt_alert(task, "execve(%s) failed %E", c->executable, nxt_errno);

    nxt_free(argv);

    return NXT_ERROR;
}
