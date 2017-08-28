
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_application.h>


static nxt_int_t nxt_go_init(nxt_task_t *task, nxt_common_app_conf_t *conf);

static nxt_int_t nxt_go_run(nxt_task_t *task,
                      nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *msg);

nxt_application_module_t  nxt_go_module = {
    nxt_string("go"),
    nxt_string("go"),
    nxt_go_init,
    nxt_go_run,
};


extern char  **environ;

nxt_inline int
nxt_sock_no_cloexec(nxt_socket_t fd)
{
    if (fd == -1) {
        return 0;
    }
    return fcntl(fd, F_SETFD, 0);
}


static nxt_int_t
nxt_go_init(nxt_task_t *task, nxt_common_app_conf_t *conf)
{
    char               *go_path;
    char               *argv[2];
    u_char             buf[256];
    u_char             *p;
    u_char             stream_buf[32];
    nxt_port_t         *port;
    nxt_runtime_t      *rt;
    nxt_go_app_conf_t  *c;

    c = &conf->u.go;
    rt = task->thread->runtime;
    p = buf;

    nxt_runtime_port_each(rt, port) {

        if (port->pid != nxt_pid && port->type != NXT_PROCESS_MAIN) {
            continue;
        }

        if (port->pid == nxt_pid) {
            nxt_sprintf(stream_buf, stream_buf + sizeof(stream_buf),
                        "%uD", port->process->init->stream);

            setenv("NXT_GO_STREAM", (char *)stream_buf, 1);
        }

        nxt_debug(task, "port %PI, %ud, (%d, %d)", port->pid, port->id,
                  port->pair[0], port->pair[1]);

        p = nxt_sprintf(p, buf + sizeof(buf), "%PI,%ud,%d,%d,%d;",
                        port->pid, port->id, (int)port->type,
                        port->pair[0], port->pair[1]);

        if (nxt_slow_path(nxt_sock_no_cloexec(port->pair[0]))) {
            nxt_log(task, NXT_LOG_WARN, "fcntl() failed %E", nxt_errno);
        }

        if (nxt_slow_path(nxt_sock_no_cloexec(port->pair[1]))) {
            nxt_log(task, NXT_LOG_WARN, "fcntl() failed %E", nxt_errno);
        }

    } nxt_runtime_port_loop;

    *p = '\0';
    nxt_debug(task, "update NXT_GO_PORTS=%s", buf);

    setenv("NXT_GO_PORTS", (char *)buf, 1);

    go_path = malloc(c->executable.length + 1);
    nxt_memcpy(go_path, c->executable.start, c->executable.length);
    go_path[c->executable.length] = '\0';

    argv[0] = go_path;
    argv[1] = NULL;

    (void) execve(go_path, argv, environ);

    nxt_log(task, NXT_LOG_WARN, "execve(%s) failed %E", go_path, nxt_errno);

    return NXT_ERROR;
}


static nxt_int_t
nxt_go_run(nxt_task_t *task,
           nxt_app_rmsg_t *rmsg, nxt_app_wmsg_t *msg)
{
    return NXT_ERROR;
}
