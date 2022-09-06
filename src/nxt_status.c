
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_status.h>


nxt_conf_value_t *
nxt_status_get(nxt_status_report_t *report, nxt_mp_t *mp)
{
    size_t            i;
    nxt_str_t         name;
    nxt_int_t         ret;
    nxt_status_app_t  *app;
    nxt_conf_value_t  *status, *obj, *apps, *app_obj;

    static nxt_str_t conns_str = nxt_string("connections");
    static nxt_str_t acc_str = nxt_string("accepted");
    static nxt_str_t active_str = nxt_string("active");
    static nxt_str_t idle_str = nxt_string("idle");
    static nxt_str_t closed_str = nxt_string("closed");
    static nxt_str_t reqs_str = nxt_string("requests");
    static nxt_str_t total_str = nxt_string("total");
    static nxt_str_t apps_str = nxt_string("applications");
    static nxt_str_t procs_str = nxt_string("processes");
    static nxt_str_t run_str = nxt_string("running");
    static nxt_str_t start_str = nxt_string("starting");

    status = nxt_conf_create_object(mp, 3);
    if (nxt_slow_path(status == NULL)) {
        return NULL;
    }

    obj = nxt_conf_create_object(mp, 4);
    if (nxt_slow_path(obj == NULL)) {
        return NULL;
    }

    nxt_conf_set_member(status, &conns_str, obj, 0);

    nxt_conf_set_member_integer(obj, &acc_str, report->accepted_conns, 0);
    nxt_conf_set_member_integer(obj, &active_str, report->accepted_conns
                                                  - report->closed_conns
                                                  - report->idle_conns, 1);
    nxt_conf_set_member_integer(obj, &idle_str, report->idle_conns, 2);
    nxt_conf_set_member_integer(obj, &closed_str, report->closed_conns, 3);

    obj = nxt_conf_create_object(mp, 1);
    if (nxt_slow_path(obj == NULL)) {
        return NULL;
    }

    nxt_conf_set_member(status, &reqs_str, obj, 1);

    nxt_conf_set_member_integer(obj, &total_str, report->requests, 0);

    apps = nxt_conf_create_object(mp, report->apps_count);
    if (nxt_slow_path(apps == NULL)) {
        return NULL;
    }

    nxt_conf_set_member(status, &apps_str, apps, 2);

    for (i = 0; i < report->apps_count; i++) {
        app = &report->apps[i];

        app_obj = nxt_conf_create_object(mp, 2);
        if (nxt_slow_path(app_obj == NULL)) {
            return NULL;
        }

        name.length = app->name.length;
        name.start = nxt_pointer_to(report, (uintptr_t) app->name.start);

        ret = nxt_conf_set_member_dup(apps, mp, &name, app_obj, i);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NULL;
        }

        obj = nxt_conf_create_object(mp, 3);
        if (nxt_slow_path(obj == NULL)) {
            return NULL;
        }

        nxt_conf_set_member(app_obj, &procs_str, obj, 0);

        nxt_conf_set_member_integer(obj, &run_str, app->processes, 0);
        nxt_conf_set_member_integer(obj, &start_str, app->pending_processes, 1);
        nxt_conf_set_member_integer(obj, &idle_str, app->idle_processes, 2);

        obj = nxt_conf_create_object(mp, 1);
        if (nxt_slow_path(obj == NULL)) {
            return NULL;
        }

        nxt_conf_set_member(app_obj, &reqs_str, obj, 1);

        nxt_conf_set_member_integer(obj, &active_str, app->active_requests, 0);
    }

    return status;
}
