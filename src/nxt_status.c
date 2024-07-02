
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_status.h>
#include <nxt_application.h>


nxt_inline const nxt_str_t *
nxt_status_app_type2name(nxt_app_type_t type)
{
#define nxt_str_sconst(s)                                                     \
    ({                                                                        \
        static const nxt_str_t _scstr = nxt_string(s);                        \
        &_scstr;                                                              \
     })

    switch (type) {
    case NXT_APP_EXTERNAL:
        return nxt_str_sconst("external");
    case NXT_APP_PYTHON:
        return nxt_str_sconst("python");
    case NXT_APP_PHP:
        return nxt_str_sconst("php");
    case NXT_APP_PERL:
        return nxt_str_sconst("perl");
    case NXT_APP_RUBY:
        return nxt_str_sconst("ruby");
    case NXT_APP_JAVA:
        return nxt_str_sconst("java");
    case NXT_APP_WASM:
        return nxt_str_sconst("wasm");
    case NXT_APP_WASM_WC:
        return nxt_str_sconst("wasm-wasi-component");
    case NXT_APP_UNKNOWN:
        return nxt_str_sconst("unknown");
    }

    /* Avoid 'warning: control reaches end of non-void function' */
    nxt_unreachable();

#undef nxt_str_sconst
}


nxt_conf_value_t *
nxt_status_get(nxt_task_t *task, nxt_status_report_t *report, nxt_mp_t *mp)
{
    size_t            i;
    uint32_t          idx = 0;
    nxt_str_t         name;
    nxt_int_t         ret;
    nxt_array_t       *langs;
    nxt_status_app_t  *app;
    nxt_conf_value_t  *status, *obj, *mods, *apps, *app_obj;

    static const nxt_str_t  modules_str = nxt_string("modules");
    static const nxt_str_t  version_str = nxt_string("version");
    static const nxt_str_t  lib_str = nxt_string("lib");
    static const nxt_str_t  conns_str = nxt_string("connections");
    static const nxt_str_t  acc_str = nxt_string("accepted");
    static const nxt_str_t  active_str = nxt_string("active");
    static const nxt_str_t  idle_str = nxt_string("idle");
    static const nxt_str_t  closed_str = nxt_string("closed");
    static const nxt_str_t  reqs_str = nxt_string("requests");
    static const nxt_str_t  total_str = nxt_string("total");
    static const nxt_str_t  apps_str = nxt_string("applications");
    static const nxt_str_t  procs_str = nxt_string("processes");
    static const nxt_str_t  run_str = nxt_string("running");
    static const nxt_str_t  start_str = nxt_string("starting");

    status = nxt_conf_create_object(mp, 4);
    if (nxt_slow_path(status == NULL)) {
        return NULL;
    }

    langs = task->thread->runtime->languages;

    /* Don't reserve space for NXT_APP_EXTERNAL */
    mods = nxt_conf_create_object(mp, langs->nelts - 1);
    if (nxt_slow_path(mods == NULL)) {
        return NULL;
    }

    nxt_conf_set_member(status, &modules_str, mods, idx++);

    i = 0;
    for (size_t l = 0; i < langs->nelts; i++) {
        nxt_str_t              item;
        const nxt_str_t        *mod_name;
        nxt_conf_value_t       *mod_obj;
        nxt_app_lang_module_t  *modules = langs->elts;

        if (modules[i].type == NXT_APP_EXTERNAL) {
            continue;
        }

        mod_obj = nxt_conf_create_object(mp, 2);
        if (nxt_slow_path(mod_obj == NULL)) {
            return NULL;
        }

        mod_name = nxt_status_app_type2name(modules[i].type);

        nxt_conf_set_member(mods, mod_name, mod_obj, l++);

        item.start = modules[i].version;
        item.length = nxt_strlen(modules[i].version);
        nxt_conf_set_member_string(mod_obj, &version_str, &item, 0);

        item.start = (u_char *) modules[i].file;
        item.length = strlen(modules[i].file);
        nxt_conf_set_member_string(mod_obj, &lib_str, &item, 1);
    }

    obj = nxt_conf_create_object(mp, 4);
    if (nxt_slow_path(obj == NULL)) {
        return NULL;
    }

    nxt_conf_set_member(status, &conns_str, obj, idx++);

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

    nxt_conf_set_member(status, &reqs_str, obj, idx++);

    nxt_conf_set_member_integer(obj, &total_str, report->requests, 0);

    apps = nxt_conf_create_object(mp, report->apps_count);
    if (nxt_slow_path(apps == NULL)) {
        return NULL;
    }

    nxt_conf_set_member(status, &apps_str, apps, idx++);

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
