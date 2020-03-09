
/*
 * Copyright (C) Max Romanov
 * Copyright (C) Igor Sysoev
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>
#include <nxt_runtime.h>
#include <nxt_main_process.h>
#include <nxt_router.h>
#include <nxt_http.h>
#include <nxt_application.h>
#include <nxt_unit.h>
#include <nxt_port_memory_int.h>

#include <glob.h>


typedef struct {
    nxt_app_type_t  type;
    nxt_str_t       version;
    nxt_str_t       file;
} nxt_module_t;


static nxt_int_t nxt_discovery_start(nxt_task_t *task,
    nxt_process_data_t *data);
static nxt_buf_t *nxt_discovery_modules(nxt_task_t *task, const char *path);
static nxt_int_t nxt_discovery_module(nxt_task_t *task, nxt_mp_t *mp,
    nxt_array_t *modules, const char *name);
static void nxt_discovery_completion_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_discovery_quit(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data);
static nxt_app_module_t *nxt_app_module_load(nxt_task_t *task,
    const char *name);
static nxt_int_t nxt_app_prefork(nxt_task_t *task, nxt_process_t *process,
    nxt_mp_t *mp);
static nxt_int_t nxt_app_setup(nxt_task_t *task, nxt_process_t *process);
static nxt_int_t nxt_app_set_environment(nxt_conf_value_t *environment);
static nxt_int_t nxt_app_isolation(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);

#if (NXT_HAVE_CLONE)
static nxt_int_t nxt_app_clone_flags(nxt_task_t *task,
    nxt_conf_value_t *namespaces, nxt_clone_t *clone);
#endif

#if (NXT_HAVE_CLONE_NEWUSER)
static nxt_int_t nxt_app_isolation_creds(nxt_task_t *task,
    nxt_conf_value_t *isolation, nxt_process_t *process);
static nxt_int_t nxt_app_isolation_credential_map(nxt_task_t *task,
    nxt_mp_t *mem_pool, nxt_conf_value_t *map_array,
    nxt_clone_credential_map_t *map);
#endif

nxt_str_t  nxt_server = nxt_string(NXT_SERVER);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


static nxt_app_module_t  *nxt_app;


static const nxt_port_handlers_t  nxt_discovery_process_port_handlers = {
    .quit         = nxt_signal_quit_handler,
    .new_port     = nxt_port_new_port_handler,
    .change_file  = nxt_port_change_log_file_handler,
    .mmap         = nxt_port_mmap_handler,
    .data         = nxt_port_data_handler,
    .remove_pid   = nxt_port_remove_pid_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
};


static const nxt_port_handlers_t  nxt_app_process_port_handlers = {
    .quit         = nxt_signal_quit_handler,
    .rpc_ready    = nxt_port_rpc_handler,
    .rpc_error    = nxt_port_rpc_handler,
};


const nxt_process_init_t  nxt_discovery_process = {
    .name           = "discovery",
    .type           = NXT_PROCESS_DISCOVERY,
    .prefork        = NULL,
    .restart        = 0,
    .setup          = nxt_process_core_setup,
    .start          = nxt_discovery_start,
    .port_handlers  = &nxt_discovery_process_port_handlers,
    .signals        = nxt_process_signals,
};


const nxt_process_init_t  nxt_app_process = {
    .type           = NXT_PROCESS_APP,
    .setup          = nxt_app_setup,
    .prefork        = nxt_app_prefork,
    .restart        = 0,
    .start          = NULL,     /* set to module->start */
    .port_handlers  = &nxt_app_process_port_handlers,
    .signals        = nxt_process_signals,
};


static nxt_int_t
nxt_discovery_start(nxt_task_t *task, nxt_process_data_t *data)
{
    uint32_t       stream;
    nxt_buf_t      *b;
    nxt_int_t      ret;
    nxt_port_t     *main_port, *discovery_port;
    nxt_runtime_t  *rt;

    nxt_log(task, NXT_LOG_INFO, "discovery started");

    rt = task->thread->runtime;

    b = nxt_discovery_modules(task, rt->modules);
    if (nxt_slow_path(b == NULL)) {
        return NXT_ERROR;
    }

    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    discovery_port = rt->port_by_type[NXT_PROCESS_DISCOVERY];

    stream = nxt_port_rpc_register_handler(task, discovery_port,
                                           nxt_discovery_quit,
                                           nxt_discovery_quit,
                                           main_port->pid, NULL);

    if (nxt_slow_path(stream == 0)) {
        return NXT_ERROR;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_MODULES, -1,
                                stream, discovery_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, discovery_port, stream);
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_buf_t *
nxt_discovery_modules(nxt_task_t *task, const char *path)
{
    char          *name;
    u_char        *p, *end;
    size_t        size;
    glob_t        glb;
    nxt_mp_t      *mp;
    nxt_buf_t     *b;
    nxt_int_t     ret;
    nxt_uint_t    i, n;
    nxt_array_t   *modules;
    nxt_module_t  *module;

    b = NULL;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (mp == NULL) {
        return b;
    }

    ret = glob(path, 0, NULL, &glb);

    n = glb.gl_pathc;

    if (ret != 0) {
        nxt_log(task, NXT_LOG_NOTICE,
                "no modules matching: \"%s\" found", path);
        n = 0;
    }

    modules = nxt_array_create(mp, n, sizeof(nxt_module_t));
    if (modules == NULL) {
        goto fail;
    }

    for (i = 0; i < n; i++) {
        name = glb.gl_pathv[i];

        ret = nxt_discovery_module(task, mp, modules, name);
        if (ret != NXT_OK) {
            goto fail;
        }
    }

    size = nxt_length("[]");
    module = modules->elts;
    n = modules->nelts;

    for (i = 0; i < n; i++) {
        nxt_debug(task, "module: %d %V %V",
                  module[i].type, &module[i].version, &module[i].file);

        size += nxt_length("{\"type\": ,");
        size += nxt_length(" \"version\": \"\",");
        size += nxt_length(" \"file\": \"\"},");

        size += NXT_INT_T_LEN
                + module[i].version.length
                + module[i].file.length;
    }

    b = nxt_buf_mem_alloc(mp, size, 0);
    if (b == NULL) {
        goto fail;
    }

    b->completion_handler = nxt_discovery_completion_handler;

    p = b->mem.free;
    end = b->mem.end;
    *p++ = '[';

    for (i = 0; i < n; i++) {
        p = nxt_sprintf(p, end,
                      "{\"type\": %d, \"version\": \"%V\", \"file\": \"%V\"},",
                      module[i].type, &module[i].version, &module[i].file);
    }

    *p++ = ']';
    b->mem.free = p;

fail:

    globfree(&glb);

    return b;
}


static nxt_int_t
nxt_discovery_module(nxt_task_t *task, nxt_mp_t *mp, nxt_array_t *modules,
    const char *name)
{
    void              *dl;
    nxt_str_t         version;
    nxt_int_t         ret;
    nxt_uint_t        i, n;
    nxt_module_t      *module;
    nxt_app_type_t    type;
    nxt_app_module_t  *app;

    /*
     * Only memory allocation failure should return NXT_ERROR.
     * Any module processing errors are ignored.
     */
    ret = NXT_ERROR;

    dl = dlopen(name, RTLD_GLOBAL | RTLD_NOW);

    if (dl == NULL) {
        nxt_alert(task, "dlopen(\"%s\"), failed: \"%s\"", name, dlerror());
        return NXT_OK;
    }

    app = dlsym(dl, "nxt_app_module");

    if (app != NULL) {
        nxt_log(task, NXT_LOG_NOTICE, "module: %V %s \"%s\"",
                &app->type, app->version, name);

        if (app->compat_length != sizeof(compat)
            || nxt_memcmp(app->compat, compat, sizeof(compat)) != 0)
        {
            nxt_log(task, NXT_LOG_NOTICE, "incompatible module %s", name);

            goto done;
        }

        type = nxt_app_parse_type(app->type.start, app->type.length);

        if (type == NXT_APP_UNKNOWN) {
            nxt_log(task, NXT_LOG_NOTICE, "unknown module type %V", &app->type);

            goto done;
        }

        module = modules->elts;
        n = modules->nelts;

        version.start = (u_char *) app->version;
        version.length = nxt_strlen(app->version);

        for (i = 0; i < n; i++) {
            if (type == module[i].type
                && nxt_strstr_eq(&module[i].version, &version))
            {
                nxt_log(task, NXT_LOG_NOTICE,
                        "ignoring %s module with the same "
                        "application language version %V %V as in %V",
                        name, &app->type, &version, &module[i].file);

                goto done;
            }
        }

        module = nxt_array_add(modules);
        if (module == NULL) {
            goto fail;
        }

        module->type = type;

        nxt_str_dup(mp, &module->version, &version);
        if (module->version.start == NULL) {
            goto fail;
        }

        module->file.length = nxt_strlen(name);

        module->file.start = nxt_mp_alloc(mp, module->file.length);
        if (module->file.start == NULL) {
            goto fail;
        }

        nxt_memcpy(module->file.start, name, module->file.length);

    } else {
        nxt_alert(task, "dlsym(\"%s\"), failed: \"%s\"", name, dlerror());
    }

done:

    ret = NXT_OK;

fail:

    if (dlclose(dl) != 0) {
        nxt_alert(task, "dlclose(\"%s\"), failed: \"%s\"", name, dlerror());
    }

    return ret;
}


static void
nxt_discovery_completion_handler(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;

    nxt_mp_destroy(mp);
}


static void
nxt_discovery_quit(nxt_task_t *task, nxt_port_recv_msg_t *msg, void *data)
{
    nxt_signal_quit_handler(task, msg);
}


static nxt_int_t
nxt_app_prefork(nxt_task_t *task, nxt_process_t *process, nxt_mp_t *mp)
{
    nxt_int_t              cap_setid;
    nxt_int_t              ret;
    nxt_runtime_t          *rt;
    nxt_common_app_conf_t  *app_conf;

    rt = task->thread->runtime;
    app_conf = process->data.app;
    cap_setid = rt->capabilities.setid;

    if (app_conf->isolation != NULL) {
        ret = nxt_app_isolation(task, app_conf->isolation, process);
        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

#if (NXT_HAVE_CLONE_NEWUSER)
    if (nxt_is_clone_flag_set(process->isolation.clone.flags, NEWUSER)) {
        cap_setid = 1;
    }
#endif

    if (cap_setid) {
        ret = nxt_process_creds_set(task, process, &app_conf->user,
                                    &app_conf->group);

        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }

    } else {
        if (!nxt_str_eq(&app_conf->user, (u_char *) rt->user_cred.user,
                        nxt_strlen(rt->user_cred.user)))
        {
            nxt_alert(task, "cannot set user \"%V\" for app \"%V\": "
                      "missing capabilities", &app_conf->user, &app_conf->name);

            return NXT_ERROR;
        }

        if (app_conf->group.length > 0
            && !nxt_str_eq(&app_conf->group, (u_char *) rt->group,
                           nxt_strlen(rt->group)))
        {
            nxt_alert(task, "cannot set group \"%V\" for app \"%V\": "
                            "missing capabilities", &app_conf->group,
                            &app_conf->name);

            return NXT_ERROR;
        }
    }

#if (NXT_HAVE_CLONE_NEWUSER)
    ret = nxt_process_vldt_isolation_creds(task, process);
    if (nxt_slow_path(ret != NXT_OK)) {
        return ret;
    }
#endif

    return NXT_OK;
}


static nxt_int_t
nxt_app_setup(nxt_task_t *task, nxt_process_t *process)
{
    nxt_int_t              ret;
    nxt_process_init_t     *init;
    nxt_app_lang_module_t  *lang;
    nxt_common_app_conf_t  *app_conf;

    app_conf = process->data.app;

    lang = nxt_app_lang_module(task->thread->runtime, &app_conf->type);
    if (nxt_slow_path(lang == NULL)) {
        nxt_alert(task, "unknown application type: \"%V\"", &app_conf->type);
        return NXT_ERROR;
    }

    nxt_app = lang->module;

    if (nxt_app == NULL) {
        nxt_debug(task, "application language module: %s \"%s\"",
                  lang->version, lang->file);

        nxt_app = nxt_app_module_load(task, lang->file);
        if (nxt_slow_path(nxt_app == NULL)) {
            return NXT_ERROR;
        }
    }

    if (nxt_app->setup != NULL) {
        ret = nxt_app->setup(task, process, app_conf);

        if (nxt_slow_path(ret != NXT_OK)) {
            return ret;
        }
    }

    if (app_conf->working_directory != NULL
        && app_conf->working_directory[0] != 0)
    {
        ret = chdir(app_conf->working_directory);

        if (nxt_slow_path(ret != 0)) {
            nxt_log(task, NXT_LOG_WARN, "chdir(%s) failed %E",
                    app_conf->working_directory, nxt_errno);

            return NXT_ERROR;
        }
    }

    if (nxt_slow_path(nxt_app_set_environment(app_conf->environment)
                      != NXT_OK))
    {
        nxt_alert(task, "failed to set environment");
        return NXT_ERROR;
    }

    init = nxt_process_init(process);

    init->start = nxt_app->start;

    process->state = NXT_PROCESS_STATE_CREATED;

    return NXT_OK;
}


static nxt_app_module_t *
nxt_app_module_load(nxt_task_t *task, const char *name)
{
    void  *dl;

    dl = dlopen(name, RTLD_GLOBAL | RTLD_LAZY);

    if (dl != NULL) {
        return dlsym(dl, "nxt_app_module");
    }

    nxt_alert(task, "dlopen(\"%s\"), failed: \"%s\"", name, dlerror());

    return NULL;
}


static nxt_int_t
nxt_app_set_environment(nxt_conf_value_t *environment)
{
    char              *env, *p;
    uint32_t          next;
    nxt_str_t         name, value;
    nxt_conf_value_t  *value_obj;

    if (environment != NULL) {
        next = 0;

        for ( ;; ) {
            value_obj = nxt_conf_next_object_member(environment, &name, &next);
            if (value_obj == NULL) {
                break;
            }

            nxt_conf_get_string(value_obj, &value);

            env = nxt_malloc(name.length + value.length + 2);
            if (nxt_slow_path(env == NULL)) {
                return NXT_ERROR;
            }

            p = nxt_cpymem(env, name.start, name.length);
            *p++ = '=';
            p = nxt_cpymem(p, value.start, value.length);
            *p = '\0';

            if (nxt_slow_path(putenv(env) != 0)) {
                return NXT_ERROR;
            }
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_app_isolation(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
#if (NXT_HAVE_CLONE)
    nxt_int_t         ret;
    nxt_conf_value_t  *obj;

    static nxt_str_t  nsname = nxt_string("namespaces");

    obj = nxt_conf_get_object_member(isolation, &nsname, NULL);
    if (obj != NULL) {
        ret = nxt_app_clone_flags(task, obj, &process->isolation.clone);
        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }
#endif

#if (NXT_HAVE_CLONE_NEWUSER)
    ret = nxt_app_isolation_creds(task, isolation, process);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }
#endif

    return NXT_OK;
}


#if (NXT_HAVE_CLONE_NEWUSER)

static nxt_int_t
nxt_app_isolation_creds(nxt_task_t *task, nxt_conf_value_t *isolation,
    nxt_process_t *process)
{
    nxt_int_t         ret;
    nxt_clone_t       *clone;
    nxt_conf_value_t  *array;

    static nxt_str_t uidname = nxt_string("uidmap");
    static nxt_str_t gidname = nxt_string("gidmap");

    clone = &process->isolation.clone;

    array = nxt_conf_get_object_member(isolation, &uidname, NULL);
    if (array != NULL) {
        ret = nxt_app_isolation_credential_map(task, process->mem_pool, array,
                                                &clone->uidmap);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    array = nxt_conf_get_object_member(isolation, &gidname, NULL);
    if (array != NULL) {
        ret = nxt_app_isolation_credential_map(task, process->mem_pool, array,
                                                &clone->gidmap);

        if (nxt_slow_path(ret != NXT_OK)) {
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}


static nxt_int_t
nxt_app_isolation_credential_map(nxt_task_t *task, nxt_mp_t *mp,
    nxt_conf_value_t *map_array, nxt_clone_credential_map_t *map)
{
    nxt_int_t         ret;
    nxt_uint_t        i;
    nxt_conf_value_t  *obj;

    static nxt_conf_map_t  nxt_clone_map_entry_conf[] = {
        {
            nxt_string("container"),
            NXT_CONF_MAP_INT,
            offsetof(nxt_clone_map_entry_t, container),
        },

        {
            nxt_string("host"),
            NXT_CONF_MAP_INT,
            offsetof(nxt_clone_map_entry_t, host),
        },

        {
            nxt_string("size"),
            NXT_CONF_MAP_INT,
            offsetof(nxt_clone_map_entry_t, size),
        },
    };

    map->size = nxt_conf_array_elements_count(map_array);

    if (map->size == 0) {
        return NXT_OK;
    }

    map->map = nxt_mp_alloc(mp, map->size * sizeof(nxt_clone_map_entry_t));
    if (nxt_slow_path(map->map == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < map->size; i++) {
        obj = nxt_conf_get_array_element(map_array, i);

        ret = nxt_conf_map_object(mp, obj, nxt_clone_map_entry_conf,
                                  nxt_nitems(nxt_clone_map_entry_conf),
                                  map->map + i);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_alert(task, "clone map entry map error");
            return NXT_ERROR;
        }
    }

    return NXT_OK;
}

#endif

#if (NXT_HAVE_CLONE)

static nxt_int_t
nxt_app_clone_flags(nxt_task_t *task, nxt_conf_value_t *namespaces,
    nxt_clone_t *clone)
{
    uint32_t          index;
    nxt_str_t         name;
    nxt_int_t         flag;
    nxt_conf_value_t  *value;

    index = 0;

    for ( ;; ) {
        value = nxt_conf_next_object_member(namespaces, &name, &index);

        if (value == NULL) {
            break;
        }

        flag = 0;

#if (NXT_HAVE_CLONE_NEWUSER)
        if (nxt_str_eq(&name, "credential", 10)) {
            flag = CLONE_NEWUSER;
        }
#endif

#if (NXT_HAVE_CLONE_NEWPID)
        if (nxt_str_eq(&name, "pid", 3)) {
            flag = CLONE_NEWPID;
        }
#endif

#if (NXT_HAVE_CLONE_NEWNET)
        if (nxt_str_eq(&name, "network", 7)) {
            flag = CLONE_NEWNET;
        }
#endif

#if (NXT_HAVE_CLONE_NEWUTS)
        if (nxt_str_eq(&name, "uname", 5)) {
            flag = CLONE_NEWUTS;
        }
#endif

#if (NXT_HAVE_CLONE_NEWNS)
        if (nxt_str_eq(&name, "mount", 5)) {
            flag = CLONE_NEWNS;
        }
#endif

#if (NXT_HAVE_CLONE_NEWCGROUP)
        if (nxt_str_eq(&name, "cgroup", 6)) {
            flag = CLONE_NEWCGROUP;
        }
#endif

        if (!flag) {
            nxt_alert(task, "unknown namespace flag: \"%V\"", &name);
            return NXT_ERROR;
        }

        if (nxt_conf_get_boolean(value)) {
            clone->flags |= flag;
        }
    }

    return NXT_OK;
}

#endif



nxt_app_lang_module_t *
nxt_app_lang_module(nxt_runtime_t *rt, nxt_str_t *name)
{
    u_char                 *p, *end, *version;
    size_t                 version_length;
    nxt_uint_t             i, n;
    nxt_app_type_t         type;
    nxt_app_lang_module_t  *lang;

    end = name->start + name->length;
    version = end;

    for (p = name->start; p < end; p++) {
        if (*p == ' ') {
            version = p + 1;
            break;
        }

        if (*p >= '0' && *p <= '9') {
            version = p;
            break;
        }
    }

    type = nxt_app_parse_type(name->start, p - name->start);

    if (type == NXT_APP_UNKNOWN) {
        return NULL;
    }

    version_length = end - version;

    lang = rt->languages->elts;
    n = rt->languages->nelts;

    for (i = 0; i < n; i++) {

        /*
         * Versions are sorted in descending order
         * so first match chooses the highest version.
         */

        if (lang[i].type == type
            && nxt_strvers_match(lang[i].version, version, version_length))
        {
            return &lang[i];
        }
    }

    return NULL;
}


nxt_app_type_t
nxt_app_parse_type(u_char *p, size_t length)
{
    nxt_str_t str;

    str.length = length;
    str.start = p;

    if (nxt_str_eq(&str, "external", 8) || nxt_str_eq(&str, "go", 2)) {
        return NXT_APP_EXTERNAL;

    } else if (nxt_str_eq(&str, "python", 6)) {
        return NXT_APP_PYTHON;

    } else if (nxt_str_eq(&str, "php", 3)) {
        return NXT_APP_PHP;

    } else if (nxt_str_eq(&str, "perl", 4)) {
        return NXT_APP_PERL;

    } else if (nxt_str_eq(&str, "ruby", 4)) {
        return NXT_APP_RUBY;

    } else if (nxt_str_eq(&str, "java", 4)) {
        return NXT_APP_JAVA;
    }

    return NXT_APP_UNKNOWN;
}


nxt_int_t
nxt_unit_default_init(nxt_task_t *task, nxt_unit_init_t *init)
{
    nxt_port_t     *my_port, *main_port;
    nxt_runtime_t  *rt;

    nxt_memzero(init, sizeof(nxt_unit_init_t));

    rt = task->thread->runtime;

    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    if (nxt_slow_path(main_port == NULL)) {
        return NXT_ERROR;
    }

    my_port = nxt_runtime_port_find(rt, nxt_pid, 0);
    if (nxt_slow_path(my_port == NULL)) {
        return NXT_ERROR;
    }

    init->ready_port.id.pid = main_port->pid;
    init->ready_port.id.id = main_port->id;
    init->ready_port.out_fd = main_port->pair[1];

    nxt_fd_blocking(task, main_port->pair[1]);

    init->ready_stream = my_port->process->stream;

    init->read_port.id.pid = my_port->pid;
    init->read_port.id.id = my_port->id;
    init->read_port.in_fd = my_port->pair[0];

    nxt_fd_blocking(task, my_port->pair[0]);

    init->log_fd = 2;

    return NXT_OK;
}
