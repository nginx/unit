
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
#include <nxt_port_memory_int.h>

#include <glob.h>


typedef struct {
    nxt_app_type_t  type;
    nxt_str_t       version;
    nxt_str_t       file;
} nxt_module_t;


static nxt_buf_t *nxt_discovery_modules(nxt_task_t *task, const char *path);
static nxt_int_t nxt_discovery_module(nxt_task_t *task, nxt_mp_t *mp,
    nxt_array_t *modules, const char *name);
static void nxt_discovery_completion_handler(nxt_task_t *task, void *obj,
    void *data);
static void nxt_discovery_quit(nxt_task_t *task, nxt_port_recv_msg_t *msg,
    void *data);
static nxt_app_module_t *nxt_app_module_load(nxt_task_t *task,
    const char *name);
static nxt_int_t nxt_app_set_environment(nxt_conf_value_t *environment);

static void nxt_app_http_release(nxt_task_t *task, void *obj, void *data);


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


nxt_str_t  nxt_server = nxt_string(NXT_SERVER);


static nxt_thread_mutex_t        nxt_app_mutex;
static nxt_thread_cond_t         nxt_app_cond;

static nxt_application_module_t  *nxt_app;


nxt_int_t
nxt_discovery_start(nxt_task_t *task, void *data)
{
    uint32_t       stream;
    nxt_buf_t      *b;
    nxt_int_t      ret;
    nxt_port_t     *main_port, *discovery_port;
    nxt_runtime_t  *rt;

    nxt_debug(task, "DISCOVERY");

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
    void                      *dl;
    nxt_str_t                 version;
    nxt_int_t                 ret;
    nxt_uint_t                i, n;
    nxt_module_t              *module;
    nxt_app_type_t            type;
    nxt_application_module_t  *app;

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
    nxt_worker_process_quit_handler(task, msg);
}


nxt_int_t
nxt_app_start(nxt_task_t *task, void *data)
{
    nxt_int_t              ret;
    nxt_app_lang_module_t  *lang;
    nxt_common_app_conf_t  *app_conf;

    app_conf = data;

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

    if (nxt_slow_path(nxt_thread_mutex_create(&nxt_app_mutex) != NXT_OK)) {
        return NXT_ERROR;
    }

    if (nxt_slow_path(nxt_thread_cond_create(&nxt_app_cond) != NXT_OK)) {
        return NXT_ERROR;
    }

    ret = nxt_app->init(task, data);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_debug(task, "application init failed");

    } else {
        nxt_debug(task, "application init done");
    }

    return ret;
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


void
nxt_app_quit_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    if (nxt_app->atexit != NULL) {
        nxt_app->atexit(task);
    }

    nxt_worker_process_quit_handler(task, msg);
}


void
nxt_app_data_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    size_t          dump_size;
    nxt_int_t       res;
    nxt_buf_t       *b;
    nxt_port_t      *port;
    nxt_app_rmsg_t  rmsg = { msg->buf };
    nxt_app_wmsg_t  wmsg;

    b = msg->buf;
    dump_size = b->mem.free - b->mem.pos;

    if (dump_size > 300) {
        dump_size = 300;
    }

    nxt_debug(task, "app data: %*s ...", dump_size, b->mem.pos);

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);
    if (nxt_slow_path(port == NULL)) {
        nxt_debug(task, "stream #%uD: reply port %d not found",
                  msg->port_msg.stream, msg->port_msg.reply_port);
        return;
    }

    wmsg.port = port;
    wmsg.write = NULL;
    wmsg.buf = &wmsg.write;
    wmsg.stream = msg->port_msg.stream;

    res = nxt_app->run(task, &rmsg, &wmsg);

    if (nxt_slow_path(res != NXT_OK)) {
        nxt_port_socket_write(task, port, NXT_PORT_MSG_RPC_ERROR, -1,
                              msg->port_msg.stream, 0, NULL);
    }
}


u_char *
nxt_app_msg_write_get_buf(nxt_task_t *task, nxt_app_wmsg_t *msg, size_t size)
{
    size_t      free_size;
    u_char      *res;
    nxt_buf_t   *b;

    res = NULL;

    do {
        b = *msg->buf;

        if (b == NULL) {
            b = nxt_port_mmap_get_buf(task, msg->port, size);
            if (nxt_slow_path(b == NULL)) {
                return NULL;
            }

            *msg->buf = b;
        }

        free_size = nxt_buf_mem_free_size(&b->mem);

        if (free_size >= size) {
            res = b->mem.free;
            b->mem.free += size;

            return res;
        }

        if (nxt_port_mmap_increase_buf(task, b, size, size) == NXT_OK) {
            res = b->mem.free;
            b->mem.free += size;

            return res;
        }

        msg->buf = &b->next;
    } while(1);
}


nxt_int_t
nxt_app_msg_write(nxt_task_t *task, nxt_app_wmsg_t *msg, u_char *c, size_t size)
{
    u_char  *dst;
    size_t  dst_length;

    if (c != NULL) {
        dst_length = size + (size < 128 ? 1 : 4) + 1;

        dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
        if (nxt_slow_path(dst == NULL)) {
            nxt_debug(task, "nxt_app_msg_write: get_buf(%uz) failed",
                      dst_length);
            return NXT_ERROR;
        }

        dst = nxt_app_msg_write_length(dst, size + 1); /* +1 for trailing 0 */

        nxt_memcpy(dst, c, size);
        dst[size] = 0;

        nxt_debug(task, "nxt_app_msg_write: %uz %*s", size, size, c);

    } else {
        dst_length = 1;

        dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
        if (nxt_slow_path(dst == NULL)) {
            nxt_debug(task, "nxt_app_msg_write: get_buf(%uz) failed",
                      dst_length);
            return NXT_ERROR;
        }

        dst = nxt_app_msg_write_length(dst, 0);

        nxt_debug(task, "nxt_app_msg_write: NULL");
    }

    return NXT_OK;
}


nxt_int_t
nxt_app_msg_write_prefixed_upcase(nxt_task_t *task, nxt_app_wmsg_t *msg,
    const nxt_str_t *prefix, u_char *c, size_t size)
{
    u_char  *dst, *src;
    size_t  i, length, dst_length;

    length = prefix->length + size;

    dst_length = length + (length < 128 ? 1 : 4) + 1;

    dst = nxt_app_msg_write_get_buf(task, msg, dst_length);
    if (nxt_slow_path(dst == NULL)) {
        return NXT_ERROR;
    }

    dst = nxt_app_msg_write_length(dst, length + 1); /* +1 for trailing 0 */

    nxt_memcpy(dst, prefix->start, prefix->length);
    dst += prefix->length;

    src = c;
    for (i = 0; i < size; i++, dst++, src++) {

        if (*src >= 'a' && *src <= 'z') {
            *dst = *src & ~0x20;
            continue;
        }

        if (*src == '-') {
            *dst = '_';
            continue;
        }

        *dst = *src;
    }

    *dst = 0;

    return NXT_OK;
}


nxt_inline nxt_int_t
nxt_app_msg_read_size_(nxt_task_t *task, nxt_app_rmsg_t *msg, size_t *size)
{
    nxt_buf_t  *buf;

    do {
        buf = msg->buf;

        if (nxt_slow_path(buf == NULL)) {
            return NXT_DONE;
        }

        if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 1)) {
            if (nxt_fast_path(nxt_buf_mem_used_size(&buf->mem) == 0)) {
                msg->buf = buf->next;
                continue;
            }
            return NXT_ERROR;
        }

        if (buf->mem.pos[0] >= 128) {
            if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < 4)) {
                return NXT_ERROR;
            }
        }

        break;
    } while (1);

    buf->mem.pos = nxt_app_msg_read_length(buf->mem.pos, size);

    return NXT_OK;
}


nxt_int_t
nxt_app_msg_read_str(nxt_task_t *task, nxt_app_rmsg_t *msg, nxt_str_t *str)
{
    size_t      length;
    nxt_int_t   ret;
    nxt_buf_t  *buf;

    ret = nxt_app_msg_read_size_(task, msg, &length);
    if (ret != NXT_OK) {
        return ret;
    }

    buf = msg->buf;

    if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) < (intptr_t) length)) {
        return NXT_ERROR;
    }

    if (length > 0) {
        str->start = buf->mem.pos;
        str->length = length - 1;

        buf->mem.pos += length;

        nxt_debug(task, "nxt_read_str: %uz %*s", length - 1,
                        length - 1, str->start);

    } else {
        str->start = NULL;
        str->length = 0;

        nxt_debug(task, "nxt_read_str: NULL");
    }

    return NXT_OK;
}


size_t
nxt_app_msg_read_raw(nxt_task_t *task, nxt_app_rmsg_t *msg, void *dst,
    size_t size)
{
    size_t     res, read_size;
    nxt_buf_t  *buf;

    res = 0;

    while (size > 0) {
        buf = msg->buf;

        if (nxt_slow_path(buf == NULL)) {
            break;
        }

        if (nxt_slow_path(nxt_buf_mem_used_size(&buf->mem) == 0)) {
            msg->buf = buf->next;
            continue;
        }

        read_size = nxt_buf_mem_used_size(&buf->mem);
        read_size = nxt_min(read_size, size);

        dst = nxt_cpymem(dst, buf->mem.pos, read_size);

        size -= read_size;
        buf->mem.pos += read_size;
        res += read_size;
    }

    nxt_debug(task, "nxt_read_raw: %uz", res);

    return res;
}


nxt_int_t
nxt_app_msg_read_nvp(nxt_task_t *task, nxt_app_rmsg_t *rmsg, nxt_str_t *n,
    nxt_str_t *v)
{
    nxt_int_t rc;

    rc = nxt_app_msg_read_str(task, rmsg, n);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    rc = nxt_app_msg_read_str(task, rmsg, v);
    if (nxt_slow_path(rc != NXT_OK)) {
        return rc;
    }

    return rc;
}


nxt_int_t
nxt_app_msg_read_size(nxt_task_t *task, nxt_app_rmsg_t *msg, size_t *size)
{
    nxt_int_t  ret;

    ret = nxt_app_msg_read_size_(task, msg, size);

    nxt_debug(task, "nxt_read_size: %d", (int) *size);

    return ret;
}


nxt_int_t
nxt_app_http_req_done(nxt_task_t *task, nxt_app_parse_ctx_t *ar)
{
    ar->timer.handler = nxt_app_http_release;
    nxt_timer_add(task->thread->engine, &ar->timer, 0);

    return NXT_OK;
}


static void
nxt_app_http_release(nxt_task_t *task, void *obj, void *data)
{
    nxt_timer_t          *timer;
    nxt_app_parse_ctx_t  *ar;

    timer = obj;

    nxt_debug(task, "http app release");

    ar = nxt_timer_data(timer, nxt_app_parse_ctx_t, timer);

    nxt_mp_release(ar->request->mem_pool);
}


nxt_int_t
nxt_app_msg_flush(nxt_task_t *task, nxt_app_wmsg_t *msg, nxt_bool_t last)
{
    nxt_int_t   rc;
    nxt_buf_t   *b;

    rc = NXT_OK;

    if (nxt_slow_path(last == 1)) {
        do {
            b = *msg->buf;

            if (b == NULL) {
                b = nxt_buf_sync_alloc(msg->port->mem_pool, NXT_BUF_SYNC_LAST);
                *msg->buf = b;
                break;
            }

            msg->buf = &b->next;
        } while(1);
    }

    if (nxt_slow_path(msg->write != NULL)) {
        rc = nxt_port_socket_write(task, msg->port, NXT_PORT_MSG_DATA,
                                   -1, msg->stream, 0, msg->write);

        msg->write = NULL;
        msg->buf = &msg->write;
    }

    return rc;
}


nxt_int_t
nxt_app_msg_write_raw(nxt_task_t *task, nxt_app_wmsg_t *msg, const u_char *c,
    size_t size)
{
    size_t     free_size, copy_size;
    nxt_buf_t  *b;

    nxt_debug(task, "nxt_app_msg_write_raw: %uz", size);

    while (size > 0) {
        b = *msg->buf;

        if (b == NULL) {
            free_size = nxt_min(size, PORT_MMAP_DATA_SIZE);

            b = nxt_port_mmap_get_buf(task, msg->port, free_size);
            if (nxt_slow_path(b == NULL)) {
                return NXT_ERROR;
            }

            *msg->buf = b;

        } else {
            free_size = nxt_buf_mem_free_size(&b->mem);

            if (free_size < size
                && nxt_port_mmap_increase_buf(task, b, size, 1) == NXT_OK)
            {
                free_size = nxt_buf_mem_free_size(&b->mem);
            }
        }

        if (free_size > 0) {
            copy_size = nxt_min(free_size, size);

            b->mem.free = nxt_cpymem(b->mem.free, c, copy_size);

            size -= copy_size;
            c += copy_size;

            if (size == 0) {
                return NXT_OK;
            }
        }

        msg->buf = &b->next;
    }

    return NXT_OK;
}


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

    if (nxt_str_eq(&str, "python", 6)) {
        return NXT_APP_PYTHON;

    } else if (nxt_str_eq(&str, "php", 3)) {
        return NXT_APP_PHP;

    } else if (nxt_str_eq(&str, "go", 2)) {
        return NXT_APP_GO;

    } else if (nxt_str_eq(&str, "perl", 4)) {
        return NXT_APP_PERL;

    } else if (nxt_str_eq(&str, "ruby", 4)) {
        return NXT_APP_RUBY;
    }

    return NXT_APP_UNKNOWN;
}
