
/*
 * Copyright (C) NGINX, Inc.
 * Copyright (C) Zhidao HONG
 */

#include <nxt_main.h>
#include <nxt_conf.h>
#include <nxt_script.h>
#include <dirent.h>


struct nxt_script_s {
    nxt_str_t         text;
};


typedef struct {
    nxt_str_t         name;
    nxt_conf_value_t  *value;
    nxt_mp_t          *mp;
} nxt_script_info_t;


typedef struct {
    nxt_str_t         name;
    nxt_fd_t          fd;
} nxt_script_item_t;


static nxt_script_t *nxt_script_get(nxt_task_t *task, nxt_str_t *name,
    nxt_fd_t fd);
static nxt_conf_value_t *nxt_script_details(nxt_mp_t *mp, nxt_script_t *cert);
static void nxt_script_buf_completion(nxt_task_t *task, void *obj, void *data);


static nxt_lvlhsh_t  nxt_script_info;


nxt_script_t *
nxt_script_new(nxt_task_t *task, nxt_str_t *name, u_char *data, size_t size,
    u_char *error)
{
    u_char        *start;
    njs_vm_t      *vm;
    njs_str_t     mod_name;
    njs_mod_t     *mod;
    njs_vm_opt_t  opts;
    nxt_script_t  *script;

    njs_vm_opt_init(&opts);

    opts.backtrace = 1;

    opts.file.start = (u_char *) "default";
    opts.file.length = 7;

    vm = njs_vm_create(&opts);
    if (nxt_slow_path(vm == NULL)) {
        return NULL;
    }

    mod_name.length = name->length;
    mod_name.start = name->start;

    start = data;

    mod = njs_vm_compile_module(vm, &mod_name, &start, start + size);

    if (nxt_slow_path(mod == NULL)) {
        (void) nxt_js_error(vm, error);
        nxt_alert(task, "JS compile module(%V) failed: %s", name, error);

        goto fail;
    }

    script = nxt_zalloc(sizeof(nxt_script_t) + size);
    if (nxt_slow_path(script == NULL)) {
        goto fail;
    }

    script->text.length = size;
    script->text.start = (u_char *) script + sizeof(nxt_script_t);

    nxt_memcpy(script->text.start, data, size);

    njs_vm_destroy(vm);

    return script;

fail:

    njs_vm_destroy(vm);

    return NULL;
}


static nxt_script_t *
nxt_script_get(nxt_task_t *task, nxt_str_t *name, nxt_fd_t fd)
{
    nxt_int_t     ret;
    nxt_str_t     text;
    nxt_script_t  *script;
    u_char        error[NXT_MAX_ERROR_STR];

    ret = nxt_script_file_read(fd, &text);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    script = nxt_script_new(task, name, text.start, text.length, error);

    nxt_free(text.start);

    return script;
}


void
nxt_script_destroy(nxt_script_t *script)
{
    nxt_free(script);
}


static nxt_int_t
nxt_script_info_hash_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    nxt_script_info_t  *info;

    info = data;

    if (nxt_strcasestr_eq(&lhq->key, &info->name)) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static const nxt_lvlhsh_proto_t  nxt_script_info_hash_proto
    nxt_aligned(64) =
{
    NXT_LVLHSH_DEFAULT,
    nxt_script_info_hash_test,
    nxt_lvlhsh_alloc,
    nxt_lvlhsh_free,
};


void
nxt_script_info_init(nxt_task_t *task, nxt_array_t *scripts)
{
    uint32_t           i;
    nxt_script_t       *script;
    nxt_script_item_t  *item;

    item = scripts->elts;

    for (i = 0; i < scripts->nelts; i++) {
        script = nxt_script_get(task, &item->name, item->fd);

        if (nxt_slow_path(script == NULL)) {
            continue;
        }

        (void) nxt_script_info_save(&item->name, script);

        nxt_script_destroy(script);

        item++;
    }
}


nxt_int_t
nxt_script_info_save(nxt_str_t *name, nxt_script_t *script)
{
    nxt_mp_t            *mp;
    nxt_int_t           ret;
    nxt_conf_value_t    *value;
    nxt_script_info_t   *info;
    nxt_lvlhsh_query_t  lhq;

    mp = nxt_mp_create(1024, 128, 256, 32);
    if (nxt_slow_path(mp == NULL)) {
        return NXT_ERROR;
    }

    info = nxt_mp_get(mp, sizeof(nxt_script_info_t));
    if (nxt_slow_path(info == NULL)) {
        goto fail;
    }

    name = nxt_str_dup(mp, &info->name, name);
    if (nxt_slow_path(name == NULL)) {
        goto fail;
    }

    value = nxt_script_details(mp, script);
    if (nxt_slow_path(value == NULL)) {
        goto fail;
    }

    info->mp = mp;
    info->value = value;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.replace = 1;
    lhq.key = *name;
    lhq.value = info;
    lhq.proto = &nxt_script_info_hash_proto;

    ret = nxt_lvlhsh_insert(&nxt_script_info, &lhq);
    if (nxt_slow_path(ret != NXT_OK)) {
        goto fail;
    }

    if (lhq.value != info) {
        info = lhq.value;
        nxt_mp_destroy(info->mp);
    }

    return NXT_OK;

fail:

    nxt_mp_destroy(mp);
    return NXT_ERROR;
}


nxt_conf_value_t *
nxt_script_info_get(nxt_str_t *name)
{
    nxt_int_t           ret;
    nxt_script_info_t   *info;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.key = *name;
    lhq.proto = &nxt_script_info_hash_proto;

    ret = nxt_lvlhsh_find(&nxt_script_info, &lhq);
    if (ret != NXT_OK) {
        return NULL;
    }

    info = lhq.value;

    return info->value;
}


nxt_conf_value_t *
nxt_script_info_get_all(nxt_mp_t *mp)
{
    uint32_t           i;
    nxt_conf_value_t   *all;
    nxt_script_info_t  *info;
    nxt_lvlhsh_each_t  lhe;

    nxt_lvlhsh_each_init(&lhe, &nxt_script_info_hash_proto);

    for (i = 0; /* void */; i++) {
        info = nxt_lvlhsh_each(&nxt_script_info, &lhe);

        if (info == NULL) {
            break;
        }
    }

    all = nxt_conf_create_object(mp, i);
    if (nxt_slow_path(all == NULL)) {
        return NULL;
    }

    nxt_lvlhsh_each_init(&lhe, &nxt_script_info_hash_proto);

    for (i = 0; /* void */; i++) {
        info = nxt_lvlhsh_each(&nxt_script_info, &lhe);

        if (info == NULL) {
            break;
        }

        nxt_conf_set_member(all, &info->name, info->value, i);
    }

    return all;
}


static nxt_conf_value_t *
nxt_script_details(nxt_mp_t *mp, nxt_script_t *script)
{
    nxt_conf_value_t  *value;

    value = nxt_conf_create_object(mp, 0);
    if (nxt_slow_path(value == NULL)) {
        return NULL;
    }

    nxt_conf_set_string_dup(value, mp, &script->text);

    return value;
}


nxt_int_t
nxt_script_info_delete(nxt_str_t *name)
{
    nxt_int_t           ret;
    nxt_script_info_t   *info;
    nxt_lvlhsh_query_t  lhq;

    lhq.key_hash = nxt_djb_hash(name->start, name->length);
    lhq.key = *name;
    lhq.proto = &nxt_script_info_hash_proto;

    ret = nxt_lvlhsh_delete(&nxt_script_info, &lhq);

    if (ret == NXT_OK) {
        info = lhq.value;
        nxt_mp_destroy(info->mp);
    }

    return ret;
}


nxt_array_t *
nxt_script_store_load(nxt_task_t *task, nxt_mp_t *mp)
{
    DIR                *dir;
    size_t             size, alloc;
    u_char             *buf, *p;
    nxt_str_t          name;
    nxt_int_t          ret;
    nxt_file_t         file;
    nxt_array_t        *scripts;
    nxt_runtime_t      *rt;
    struct dirent      *de;
    nxt_script_item_t  *item;

    rt = task->thread->runtime;

    if (nxt_slow_path(rt->scripts.start == NULL)) {
        nxt_alert(task, "no scripts storage directory");
        return NULL;
    }

    scripts = nxt_array_create(mp, 16, sizeof(nxt_script_item_t));
    if (nxt_slow_path(scripts == NULL)) {
        return NULL;
    }

    buf = NULL;
    alloc = 0;

    dir = opendir((char *) rt->scripts.start);
    if (nxt_slow_path(dir == NULL)) {
        nxt_alert(task, "opendir(\"%s\") failed %E",
                  rt->scripts.start, nxt_errno);
        goto fail;
    }

    for ( ;; ) {
        de = readdir(dir);
        if (de == NULL) {
            break;
        }

        nxt_debug(task, "readdir(\"%s\"): \"%s\"",
                  rt->scripts.start, de->d_name);

        name.length = nxt_strlen(de->d_name);
        name.start = (u_char *) de->d_name;

        if (nxt_str_eq(&name, ".", 1) || nxt_str_eq(&name, "..", 2)) {
            continue;
        }

        item = nxt_array_add(scripts);
        if (nxt_slow_path(item == NULL)) {
            goto fail;
        }

        item->fd = -1;

        size = rt->scripts.length + name.length + 1;

        if (size > alloc) {
            size += 32;

            p = nxt_realloc(buf, size);
            if (p == NULL) {
                goto fail;
            }

            alloc = size;
            buf = p;
        }

        p = nxt_cpymem(buf, rt->scripts.start, rt->scripts.length);
        p = nxt_cpymem(p, name.start, name.length + 1);

        nxt_memzero(&file, sizeof(nxt_file_t));

        file.name = buf;

        ret = nxt_file_open(task, &file, NXT_FILE_RDONLY, NXT_FILE_OPEN,
                            NXT_FILE_OWNER_ACCESS);

        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_array_remove_last(scripts);
            continue;
        }

        item->fd = file.fd;

        if (nxt_slow_path(nxt_str_dup(mp, &item->name, &name) == NULL)) {
            goto fail;
        }
    }

    if (buf != NULL) {
        nxt_free(buf);
    }

    (void) closedir(dir);

    return scripts;

fail:

    if (buf != NULL) {
        nxt_free(buf);
    }

    if (dir != NULL) {
        (void) closedir(dir);
    }

    nxt_script_store_release(scripts);

    return NULL;
}


void
nxt_script_store_release(nxt_array_t *scripts)
{
    uint32_t           i;
    nxt_script_item_t  *item;

    item = scripts->elts;

    for (i = 0; i < scripts->nelts; i++) {
        nxt_fd_close(item[i].fd);
    }

    nxt_array_destroy(scripts);
}


void
nxt_script_store_get(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp,
    nxt_port_rpc_handler_t handler, void *ctx)
{
    uint32_t       stream;
    nxt_int_t      ret;
    nxt_buf_t      *b;
    nxt_port_t     *main_port, *recv_port;
    nxt_runtime_t  *rt;

    b = nxt_buf_mem_alloc(mp, name->length + 1, 0);
    if (nxt_slow_path(b == NULL)) {
        goto fail;
    }

    nxt_mp_retain(mp);
    b->completion_handler = nxt_script_buf_completion;

    nxt_buf_cpystr(b, name);
    *b->mem.free++ = '\0';

    rt = task->thread->runtime;
    main_port = rt->port_by_type[NXT_PROCESS_MAIN];
    recv_port = rt->port_by_type[rt->type];

    stream = nxt_port_rpc_register_handler(task, recv_port, handler, handler,
                                           -1, ctx);
    if (nxt_slow_path(stream == 0)) {
        goto fail;
    }

    ret = nxt_port_socket_write(task, main_port, NXT_PORT_MSG_SCRIPT_GET, -1,
                                stream, recv_port->id, b);

    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_port_rpc_cancel(task, recv_port, stream);
        goto fail;
    }

    return;

fail:

    handler(task, NULL, ctx);
}


static void
nxt_script_buf_completion(nxt_task_t *task, void *obj, void *data)
{
    nxt_mp_t   *mp;
    nxt_buf_t  *b;

    b = obj;
    mp = b->data;
    nxt_assert(b->next == NULL);

    nxt_mp_free(mp, b);
    nxt_mp_release(mp);
}


void
nxt_script_store_get_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char               *p;
    nxt_int_t            ret;
    nxt_str_t            name;
    nxt_file_t           file;
    nxt_port_t           *port;
    nxt_runtime_t        *rt;
    nxt_port_msg_type_t  type;

    port = nxt_runtime_port_find(task->thread->runtime, msg->port_msg.pid,
                                 msg->port_msg.reply_port);

    if (nxt_slow_path(port == NULL)) {
        nxt_alert(task, "process port not found (pid %PI, reply_port %d)",
                  msg->port_msg.pid, msg->port_msg.reply_port);
        return;
    }

    if (nxt_slow_path(port->type != NXT_PROCESS_CONTROLLER
                      && port->type != NXT_PROCESS_ROUTER))
    {
        nxt_alert(task, "process %PI cannot store scripts",
                  msg->port_msg.pid);
        return;
    }

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.fd = -1;
    type = NXT_PORT_MSG_RPC_ERROR;

    rt = task->thread->runtime;

    if (nxt_slow_path(rt->certs.start == NULL)) {
        nxt_alert(task, "no scripts storage directory");
        goto error;
    }

    name.start = msg->buf->mem.pos;
    name.length = nxt_strlen(name.start);

    file.name = nxt_malloc(rt->scripts.length + name.length + 1);
    if (nxt_slow_path(file.name == NULL)) {
        goto error;
    }

    p = nxt_cpymem(file.name, rt->scripts.start, rt->scripts.length);
    p = nxt_cpymem(p, name.start, name.length + 1);

    ret = nxt_file_open(task, &file, NXT_FILE_RDWR, NXT_FILE_CREATE_OR_OPEN,
                        NXT_FILE_OWNER_ACCESS);

    nxt_free(file.name);

    if (nxt_fast_path(ret == NXT_OK)) {
        type = NXT_PORT_MSG_RPC_READY_LAST | NXT_PORT_MSG_CLOSE_FD;
    }

error:

    (void) nxt_port_socket_write(task, port, type, file.fd,
                                 msg->port_msg.stream, 0, NULL);
}


void
nxt_script_store_delete(nxt_task_t *task, nxt_str_t *name, nxt_mp_t *mp)
{
    nxt_buf_t      *b;
    nxt_port_t     *main_port;
    nxt_runtime_t  *rt;

    b = nxt_buf_mem_alloc(mp, name->length + 1, 0);

    if (nxt_fast_path(b != NULL)) {
        nxt_buf_cpystr(b, name);
        *b->mem.free++ = '\0';

        rt = task->thread->runtime;
        main_port = rt->port_by_type[NXT_PROCESS_MAIN];

        (void) nxt_port_socket_write(task, main_port,
                                     NXT_PORT_MSG_SCRIPT_DELETE, -1, 0, 0, b);
    }
}


void
nxt_script_store_delete_handler(nxt_task_t *task, nxt_port_recv_msg_t *msg)
{
    u_char           *p;
    nxt_str_t        name;
    nxt_port_t       *ctl_port;
    nxt_runtime_t    *rt;
    nxt_file_name_t  *path;

    rt = task->thread->runtime;
    ctl_port = rt->port_by_type[NXT_PROCESS_CONTROLLER];

    if (nxt_slow_path(ctl_port == NULL)) {
        nxt_alert(task, "controller port not found");
        return;
    }

    if (nxt_slow_path(nxt_recv_msg_cmsg_pid(msg) != ctl_port->pid)) {
        nxt_alert(task, "process %PI cannot delete scripts",
                  nxt_recv_msg_cmsg_pid(msg));
        return;
    }

    if (nxt_slow_path(rt->scripts.start == NULL)) {
        nxt_alert(task, "no scripts storage directory");
        return;
    }

    name.start = msg->buf->mem.pos;
    name.length = nxt_strlen(name.start);

    path = nxt_malloc(rt->scripts.length + name.length + 1);

    if (nxt_fast_path(path != NULL)) {
        p = nxt_cpymem(path, rt->scripts.start, rt->scripts.length);
        p = nxt_cpymem(p, name.start, name.length + 1);

        (void) nxt_file_delete(path);

        nxt_free(path);
    }
}


nxt_int_t
nxt_script_file_read(nxt_fd_t fd, nxt_str_t *str)
{
    ssize_t          n;
    nxt_int_t        ret;
    nxt_file_t       file;
    nxt_file_info_t  fi;

    nxt_memzero(&file, sizeof(nxt_file_t));

    file.fd = fd;

    ret = nxt_file_info(&file, &fi);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NXT_ERROR;
    }

    if (nxt_slow_path(!nxt_is_file(&fi))) {
        nxt_str_null(str);
        return NXT_DECLINED;
    }

    str->length = nxt_file_size(&fi);
    str->start = nxt_malloc(str->length);
    if (nxt_slow_path(str->start == NULL)) {
        return NXT_ERROR;
    }

    n = nxt_file_read(&file, str->start, str->length, 0);

    if (nxt_slow_path(n != (ssize_t) str->length)) {
        nxt_free(str->start);
        return NXT_ERROR;
    }

    return NXT_OK;
}
