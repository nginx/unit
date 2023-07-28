/*
 * Copyright (C) Andrew Clayton
 * Copyright (C) F5, Inc.
 */

#include <nxt_main.h>
#include <nxt_application.h>
#include <nxt_unit.h>
#include <nxt_unit_request.h>

#include "nxt_wasm.h"

#define NXT_WASM_VERSION    "0.1"

static nxt_wasm_ctx_t               nxt_wasm_ctx;

static const nxt_wasm_operations_t  *nxt_wops;

#define NXT_WASM_DO_HOOK(hook)  nxt_wops->exec_hook(&nxt_wasm_ctx, hook);

void
nxt_wasm_do_response_end(nxt_wasm_ctx_t *ctx)
{
    nxt_unit_request_done(ctx->req, NXT_UNIT_OK);

    NXT_WASM_DO_HOOK(NXT_WASM_FH_RESPONSE_END);
}


void
nxt_wasm_do_send_headers(uint32_t offs, nxt_wasm_ctx_t *ctx)
{
    size_t                   fields_len;
    unsigned int             i;
    nxt_wasm_response_hdr_t  *rh;

    rh = (nxt_wasm_response_hdr_t *)(ctx->baddr + offs);

    fields_len = 0;
    for (i = 0; i < rh->nr_fields; i++)
        fields_len += rh->fields[i].name_len + rh->fields[i].value_len;

    nxt_unit_response_init(ctx->req, 200, rh->nr_fields, fields_len);

    for (i = 0; i < rh->nr_fields; i++) {
        const char *name;
        const char *val;

        name = (const char *)(uint8_t *)rh + rh->fields[i].name_offs;
        val = (const char *)(uint8_t *)rh + rh->fields[i].value_offs;

        printf("# Got header field [%.*s: %.*s]\n",
               rh->fields[i].name_len, name,
               rh->fields[i].value_len, val);

        nxt_unit_response_add_field(ctx->req, name, rh->fields[i].name_len,
                                    val, rh->fields[i].value_len);
    }

    nxt_unit_response_send(ctx->req);
}


void
nxt_wasm_do_send_response(uint32_t offs, nxt_wasm_ctx_t *ctx)
{
    nxt_wasm_response_t      *resp;
    nxt_unit_request_info_t  *req = ctx->req;

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_response_init(req, 200, 0, 0);
    }

    resp = (nxt_wasm_response_t *)(nxt_wasm_ctx.baddr + offs);

    nxt_unit_response_write(req, (const char *)resp->data, resp->size);
    printf("== Sending %u bytes to unit\n", resp->size);
}


static void
nxt_wasm_request_handler(nxt_unit_request_info_t *req)
{
    size_t                     offset, read_bytes, content_sent, content_len;
    ssize_t                    bytes_read;
    nxt_unit_field_t           *sf, *sf_end;
    nxt_unit_request_t         *r;
    nxt_wasm_request_t         *wr;
    nxt_wasm_http_hdr_field_t  *df;

    NXT_WASM_DO_HOOK(NXT_WASM_FH_REQUEST_INIT);

    wr = (nxt_wasm_request_t *)nxt_wasm_ctx.baddr;

#define SET_REQ_MEMBER(dmember, smember) \
    do { \
        const char *str = nxt_unit_sptr_get(&r->smember); \
        wr->dmember##_offs = offset; \
        wr->dmember##_len = strlen(str); \
        memcpy((uint8_t *)wr + offset, str, wr->dmember##_len + 1); \
        offset += wr->dmember##_len + 1; \
    } while (0)

    r = req->request;
    offset = sizeof(nxt_wasm_request_t)
             + (r->fields_count * sizeof(nxt_wasm_http_hdr_field_t));

    SET_REQ_MEMBER(path, path);
    SET_REQ_MEMBER(method, method);
    SET_REQ_MEMBER(version, version);
    SET_REQ_MEMBER(query, query);
    SET_REQ_MEMBER(remote, remote);
    SET_REQ_MEMBER(local_addr, local_addr);
    SET_REQ_MEMBER(local_port, local_port);
    SET_REQ_MEMBER(server_name, server_name);
#undef SET_REQ_MEMBER

    df = wr->fields;
    sf_end = r->fields + r->fields_count;
    for (sf = r->fields; sf < sf_end; sf++) {
        const char *name = nxt_unit_sptr_get(&sf->name);
        const char *value = nxt_unit_sptr_get(&sf->value);

        df->name_offs = offset;
        df->name_len = strlen(name);
        memcpy((uint8_t *)wr + offset, name, df->name_len + 1);
        offset += df->name_len + 1;

        df->value_offs = offset;
        df->value_len = strlen(value);
        memcpy((uint8_t *)wr + offset, value, df->value_len + 1);
        offset += df->value_len + 1;

        df++;
    }

    wr->tls = r->tls;
    wr->nr_fields = r->fields_count;
    wr->content_offs = offset;
    wr->content_len = content_len = r->content_length;

    printf("%s: Got request for (%.*s)\n", __func__, wr->path_len,
           (uint8_t *)wr + wr->path_offs);

    read_bytes = wr->content_len;
    if (read_bytes > NXT_WASM_MEM_SIZE - offset) {
        read_bytes = NXT_WASM_MEM_SIZE - offset;
    }

    printf("**** Reading %lu bytes from nxt_unit_request_read()\n", read_bytes);
    bytes_read = nxt_unit_request_read(req, (uint8_t *)wr + offset, read_bytes);
    printf("**** Got %ld from nxt_unit_request_read()\n", bytes_read);
    wr->content_sent = wr->total_content_sent = content_sent = bytes_read;

    wr->request_size = offset + bytes_read;
    printf("**** wr->request_size : %u\n", wr->request_size);

    nxt_wasm_ctx.req = req;
    nxt_wops->exec_request(&nxt_wasm_ctx);

    printf("**** content_len : %lu, content_sent : %lu\n",
           content_len, content_sent);
    if (content_len == content_sent) {
        printf("**** Going to request_done:\n");
        goto request_done;
    }

    wr->nr_fields = 0;
    wr->content_offs = offset = sizeof(nxt_wasm_request_t);
    for ( ; ; ) {
        read_bytes = nxt_min(content_len - content_sent,
                             NXT_WASM_MEM_SIZE - offset);
        printf("**** Reading %lu bytes from nxt_unit_request_read()\n",
               read_bytes);
        bytes_read = nxt_unit_request_read(req, (uint8_t *)wr + offset,
                                           read_bytes);
        printf("**** Got %ld from nxt_unit_request_read()\n", bytes_read);

        content_sent += bytes_read;
        wr->request_size = wr->content_sent = bytes_read;
        wr->total_content_sent = content_sent;

        printf("**** content_length : %lu, content_sent : %lu\n",
               content_len, content_sent);

        nxt_wops->exec_request(&nxt_wasm_ctx);

        if (content_len == content_sent) {
            break;
        }
    }

request_done:
    nxt_wops->meminfo(&nxt_wasm_ctx);

    NXT_WASM_DO_HOOK(NXT_WASM_FH_REQUEST_END);
}


static nxt_int_t
nxt_wasm_start(nxt_task_t *task, nxt_process_data_t *data)
{
    nxt_int_t              ret;
    nxt_unit_ctx_t         *unit_ctx;
    nxt_unit_init_t        wasm_init;
    nxt_common_app_conf_t  *conf;

    printf("%s: \n", __func__);

    conf = data->app;

    ret = nxt_unit_default_init(task, &wasm_init, conf);
    if (nxt_slow_path(ret != NXT_OK)) {
        nxt_alert(task, "nxt_unit_default_init() failed");
        return ret;
    }

    wasm_init.callbacks.request_handler = nxt_wasm_request_handler;

    unit_ctx = nxt_unit_init(&wasm_init);
    if (nxt_slow_path(unit_ctx == NULL)) {
        return NXT_ERROR;
    }

    NXT_WASM_DO_HOOK(NXT_WASM_FH_MODULE_INIT);
    nxt_unit_run(unit_ctx);
    nxt_unit_done(unit_ctx);
    NXT_WASM_DO_HOOK(NXT_WASM_FH_MODULE_END);

    if (nxt_wasm_ctx.dirs != NULL) {
        char  **p;

        for (p = nxt_wasm_ctx.dirs; *p != NULL; p++) {
            nxt_free(*p);
        }
        nxt_free(nxt_wasm_ctx.dirs);
    }

    nxt_wops->destroy(&nxt_wasm_ctx);

    exit(EXIT_SUCCESS);
}


static nxt_int_t
nxt_wasm_setup(nxt_task_t *task, nxt_process_t *process,
               nxt_common_app_conf_t *conf)
{
    int                      n, i, err;
    nxt_conf_value_t         *dirs = NULL;
    nxt_wasm_app_conf_t      *c;
    nxt_wasm_func_handler_t  *fh;
    static nxt_str_t         filesystem_str = nxt_string("filesystem");

    c = &conf->u.wasm;

    printf("%s: loading wasm module %s\n", __func__, c->module);

    nxt_wops = &wasm_ops;

    nxt_wasm_ctx.module_path = c->module;

    fh = nxt_wasm_ctx.fh;

    fh[NXT_WASM_FH_REQUEST].func_name = c->request_handler;
    fh[NXT_WASM_FH_MALLOC].func_name = c->malloc_handler;
    fh[NXT_WASM_FH_FREE].func_name = c->free_handler;

    /* Optional function handlers (hooks) */
    fh[NXT_WASM_FH_MODULE_INIT].func_name = c->module_init_handler;
    fh[NXT_WASM_FH_MODULE_END].func_name = c->module_end_handler;
    fh[NXT_WASM_FH_REQUEST_INIT].func_name = c->request_init_handler;
    fh[NXT_WASM_FH_REQUEST_END].func_name = c->request_end_handler;
    fh[NXT_WASM_FH_RESPONSE_END].func_name = c->response_end_handler;

    /* Get any directories to pass through to the WASM module */
    if (c->access != NULL) {
        dirs = nxt_conf_get_object_member(c->access, &filesystem_str, NULL);
    }

    n = (dirs != NULL) ? nxt_conf_object_members_count(dirs) : 0;
    if (n == 0) {
        goto out_init;
    }

    nxt_wasm_ctx.dirs = nxt_zalloc((n + 1) * sizeof(char *));
    if (nxt_slow_path(nxt_wasm_ctx.dirs == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < n; i++) {
        nxt_str_t         str;
        nxt_conf_value_t  *value;

        value = nxt_conf_get_array_element(dirs, i);
        nxt_conf_get_string(value, &str);

        nxt_wasm_ctx.dirs[i] = nxt_zalloc(str.length + 1);
        nxt_cpymem(nxt_wasm_ctx.dirs[i], str.start, str.length);
    }

out_init:
    err = nxt_wops->init(&nxt_wasm_ctx);
    if (err) {
        exit(EXIT_FAILURE);
    }

    return NXT_OK;
}


static uint32_t  compat[] = {
    NXT_VERNUM, NXT_DEBUG,
};


NXT_EXPORT nxt_app_module_t  nxt_app_module = {
    .compat_length  = sizeof(compat),
    .compat         = compat,
    .type           = nxt_string("wasm"),
    .version        = NXT_WASM_VERSION,
    .mounts         = NULL,
    .nmounts        = 0,
    .setup          = nxt_wasm_setup,
    .start          = nxt_wasm_start,
};
