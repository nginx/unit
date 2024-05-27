
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <nxt_clang.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>


#define CONTENT_TYPE  "Content-Type"
#define TEXT_PLAIN    "text/plain"
#define HELLO_WORLD   "Hello world!\n"

#define NEW_LINE      "\n"

#define REQUEST_DATA  "Request data:\n"
#define METHOD        "  Method: "
#define PROTOCOL      "  Protocol: "
#define REMOTE_ADDR   "  Remote addr: "
#define LOCAL_ADDR    "  Local addr: "
#define TARGET        "  Target: "
#define PATH          "  Path: "
#define QUERY         "  Query: "
#define FIELDS        "  Fields:\n"
#define FIELD_PAD     "    "
#define FIELD_SEP     ": "
#define BODY          "  Body:\n"


static int ready_handler(nxt_unit_ctx_t *ctx);
static void *worker(void *main_ctx);
static void greeting_app_request_handler(nxt_unit_request_info_t *req);
static inline char *copy(char *p, const void *src, uint32_t len);


static int        thread_count;
static pthread_t  *threads;


int
main(int argc, char **argv)
{
    int              i, err;
    nxt_unit_ctx_t   *ctx;
    nxt_unit_init_t  init;

    if (argc == 3 && strcmp(argv[1], "-t") == 0) {
        thread_count = atoi(argv[2]);
    }

    memset(&init, 0, sizeof(nxt_unit_init_t));

    init.callbacks.request_handler = greeting_app_request_handler;
    init.callbacks.ready_handler = ready_handler;

    ctx = nxt_unit_init(&init);
    if (ctx == NULL) {
        return 1;
    }

    err = nxt_unit_run(ctx);

    nxt_unit_debug(ctx, "main worker finished with %d code", err);

    if (thread_count > 1) {
        for (i = 0; i < thread_count - 1; i++) {
            err = pthread_join(threads[i], NULL);

            if (nxt_fast_path(err == 0)) {
                nxt_unit_debug(ctx, "join thread #%d", i);

            } else {
                nxt_unit_alert(ctx, "pthread_join(#%d) failed: %s (%d)",
                                    i, strerror(err), err);
            }
        }

        nxt_unit_free(ctx, threads);
    }

    nxt_unit_done(ctx);

    nxt_unit_debug(NULL, "main worker done");

    return 0;
}


static int
ready_handler(nxt_unit_ctx_t *ctx)
{
    int  i, err;

    nxt_unit_debug(ctx, "ready");

    if (thread_count <= 1) {
        return NXT_UNIT_OK;
    }

    threads = nxt_unit_malloc(ctx, sizeof(pthread_t) * (thread_count - 1));
    if (threads == NULL) {
        return NXT_UNIT_ERROR;
    }

    for (i = 0; i < thread_count - 1; i++) {
        err = pthread_create(&threads[i], NULL, worker, ctx);
        if (err != 0) {
            return NXT_UNIT_ERROR;
        }
    }

    return NXT_UNIT_OK;
}


static void *
worker(void *main_ctx)
{
    int             rc;
    nxt_unit_ctx_t  *ctx;

    ctx = nxt_unit_ctx_alloc(main_ctx, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    nxt_unit_debug(ctx, "start worker");

    rc = nxt_unit_run(ctx);

    nxt_unit_debug(ctx, "worker finished with %d code", rc);

    nxt_unit_done(ctx);

    return (void *) (intptr_t) rc;
}


static void
greeting_app_request_handler(nxt_unit_request_info_t *req)
{
    int                 rc;
    char                *p;
    ssize_t             res;
    uint32_t            i;
    nxt_unit_buf_t      *buf;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    rc = nxt_unit_response_init(req, 200 /* Status code. */,
                                1 /* Number of response headers. */,
                                nxt_length(CONTENT_TYPE)
                                + nxt_length(TEXT_PLAIN)
                                + nxt_length(HELLO_WORLD));
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_unit_response_add_field(req,
                                     CONTENT_TYPE, nxt_length(CONTENT_TYPE),
                                     TEXT_PLAIN, nxt_length(TEXT_PLAIN));
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_unit_response_add_content(req, HELLO_WORLD,
                                       nxt_length(HELLO_WORLD));
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    rc = nxt_unit_response_send(req);
    if (nxt_slow_path(rc != NXT_UNIT_OK)) {
        goto fail;
    }

    r = req->request;

    buf = nxt_unit_response_buf_alloc(req, (req->request_buf->end
                                            - req->request_buf->start)
                                      + nxt_length(REQUEST_DATA)
                                      + nxt_length(METHOD)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(PROTOCOL)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(REMOTE_ADDR)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(LOCAL_ADDR)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(TARGET)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(PATH)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(QUERY)
                                      + nxt_length(NEW_LINE)
                                      + nxt_length(FIELDS)
                                      + r->fields_count * (
                                          nxt_length(FIELD_PAD)
                                          + nxt_length(FIELD_SEP))
                                      + nxt_length(BODY));
    if (nxt_slow_path(buf == NULL)) {
        rc = NXT_UNIT_ERROR;

        goto fail;
    }

    p = buf->free;

    p = copy(p, REQUEST_DATA, nxt_length(REQUEST_DATA));

    p = copy(p, METHOD, nxt_length(METHOD));
    p = copy(p, nxt_unit_sptr_get(&r->method), r->method_length);
    *p++ = '\n';

    p = copy(p, PROTOCOL, nxt_length(PROTOCOL));
    p = copy(p, nxt_unit_sptr_get(&r->version), r->version_length);
    *p++ = '\n';

    p = copy(p, REMOTE_ADDR, nxt_length(REMOTE_ADDR));
    p = copy(p, nxt_unit_sptr_get(&r->remote), r->remote_length);
    *p++ = '\n';

    p = copy(p, LOCAL_ADDR, nxt_length(LOCAL_ADDR));
    p = copy(p, nxt_unit_sptr_get(&r->local_addr), r->local_addr_length);
    *p++ = '\n';

    p = copy(p, TARGET, nxt_length(TARGET));
    p = copy(p, nxt_unit_sptr_get(&r->target), r->target_length);
    *p++ = '\n';

    p = copy(p, PATH, nxt_length(PATH));
    p = copy(p, nxt_unit_sptr_get(&r->path), r->path_length);
    *p++ = '\n';

    if (r->query.offset) {
        p = copy(p, QUERY, nxt_length(QUERY));
        p = copy(p, nxt_unit_sptr_get(&r->query), r->query_length);
        *p++ = '\n';
    }

    p = copy(p, FIELDS, nxt_length(FIELDS));

    for (i = 0; i < r->fields_count; i++) {
        f = r->fields + i;

        p = copy(p, FIELD_PAD, nxt_length(FIELD_PAD));
        p = copy(p, nxt_unit_sptr_get(&f->name), f->name_length);
        p = copy(p, FIELD_SEP, nxt_length(FIELD_SEP));
        p = copy(p, nxt_unit_sptr_get(&f->value), f->value_length);
        *p++ = '\n';
    }

    if (r->content_length > 0) {
        p = copy(p, BODY, nxt_length(BODY));

        res = nxt_unit_request_read(req, p, buf->end - p);
        p += res;

    }

    buf->free = p;

    rc = nxt_unit_buf_send(buf);

fail:

    nxt_unit_request_done(req, rc);
}


static inline char *
copy(char *p, const void *src, uint32_t len)
{
    memcpy(p, src, len);

    return p + len;
}
