
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


static nxt_int_t nxt_http_var_method(nxt_task_t *task, nxt_var_query_t *query,
    nxt_str_t *str, void *ctx);
static nxt_int_t nxt_http_var_uri(nxt_task_t *task, nxt_var_query_t *query,
    nxt_str_t *str, void *ctx);
static nxt_int_t nxt_http_var_host(nxt_task_t *task, nxt_var_query_t *query,
    nxt_str_t *str, void *ctx);


static nxt_var_decl_t  nxt_http_vars[] = {
    { nxt_string("method"),
      &nxt_http_var_method,
      0 },

    { nxt_string("uri"),
      &nxt_http_var_uri,
      0 },

    { nxt_string("host"),
      &nxt_http_var_host,
      0 },
};


nxt_int_t
nxt_http_register_variables(void)
{
    return nxt_var_register(nxt_http_vars, nxt_nitems(nxt_http_vars));
}


static nxt_int_t
nxt_http_var_method(nxt_task_t *task, nxt_var_query_t *query, nxt_str_t *str,
    void *ctx)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = *r->method;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_uri(nxt_task_t *task, nxt_var_query_t *query, nxt_str_t *str,
    void *ctx)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = *r->path;

    return NXT_OK;
}


static nxt_int_t
nxt_http_var_host(nxt_task_t *task, nxt_var_query_t *query, nxt_str_t *str,
    void *ctx)
{
    nxt_http_request_t  *r;

    r = ctx;

    *str = r->host;

    return NXT_OK;
}
