
/*
 * Copyright (C) Zhidao HONG
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>


typedef struct {
    nxt_str_t               name;
    nxt_tstr_t              *value;
} nxt_http_header_val_t;


nxt_int_t
nxt_http_set_headers_init(nxt_router_conf_t *rtcf, nxt_http_action_t *action,
     nxt_http_action_conf_t *acf)
 {
    uint32_t               next;
    nxt_str_t              str, name;
    nxt_array_t            *headers;
    nxt_conf_value_t       *value;
    nxt_http_header_val_t  *hv;

    headers = nxt_array_create(rtcf->mem_pool, 4,
                               sizeof(nxt_http_header_val_t));
    if (nxt_slow_path(headers == NULL)) {
        return NXT_ERROR;
    }

    action->set_headers = headers;

    next = 0;

    for ( ;; ) {
        value = nxt_conf_next_object_member(acf->set_headers, &name, &next);
        if (value == NULL) {
            break;
        }

        hv = nxt_array_zero_add(headers);
        if (nxt_slow_path(hv == NULL)) {
            return NXT_ERROR;
        }

        hv->name.length = name.length;

        hv->name.start = nxt_mp_nget(rtcf->mem_pool, name.length);
        if (nxt_slow_path(hv->name.start == NULL)) {
            return NXT_ERROR;
        }

        nxt_memcpy(hv->name.start, name.start, name.length);

        if (nxt_conf_type(value) == NXT_CONF_STRING) {
            nxt_conf_get_string(value, &str);

            hv->value = nxt_tstr_compile(rtcf->tstr_state, &str, 0);
            if (nxt_slow_path(hv->value == NULL)) {
                return NXT_ERROR;
            }
        }
    }

    return NXT_OK;
}


static nxt_http_field_t *
nxt_http_resp_header_find(nxt_http_request_t *r, u_char *name, size_t length)
{
    nxt_http_field_t  *f;

    nxt_list_each(f, r->resp.fields) {

        if (f->skip) {
            continue;
        }

        if (length == f->name_length
            && nxt_memcasecmp(name, f->name, f->name_length) == 0)
        {
            return f;
        }

    } nxt_list_loop;

    return NULL;
}


nxt_int_t
nxt_http_set_headers(nxt_http_request_t *r)
{
    nxt_int_t              ret;
    nxt_uint_t             i, n;
    nxt_str_t              *value;
    nxt_http_field_t       *f;
    nxt_router_conf_t      *rtcf;
    nxt_http_action_t      *action;
    nxt_http_header_val_t  *hv, *header;

    action = r->action;

    if (action == NULL || action->set_headers == NULL) {
        return NXT_OK;
    }

    if ((r->status < NXT_HTTP_OK || r->status >= NXT_HTTP_BAD_REQUEST)) {
        return NXT_OK;
    }

    rtcf = r->conf->socket_conf->router_conf;

    header = action->set_headers->elts;
    n = action->set_headers->nelts;

    value = nxt_mp_zalloc(r->mem_pool, sizeof(nxt_str_t) * n);
    if (nxt_slow_path(value == NULL)) {
        return NXT_ERROR;
    }

    for (i = 0; i < n; i++) {
        hv = &header[i];

        if (hv->value == NULL) {
            continue;
        }

        if (nxt_tstr_is_const(hv->value)) {
            nxt_tstr_str(hv->value, &value[i]);

        } else {
            ret = nxt_tstr_query_init(&r->tstr_query, rtcf->tstr_state,
                                      &r->tstr_cache, r, r->mem_pool);
            if (nxt_slow_path(ret != NXT_OK)) {
                return NXT_ERROR;
            }

            nxt_tstr_query(&r->task, r->tstr_query, hv->value, &value[i]);

            if (nxt_slow_path(nxt_tstr_query_failed(r->tstr_query))) {
                return NXT_ERROR;
            }
        }
    }

    for (i = 0; i < n; i++) {
        hv = &header[i];

        f = nxt_http_resp_header_find(r, hv->name.start, hv->name.length);

        if (value[i].start != NULL) {

            if (f == NULL) {
                f = nxt_list_zero_add(r->resp.fields);
                if (nxt_slow_path(f == NULL)) {
                    return NXT_ERROR;
                }

                f->name = hv->name.start;
                f->name_length = hv->name.length;
            }

            f->value = value[i].start;
            f->value_length = value[i].length;

        } else if (f != NULL) {
            f->skip = 1;
        }
    }

    return NXT_OK;
}
