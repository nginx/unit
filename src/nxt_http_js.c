
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_router.h>
#include <nxt_http.h>
#include <njs.h>


static njs_int_t nxt_http_js_ext_uri(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval);
static njs_int_t nxt_http_js_ext_host(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval);
static njs_int_t nxt_http_js_ext_remote_addr(njs_vm_t *vm,
    njs_object_prop_t *prop, njs_value_t *value, njs_value_t *setval,
    njs_value_t *retval);
static njs_int_t nxt_http_js_ext_get_args(njs_vm_t *vm,
    njs_object_prop_t *prop, njs_value_t *value, njs_value_t *setval,
    njs_value_t *retval);
static njs_int_t nxt_http_js_ext_get_header(njs_vm_t *vm,
    njs_object_prop_t *prop, njs_value_t *value, njs_value_t *setval,
    njs_value_t *retval);
static njs_int_t nxt_http_js_ext_keys_header(njs_vm_t *vm,
    njs_value_t *value, njs_value_t *keys);
static njs_int_t nxt_http_js_ext_get_cookie(njs_vm_t *vm,
    njs_object_prop_t *prop, njs_value_t *value, njs_value_t *setval,
    njs_value_t *retval);
static njs_int_t nxt_http_js_ext_keys_cookie(njs_vm_t *vm, njs_value_t *value,
    njs_value_t *keys);
static njs_int_t nxt_http_js_ext_get_var(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval);


static njs_external_t  nxt_http_js_proto[] = {
    {
        .flags = NJS_EXTERN_PROPERTY,
        .name.string = njs_str("uri"),
        .enumerable = 1,
        .u.property = {
            .handler = nxt_http_js_ext_uri,
        }
    },

    {
        .flags = NJS_EXTERN_PROPERTY,
        .name.string = njs_str("host"),
        .enumerable = 1,
        .u.property = {
            .handler = nxt_http_js_ext_host,
        }
    },

    {
        .flags = NJS_EXTERN_PROPERTY,
        .name.string = njs_str("remoteAddr"),
        .enumerable = 1,
        .u.property = {
            .handler = nxt_http_js_ext_remote_addr,
        }
    },

    {
        .flags = NJS_EXTERN_PROPERTY,
        .name.string = njs_str("args"),
        .enumerable = 1,
        .u.property = {
            .handler = nxt_http_js_ext_get_args,
        }
    },

    {
        .flags = NJS_EXTERN_OBJECT,
        .name.string = njs_str("headers"),
        .enumerable = 1,
        .u.object = {
            .enumerable = 1,
            .prop_handler = nxt_http_js_ext_get_header,
            .keys = nxt_http_js_ext_keys_header,
        }
    },

    {
        .flags = NJS_EXTERN_OBJECT,
        .name.string = njs_str("cookies"),
        .enumerable = 1,
        .u.object = {
            .enumerable = 1,
            .prop_handler = nxt_http_js_ext_get_cookie,
            .keys = nxt_http_js_ext_keys_cookie,
        }
    },

    {
        .flags = NJS_EXTERN_OBJECT,
        .name.string = njs_str("vars"),
        .u.object = {
            .prop_handler = nxt_http_js_ext_get_var,
        }
    },
};


void
nxt_http_register_js_proto(nxt_js_conf_t *jcf)
{
    nxt_js_set_proto(jcf, nxt_http_js_proto, njs_nitems(nxt_http_js_proto));
}


static njs_int_t
nxt_http_js_ext_uri(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    nxt_http_request_t  *r;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    return njs_vm_value_string_set(vm, retval, r->path->start, r->path->length);
}


static njs_int_t
nxt_http_js_ext_host(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    nxt_http_request_t  *r;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    return njs_vm_value_string_set(vm, retval, r->host.start, r->host.length);
}


static njs_int_t
nxt_http_js_ext_remote_addr(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    nxt_http_request_t  *r;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    return njs_vm_value_string_set(vm, retval,
                                   nxt_sockaddr_address(r->remote),
                                   r->remote->address_length);
}


static njs_int_t
nxt_http_js_ext_get_args(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    u_char              *start;
    njs_int_t           ret;
    njs_value_t         *args;
    njs_opaque_value_t  val;
    nxt_http_request_t  *r;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    args = njs_value_arg(&val);

    start = (r->args->start != NULL) ? r->args->start : (u_char *) "";
    ret = njs_vm_query_string_parse(vm, start, start + r->args->length, args);

    if (ret == NJS_ERROR) {
        return NJS_ERROR;
    }

    njs_value_assign(retval, args);

    return NJS_OK;
}


static njs_int_t
nxt_http_js_ext_get_header(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    njs_int_t           rc;
    njs_str_t           key;
    nxt_http_field_t    *f;
    nxt_http_request_t  *r;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    rc = njs_vm_prop_name(vm, prop, &key);
    if (rc != NJS_OK) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    nxt_list_each(f, r->fields) {

        if (key.length == f->name_length
            && memcmp(key.start, f->name, f->name_length) == 0)
        {
            return njs_vm_value_string_set(vm, retval, f->value,
                                           f->value_length);
        }

    } nxt_list_loop;

    njs_value_undefined_set(retval);

    return NJS_DECLINED;
}


static njs_int_t
nxt_http_js_ext_keys_header(njs_vm_t *vm, njs_value_t *value, njs_value_t *keys)
{
    njs_int_t           rc;
    nxt_http_field_t    *f;
    nxt_http_request_t  *r;

    rc = njs_vm_array_alloc(vm, keys, 4);
    if (rc != NJS_OK) {
        return NJS_ERROR;
    }

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        return NJS_OK;
    }

    nxt_list_each(f, r->fields) {

        value = njs_vm_array_push(vm, keys);
        if (value == NULL) {
            return NJS_ERROR;
        }

        rc = njs_vm_value_string_set(vm, value, f->name, f->name_length);
        if (rc != NJS_OK) {
            return NJS_ERROR;
        }

    } nxt_list_loop;

    return NJS_OK;
}


static njs_int_t
nxt_http_js_ext_get_cookie(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    njs_int_t              rc;
    njs_str_t              key;
    nxt_array_t            *cookies;
    nxt_http_request_t     *r;
    nxt_http_name_value_t  *nv, *start, *end;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    rc = njs_vm_prop_name(vm, prop, &key);
    if (rc != NJS_OK) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    cookies = nxt_http_cookies_parse(r);
    if (nxt_slow_path(cookies == NULL)) {
        return NJS_ERROR;
    }

    start = cookies->elts;
    end = start + cookies->nelts;

    for (nv = start; nv < end; nv++) {

        if (key.length == nv->name_length
            && memcmp(key.start, nv->name, nv->name_length) == 0)
        {
            return njs_vm_value_string_set(vm, retval, nv->value,
                                           nv->value_length);
        }
    }

    njs_value_undefined_set(retval);

    return NJS_DECLINED;
}


static njs_int_t
nxt_http_js_ext_keys_cookie(njs_vm_t *vm, njs_value_t *value, njs_value_t *keys)
{
    njs_int_t              rc;
    nxt_array_t            *cookies;
    nxt_http_request_t     *r;
    nxt_http_name_value_t  *nv, *start, *end;

    rc = njs_vm_array_alloc(vm, keys, 4);
    if (rc != NJS_OK) {
        return NJS_ERROR;
    }

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        return NJS_OK;
    }

    cookies = nxt_http_cookies_parse(r);
    if (nxt_slow_path(cookies == NULL)) {
        return NJS_ERROR;
    }

    start = cookies->elts;
    end = start + cookies->nelts;

    for (nv = start; nv < end; nv++) {

        value = njs_vm_array_push(vm, keys);
        if (value == NULL) {
            return NJS_ERROR;
        }

        rc = njs_vm_value_string_set(vm, value, nv->name, nv->name_length);
        if (rc != NJS_OK) {
            return NJS_ERROR;
        }
    }

    return NJS_OK;
}


static njs_int_t
nxt_http_js_ext_get_var(njs_vm_t *vm, njs_object_prop_t *prop,
    njs_value_t *value, njs_value_t *setval, njs_value_t *retval)
{
    njs_int_t           rc;
    njs_str_t           key;
    nxt_str_t           name, *vv;
    nxt_router_conf_t   *rtcf;
    nxt_http_request_t  *r;

    r = njs_vm_external(vm, nxt_js_proto_id, value);
    if (r == NULL) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    rc = njs_vm_prop_name(vm, prop, &key);
    if (rc != NJS_OK) {
        njs_value_undefined_set(retval);
        return NJS_DECLINED;
    }

    rtcf = r->conf->socket_conf->router_conf;

    name.start = key.start;
    name.length = key.length;

    vv = nxt_var_get(&r->task, rtcf->tstr_state, &r->tstr_cache.var, &name, r);

    if (vv != NULL) {
        return njs_vm_value_string_set(vm, retval, vv->start, vv->length);
    }

    njs_value_undefined_set(retval);

    return NJS_DECLINED;
}
