
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


struct nxt_js_s {
    uint32_t            index;
    njs_vm_t            *vm;
};


struct nxt_js_conf_s {
    nxt_mp_t            *pool;
    njs_vm_t            *vm;
    nxt_array_t         *funcs;
};


nxt_js_conf_t *
nxt_js_conf_new(nxt_mp_t *mp)
{
    njs_vm_opt_t   opts;
    nxt_js_conf_t  *jcf;

    jcf = nxt_mp_zget(mp, sizeof(nxt_js_conf_t));
    if (nxt_slow_path(jcf == NULL)) {
        return NULL;
    }

    jcf->pool = mp;

    njs_vm_opt_init(&opts);

    jcf->vm = njs_vm_create(&opts);
    if (nxt_slow_path(jcf->vm == NULL)) {
        return NULL;
    }

    jcf->funcs = nxt_array_create(mp, 4, sizeof(nxt_str_t));
    if (nxt_slow_path(jcf->funcs == NULL)) {
        return NULL;
    }

    return jcf;
}


nxt_js_t *
nxt_js_add_tpl(nxt_js_conf_t *jcf, nxt_str_t *str, nxt_bool_t strz)
{
    size_t     size;
    u_char     *p, *start;
    nxt_js_t   *js;
    nxt_str_t  *func;

    static nxt_str_t  func_str = nxt_string("function() {"
                                            "    return ");

    /*
     * Appending a terminating null character if strz is true.
     */
    static nxt_str_t  strz_str = nxt_string(" + '\\x00'");

    size = func_str.length + str->length + 1;

    if (strz) {
        size += strz_str.length;
    }

    start = nxt_mp_nget(jcf->pool, size);
    if (nxt_slow_path(start == NULL)) {
        return NULL;
    }

    p = start;

    p = nxt_cpymem(p, func_str.start, func_str.length);
    p = nxt_cpymem(p, str->start, str->length);

    if (strz) {
        p = nxt_cpymem(p, strz_str.start, strz_str.length);
    }

    *p++ = '}';

    js = nxt_mp_get(jcf->pool, sizeof(nxt_js_t));
    if (nxt_slow_path(js == NULL)) {
        return NULL;
    }

    js->vm = jcf->vm;

    func = nxt_array_add(jcf->funcs);
    if (nxt_slow_path(func == NULL)) {
        return NULL;
    }

    func->start = start;
    func->length = p - start;

    js->index = jcf->funcs->nelts - 1;

    return js;
}


nxt_int_t
nxt_js_compile(nxt_js_conf_t *jcf)
{
    size_t      size;
    u_char      *p, *start;
    njs_int_t   ret;
    nxt_str_t   *func;
    nxt_uint_t  i;

    size = 2;
    func = jcf->funcs->elts;

    for (i = 0; i < jcf->funcs->nelts; i++) {
        size += func[i].length + 1;
    }

    start = nxt_mp_nget(jcf->pool, size);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    p = start;
    *p++ = '[';

    func = jcf->funcs->elts;

    for (i = 0; i < jcf->funcs->nelts; i++) {
        p = nxt_cpymem(p, func[i].start, func[i].length);
        *p++ = ',';
    }

    *p++ = ']';

    ret = njs_vm_compile(jcf->vm, &start, p);

    return (ret == NJS_OK) ? NXT_OK : NXT_ERROR;
}


nxt_int_t
nxt_js_test(nxt_js_conf_t *jcf, nxt_str_t *str, u_char *error)
{
    u_char     *start;
    nxt_str_t  err;
    njs_int_t  ret;
    njs_str_t  res;

    start = nxt_mp_nget(jcf->pool, str->length);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    nxt_memcpy(start, str->start, str->length);

    ret = njs_vm_compile(jcf->vm, &start, start + str->length);

    if (nxt_slow_path(ret != NJS_OK)) {
        (void) njs_vm_retval_string(jcf->vm, &res);

        err.start = res.start;
        err.length = res.length;

        nxt_sprintf(error, error + NXT_MAX_ERROR_STR, "\"%V\"%Z", &err);

        return NXT_ERROR;
    }

    return NXT_OK;
}


nxt_int_t
nxt_js_call(nxt_task_t *task, nxt_js_cache_t *cache, nxt_js_t *js,
    nxt_str_t *str, void *ctx)
{
    njs_vm_t            *vm;
    njs_int_t           rc, ret;
    njs_str_t           res;
    njs_value_t         *array, *value;
    njs_function_t      *func;
    njs_opaque_value_t  opaque_value;

    vm = cache->vm;

    if (vm == NULL) {
        vm = njs_vm_clone(js->vm, ctx);
        if (nxt_slow_path(vm == NULL)) {
            return NXT_ERROR;
        }

        ret = njs_vm_start(vm);
        if (ret != NJS_OK) {
            return NXT_ERROR;
        }

        array = njs_vm_retval(vm);

        cache->vm = vm;
        cache->array = *array;
    }

    value = njs_vm_array_prop(vm, &cache->array, js->index, &opaque_value);
    func = njs_value_function(value);

    ret = njs_vm_call(vm, func, NULL, 0);

    rc = njs_vm_retval_string(vm, &res);
    if (rc != NJS_OK) {
        return NXT_ERROR;
    }

    if (ret != NJS_OK) {
        nxt_alert(task, "js exception: %V", &res);
        return NXT_ERROR;
    }

    str->length = res.length;
    str->start = res.start;

    return NXT_OK;
}
