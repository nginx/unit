
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


struct nxt_js_s {
    uint32_t            index;
};


typedef struct {
    nxt_str_t           name;
    nxt_str_t           text;
} nxt_js_module_t;


struct nxt_js_conf_s {
    nxt_mp_t            *pool;
    njs_vm_t            *vm;
    njs_uint_t          protos;
    njs_external_t      *proto;
    nxt_str_t           init;
    nxt_array_t         *modules;  /* of nxt_js_module_t */
    nxt_array_t         *funcs;
    uint8_t             test;  /* 1 bit */
};


njs_mod_t *
nxt_js_module_loader(njs_vm_t *vm, njs_external_ptr_t external, njs_str_t *name)
{
    nxt_str_t        text;
    nxt_uint_t       i, n;
    nxt_js_conf_t    *jcf;
    nxt_js_module_t  *modules, *module;

    jcf = external;

    module = NULL;

    n = jcf->modules->nelts;
    modules = jcf->modules->elts;

    for (i = 0; i < n; i++) {
        if (nxt_strstr_eq(name, &modules[i].name)) {
            module = &modules[i];
            break;
        }
    }

    if (module == NULL) {
        return NULL;
    }

    text.length = module->text.length;

    text.start = njs_mp_alloc(vm->mem_pool, text.length);
    if (nxt_slow_path(text.start == NULL)) {
        return NULL;
    }

    nxt_memcpy(text.start, module->text.start, text.length);

    return njs_vm_compile_module(vm, name, &text.start,
                                 &text.start[text.length]);
}


njs_int_t  nxt_js_proto_id;


nxt_js_conf_t *
nxt_js_conf_new(nxt_mp_t *mp, nxt_bool_t test)
{
    nxt_js_conf_t  *jcf;

    jcf = nxt_mp_zget(mp, sizeof(nxt_js_conf_t));
    if (nxt_slow_path(jcf == NULL)) {
        return NULL;
    }

    jcf->pool = mp;
    jcf->test = test;

    jcf->modules = nxt_array_create(mp, 4, sizeof(nxt_js_module_t));
    if (nxt_slow_path(jcf->modules == NULL)) {
        return NULL;
    }

    jcf->funcs = nxt_array_create(mp, 4, sizeof(nxt_str_t));
    if (nxt_slow_path(jcf->funcs == NULL)) {
        return NULL;
    }

    return jcf;
}


void
nxt_js_conf_release(nxt_js_conf_t *jcf)
{
    njs_vm_destroy(jcf->vm);
}


void
nxt_js_set_proto(nxt_js_conf_t *jcf, njs_external_t *proto, njs_uint_t n)
{
    jcf->protos = n;
    jcf->proto = proto;
}


static njs_vm_t *
nxt_js_vm_create(nxt_js_conf_t *jcf)
{
    u_char           *p;
    size_t           size;
    njs_vm_t         *vm;
    nxt_uint_t       i;
    njs_vm_opt_t     opts;
    nxt_js_module_t  *module, *mod;

    static const nxt_str_t  import_str = nxt_string("import");
    static const nxt_str_t  from_str = nxt_string("from");
    static const nxt_str_t  global_str = nxt_string("globalThis");

    njs_vm_opt_init(&opts);

    opts.backtrace = 1;

    opts.file.start = (u_char *) "default";
    opts.file.length = 7;

    if (jcf->test || jcf->modules->nelts == 0) {
        goto done;
    }

    opts.external = jcf;

    size = 0;
    module = jcf->modules->elts;

    for (i = 0; i < jcf->modules->nelts; i++) {
        mod = &module[i];

        size += import_str.length + 1 + mod->name.length + 1
                + from_str.length + 2 + mod->name.length + 3;

        size += global_str.length + 1 + mod->name.length + 3
                + mod->name.length + 2;
    }

    p = nxt_mp_nget(jcf->pool, size);
    if (nxt_slow_path(p == NULL)) {
        return NULL;
    }

    jcf->init.length = size;
    jcf->init.start = p;

    for (i = 0; i < jcf->modules->nelts; i++) {
        mod = &module[i];

        p = nxt_cpymem(p, import_str.start, import_str.length);
        *p++ = ' ';

        p = nxt_cpymem(p, mod->name.start, mod->name.length);
        *p++ = ' ';

        p = nxt_cpymem(p, from_str.start, from_str.length);
        *p++ = ' ';

        *p++ = '\"';
        p = nxt_cpymem(p, mod->name.start, mod->name.length);
        *p++ = '\"';
        *p++ = ';';
        *p++ = '\n';

        p = nxt_cpymem(p, global_str.start, global_str.length);
        *p++ = '.';

        p = nxt_cpymem(p, mod->name.start, mod->name.length);
        *p++ = ' ';
        *p++ = '=';
        *p++ = ' ';

        p = nxt_cpymem(p, mod->name.start, mod->name.length);
        *p++ = ';';
        *p++ = '\n';
    }

done:

    vm = njs_vm_create(&opts);

    if (nxt_fast_path(vm != NULL)) {
        njs_vm_set_module_loader(vm, nxt_js_module_loader, jcf);
    }

    return vm;
}


nxt_int_t
nxt_js_add_module(nxt_js_conf_t *jcf, nxt_str_t *name, nxt_str_t *text)
{
    nxt_js_module_t  *module;

    module = nxt_array_add(jcf->modules);
    if (nxt_slow_path(module == NULL)) {
        return NXT_ERROR;
    }

    module->name = *name;

    module->text.length = text->length;
    module->text.start = nxt_mp_nget(jcf->pool, text->length);
    if (nxt_slow_path(module->text.start == NULL)) {
        return NXT_ERROR;
    }

    nxt_memcpy(module->text.start, text->start, text->length);

    return NXT_OK;
}


nxt_js_t *
nxt_js_add_tpl(nxt_js_conf_t *jcf, nxt_str_t *str, nxt_bool_t strz)
{
    size_t     size;
    u_char     *p, *start;
    nxt_js_t   *js;
    nxt_str_t  *func;

    static const nxt_str_t  func_str =
                                nxt_string("function(uri, host, remoteAddr, "
                                           "args, headers, cookies, vars) {"
                                           "    return ");

    /*
     * Appending a terminating null character if strz is true.
     */
    static const nxt_str_t  strz_str = nxt_string(" + '\\x00'");

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

    if (jcf->test) {
        return NXT_OK;
    }

    jcf->vm = nxt_js_vm_create(jcf);
    if (nxt_slow_path(jcf->vm == NULL)) {
        return NXT_ERROR;
    }

    size = jcf->init.length + 2;
    func = jcf->funcs->elts;

    for (i = 0; i < jcf->funcs->nelts; i++) {
        size += func[i].length + 1;
    }

    start = nxt_mp_nget(jcf->pool, size);
    if (nxt_slow_path(start == NULL)) {
        return NXT_ERROR;
    }

    p = nxt_cpymem(start, jcf->init.start, jcf->init.length);
    *p++ = '[';

    func = jcf->funcs->elts;

    for (i = 0; i < jcf->funcs->nelts; i++) {
        p = nxt_cpymem(p, func[i].start, func[i].length);
        *p++ = ',';
    }

    *p++ = ']';

    nxt_js_proto_id = njs_vm_external_prototype(jcf->vm, jcf->proto,
                                                jcf->protos);
    if (nxt_slow_path(nxt_js_proto_id < 0)) {
        return NXT_ERROR;
    }

    ret = njs_vm_compile(jcf->vm, &start, p);

    return (ret == NJS_OK) ? NXT_OK : NXT_ERROR;
}


nxt_int_t
nxt_js_test(nxt_js_conf_t *jcf, nxt_str_t *str, u_char *error)
{
    u_char     *start;
    njs_vm_t   *vm;
    njs_int_t  ret;

    vm = nxt_js_vm_create(jcf);
    if (nxt_slow_path(vm == NULL)) {
        return NXT_ERROR;
    }

    start = nxt_mp_nget(jcf->pool, str->length);
    if (nxt_slow_path(start == NULL)) {
        goto fail;
    }

    nxt_memcpy(start, str->start, str->length);

    ret = njs_vm_compile(vm, &start, start + str->length);

    if (nxt_slow_path(ret != NJS_OK)) {
        (void) nxt_js_error(vm, error);
        goto fail;
    }

    njs_vm_destroy(vm);

    return NXT_OK;

fail:

    njs_vm_destroy(vm);

    return NXT_ERROR;
}


nxt_int_t
nxt_js_call(nxt_task_t *task, nxt_js_conf_t *jcf, nxt_js_cache_t *cache,
    nxt_js_t *js, nxt_str_t *str, void *ctx)
{
    njs_vm_t            *vm;
    njs_int_t           ret;
    njs_str_t           res;
    njs_uint_t          i, n;
    njs_value_t         *value;
    njs_function_t      *func;
    njs_opaque_value_t  retval, opaque_value, arguments[7];

    static const njs_str_t  js_args[] = {
        njs_str("uri"),
        njs_str("host"),
        njs_str("remoteAddr"),
        njs_str("args"),
        njs_str("headers"),
        njs_str("cookies"),
        njs_str("vars"),
    };

    vm = cache->vm;

    if (vm == NULL) {
        vm = njs_vm_clone(jcf->vm, ctx);
        if (nxt_slow_path(vm == NULL)) {
            return NXT_ERROR;
        }

        cache->vm = vm;

        ret = njs_vm_start(vm, &cache->array);
        if (ret != NJS_OK) {
            return NXT_ERROR;
        }
    }

    value = njs_vm_array_prop(vm, &cache->array, js->index, &opaque_value);
    func = njs_value_function(value);

    ret = njs_vm_external_create(vm, njs_value_arg(&opaque_value),
                                 nxt_js_proto_id, ctx, 0);
    if (nxt_slow_path(ret != NJS_OK)) {
        return NXT_ERROR;
    }

    n = nxt_nitems(js_args);

    for (i = 0; i < n; i++) {
        value = njs_vm_object_prop(vm, njs_value_arg(&opaque_value),
                                   &js_args[i], &arguments[i]);
        if (nxt_slow_path(value == NULL)) {
            return NXT_ERROR;
        }
    }

    ret = njs_vm_invoke(vm, func, njs_value_arg(&arguments), n,
                        njs_value_arg(&retval));

    if (ret != NJS_OK) {
        ret = njs_vm_exception_string(vm, &res);
        if (ret == NJS_OK) {
            nxt_alert(task, "js exception: %V", &res);
        }

        return NXT_ERROR;
    }

    ret = njs_vm_value_string(vm, &res, njs_value_arg(&retval));

    str->length = res.length;
    str->start = res.start;

    return NXT_OK;
}


void
nxt_js_release(nxt_js_cache_t *cache)
{
    if (cache->vm != NULL) {
        njs_vm_destroy(cache->vm);
    }
}


nxt_int_t
nxt_js_error(njs_vm_t *vm, u_char *error)
{
    njs_int_t  ret;
    njs_str_t  res;
    nxt_str_t  err;

    ret = njs_vm_exception_string(vm, &res);
    if (nxt_slow_path(ret != NJS_OK)) {
        return NXT_ERROR;
    }

    err.start = res.start;
    err.length = res.length;

    nxt_sprintf(error, error + NXT_MAX_ERROR_STR, "\"%V\"%Z", &err);

    return NXT_OK;
}
