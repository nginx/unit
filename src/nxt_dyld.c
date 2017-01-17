
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_main.h>


nxt_int_t
nxt_dyld_load(nxt_dyld_t *dyld)
{
    const char  *err;

    dyld->handle = dlopen(dyld->name, RTLD_NOW | RTLD_GLOBAL);

    if (dyld->handle != NULL) {
        nxt_thread_log_debug("dlopen(\"%s\")", dyld->name);
        return NXT_OK;
    }

    err = dlerror();
    if (err == NULL) {
        err = "(null)";
    }

    nxt_thread_log_alert("dlopen(\"%s\") failed: %s", dyld->name, err);

    return NXT_ERROR;
}


void *
nxt_dyld_symbol(nxt_dyld_t *dyld, const char *symbol)
{
    void        *handle, *s;
    const char  *name;
    const char  *err;

    if (dyld == NXT_DYLD_ANY) {
        handle = RTLD_DEFAULT;
        name = "RTLD_DEFAULT";

    } else {
        handle = dyld->handle;
        name = dyld->name;
    }

    s = dlsym(handle, symbol);

    if (s != NULL) {
        nxt_thread_log_debug("dlsym(\"%s\", \"%s\")", name, symbol);
        return s;
    }

    err = dlerror();
    if (err == NULL) {
        err = "(null)";
    }

    nxt_thread_log_alert("dlsym(\"%s\", \"%s\") failed: %s", name, symbol, err);

    return s;
}


nxt_int_t
nxt_dyld_unload(nxt_dyld_t *dyld)
{
    const char  *err;

    if (dlclose(dyld->handle) == 0) {
        nxt_thread_log_debug("dlclose(\"%s\")", dyld->name);
        return NXT_OK;
    }

    err = dlerror();

    if (err == NULL) {
        err = "(null)";
    }

    nxt_thread_log_alert("dlclose(\"%s\") failed: %s", dyld->name, err);

    return NXT_ERROR;
}
