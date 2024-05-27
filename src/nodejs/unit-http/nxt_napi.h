
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_NODEJS_NAPI_H_INCLUDED_
#define _NXT_NODEJS_NAPI_H_INCLUDED_

#include <node_api.h>


#ifdef __cplusplus
extern "C" {
#endif

#include "version.h"
#include <nxt_unit.h>

#if NXT_VERNUM != NXT_NODE_VERNUM
#error "libunit version mismatch."
#endif

#include <nxt_unit_response.h>
#include <nxt_unit_request.h>


#ifdef __cplusplus
} /* extern "C" */
#endif


struct nxt_napi {

    struct exception {
        exception(const char *s) : str(s) { }

        const char *str;
    };


    nxt_napi(napi_env env) : env_(env) { }


    inline napi_value
    coerce_to_string(napi_value val)
    {
        napi_value   res;
        napi_status  status;

        status = napi_coerce_to_string(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to coerce to string");
        }

        return res;
    }


    inline napi_value
    create_buffer(size_t size, void **data)
    {
        napi_value   res;
        napi_status  status;

        status = napi_create_buffer(env_, size, data, &res);
        if (status != napi_ok) {
            throw exception("Failed to create buffer");
        }

        return res;
    }


    inline napi_value
    create_function(const char *name, size_t len, napi_callback cb, void *data)
    {
        napi_value   res;
        napi_status  status;

        status = napi_create_function(env_, name, len, cb, data, &res);
        if (status != napi_ok) {
            throw exception("Failed to create function");
        }

        return res;
    }


    inline napi_value
    create_function(napi_callback cb)
    {
        return create_function(NULL, 0, cb, NULL);
    }


    inline napi_value
    create_object()
    {
        napi_value   res;
        napi_status  status;

        status = napi_create_object(env_, &res);
        if (status != napi_ok) {
            throw exception("Failed to create object");
        }

        return res;
    }


    inline napi_ref
    create_reference(napi_value val, int ref_count = 1)
    {
        napi_ref     res;
        napi_status  status;

        status = napi_create_reference(env_, val, ref_count, &res);
        if (status != napi_ok) {
            throw exception("Failed to create reference");
        }

        return res;
    }


    inline napi_value
    create_string_latin1(const char *str, size_t len)
    {
        napi_value   res;
        napi_status  status;

        status = napi_create_string_latin1(env_, str, len, &res);
        if (status != napi_ok) {
            throw exception("Failed to create latin1 string");
        }

        return res;
    }


    inline napi_value
    create_string_latin1(nxt_unit_sptr_t &str, size_t len)
    {
        const char  *p;

        p = (const char *) nxt_unit_sptr_get(&str);

        return create_string_latin1(p, len);
    }


    inline napi_value
    define_class(const char *name, napi_callback ctor, size_t prop_count,
        const napi_property_descriptor* props)
    {
        napi_value   res;
        napi_status  status;

        status = napi_define_class(env_, name, NAPI_AUTO_LENGTH, ctor, nullptr,
                                   prop_count, props, &res);
        if (status != napi_ok) {
            throw exception("Failed to define class");
        }

        return res;
    }


    inline void
    delete_reference(napi_ref ref)
    {
        napi_delete_reference(env_, ref);
    }


    inline uint32_t
    get_array_length(napi_value val)
    {
        uint32_t     res;
        napi_status  status;

        status = napi_get_array_length(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to get array length");
        }

        return res;
    }


    inline void *
    get_buffer_info(napi_value val, size_t &size)
    {
        void         *res;
        napi_status  status;

        status = napi_get_buffer_info(env_, val, &res, &size);
        if (status != napi_ok) {
            throw exception("Failed to get buffer info");
        }

        return res;
    }


    inline napi_value
    get_cb_info(napi_callback_info info, size_t &argc, napi_value *argv)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_cb_info(env_, info, &argc, argv, &res, nullptr);
        if (status != napi_ok) {
            throw exception("Failed to get arguments from js");
        }

        return res;
    }


    inline napi_value
    get_cb_info(napi_callback_info info)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_cb_info(env_, info, nullptr, nullptr, &res, nullptr);
        if (status != napi_ok) {
            throw exception("Failed to get arguments from js");
        }

        return res;
    }


    inline napi_value
    get_cb_info(napi_callback_info info, napi_value &arg)
    {
        size_t       argc;
        napi_value   res;

        argc = 1;
        res = get_cb_info(info, argc, &arg);

        if (argc != 1) {
            throw exception("Wrong args count. Expected 1");
        }

        return res;
    }


    inline napi_value
    get_element(napi_value obj, uint32_t i)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_element(env_, obj, i, &res);
        if (status != napi_ok) {
            throw exception("Failed to get element");
        }

        return res;
    }


    inline napi_value
    get_named_property(napi_value obj, const char *name)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_named_property(env_, obj, name, &res);
        if (status != napi_ok) {
            throw exception("Failed to get named property");
        }

        return res;
    }


    inline napi_value
    get_new_target(napi_callback_info info)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_new_target(env_, info, &res);
        if (status != napi_ok) {
            throw exception("Failed to get new target");
        }

        return res;
    }


    inline napi_value
    get_property(napi_value val, napi_value key)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_property(env_, val, key, &res);
        if (status != napi_ok) {
            throw exception("Failed to get property");
        }

        return res;
    }


    inline napi_value
    get_property_names(napi_value val)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_property_names(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to get property names");
        }

        return res;
    }


    inline napi_value
    get_reference_value(napi_ref ref)
    {
        napi_value   res;
        napi_status  status;

        status = napi_get_reference_value(env_, ref, &res);
        if (status != napi_ok) {
            throw exception("Failed to get reference value");
        }

        return res;
    }


    inline nxt_unit_request_info_t *
    get_request_info(napi_value obj)
    {
        return (nxt_unit_request_info_t *) unwrap(obj);
    }


    inline uint32_t
    get_value_bool(napi_value obj)
    {
        bool         res;
        napi_status  status;

        status = napi_get_value_bool(env_, obj, &res);
        if (status != napi_ok) {
            throw exception("Failed to get bool");
        }

        return res;
    }


    inline size_t
    get_value_string_latin1(napi_value val, char *buf, size_t bufsize)
    {
        size_t       res;
        napi_status  status;

        status = napi_get_value_string_latin1(env_, val, buf, bufsize, &res);
        if (status != napi_ok) {
            throw exception("Failed to get string latin1");
        }

        return res;
    }


    inline uint32_t
    get_value_uint32(napi_value obj)
    {
        uint32_t     res;
        napi_status  status;

        status = napi_get_value_uint32(env_, obj, &res);
        if (status != napi_ok) {
            throw exception("Failed to get uint32_t");
        }

        return res;
    }


    inline size_t
    get_value_string_utf8(napi_value val, char *buf, size_t bufsize)
    {
        size_t       res;
        napi_status  status;

        status = napi_get_value_string_utf8(env_, val, buf, bufsize, &res);
        if (status != napi_ok) {
            throw exception("Failed to get string utf8");
        }

        return res;
    }


    inline bool
    is_array(napi_value val)
    {
        bool         res;
        napi_status  status;

        status = napi_is_array(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to confirm value is array");
        }

        return res;
    }


    inline bool
    is_buffer(napi_value val)
    {
        bool         res;
        napi_status  status;

        status = napi_is_buffer(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to confirm value is buffer");
        }

        return res;
    }


    inline napi_value
    make_callback(napi_async_context ctx, napi_value val, napi_value func,
        int argc, const napi_value *argv)
    {
        napi_value   res, ex;
        napi_status  status;

        status = napi_make_callback(env_, ctx, val, func, argc, argv, &res);
        if (status != napi_ok) {
            if (status != napi_pending_exception) {
                throw exception("Failed to make callback");
            }

            status = napi_get_and_clear_last_exception(env_, &ex);
            if (status != napi_ok) {
                throw exception("Failed to get and clear last exception");
            }

            /* Logging a description of the error and call stack. */
            status = napi_fatal_exception(env_, ex);
            if (status != napi_ok) {
                throw exception("Failed napi_fatal_exception()");
            }
        }

        return res;
    }


    inline napi_value
    make_callback(napi_async_context ctx, napi_value val, napi_value func)
    {
        return make_callback(ctx, val, func, 0, NULL);
    }


    inline napi_value
    make_callback(napi_async_context ctx, napi_value val, napi_value func,
        napi_value arg1)
    {
        return make_callback(ctx, val, func, 1, &arg1);
    }


    inline napi_value
    make_callback(napi_async_context ctx, napi_value val, napi_value func,
        napi_value arg1, napi_value arg2)
    {
        napi_value  args[2] = { arg1, arg2 };

        return make_callback(ctx, val, func, 2, args);
    }


    inline napi_value
    make_callback(napi_async_context ctx, napi_value val, napi_value func,
        napi_value arg1, napi_value arg2, napi_value arg3)
    {
        napi_value  args[3] = { arg1, arg2, arg3 };

        return make_callback(ctx, val, func, 3, args);
    }


    inline napi_value
    new_instance(napi_value ctor)
    {
        napi_value   res;
        napi_status  status;

        status = napi_new_instance(env_, ctor, 0, NULL, &res);
        if (status != napi_ok) {
            throw exception("Failed to create instance");
        }

        return res;
    }


    inline napi_value
    new_instance(napi_value ctor, napi_value param)
    {
        napi_value   res;
        napi_status  status;

        status = napi_new_instance(env_, ctor, 1, &param, &res);
        if (status != napi_ok) {
            throw exception("Failed to create instance");
        }

        return res;
    }


    inline napi_value
    new_instance(napi_value ctor, napi_value param1, napi_value param2)
    {
        napi_value   res;
        napi_status  status;
        napi_value   param[2] = { param1, param2 };

        status = napi_new_instance(env_, ctor, 2, param, &res);
        if (status != napi_ok) {
            throw exception("Failed to create instance");
        }

        return res;
    }


    inline void
    set_element(napi_value obj, uint32_t i, napi_value val)
    {
        napi_status  status;

        status = napi_set_element(env_, obj, i, val);
        if (status != napi_ok) {
            throw exception("Failed to set element");
        }
    }


    inline void
    set_named_property(napi_value obj, const char *name, napi_value val)
    {
        napi_status  status;

        status = napi_set_named_property(env_, obj, name, val);
        if (status != napi_ok) {
            throw exception("Failed to set named property");
        }
    }


    inline void
    set_named_property(napi_value obj, const char *name, napi_callback cb)
    {
        set_named_property(obj, name, create_function(cb));
    }


    inline napi_value
    set_named_property(napi_value obj, const char *name, nxt_unit_sptr_t &val,
        size_t len)
    {
        napi_value  str;

        str = create_string_latin1(val, len);

        set_named_property(obj, name, str);

        return str;
    }


    template<typename T>
    inline void
    set_named_property(napi_value obj, const char *name, T val)
    {
        set_named_property(obj, name, create(val));
    }


    inline napi_value
    create(int32_t val)
    {
        napi_value   ptr;
        napi_status  status;

        status = napi_create_int32(env_, val, &ptr);
        if (status != napi_ok) {
            throw exception("Failed to create int32");
        }

        return ptr;
    }


    inline napi_value
    create(uint32_t val)
    {
        napi_value   ptr;
        napi_status  status;

        status = napi_create_uint32(env_, val, &ptr);
        if (status != napi_ok) {
            throw exception("Failed to create uint32");
        }

        return ptr;
    }


    inline napi_value
    create(int64_t val)
    {
        napi_value   ptr;
        napi_status  status;

        status = napi_create_int64(env_, val, &ptr);
        if (status != napi_ok) {
            throw exception("Failed to create int64");
        }

        return ptr;
    }


    inline void
    remove_wrap(napi_ref& ref)
    {
        if (ref != nullptr) {
            remove_wrap(get_reference_value(ref));
            ref = nullptr;
        }
    }


    inline void *
    remove_wrap(napi_value val)
    {
        void         *res;
        napi_status  status;

        status = napi_remove_wrap(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to remove_wrap");
        }

        return res;
    }


    inline void
    throw_error(const char *str)
    {
        napi_throw_error(env_, NULL, str);
    }


    inline void
    throw_error(const exception &e)
    {
        napi_throw_error(env_, NULL, e.str);
    }


    inline napi_valuetype
    type_of(napi_value val)
    {
        napi_status     status;
        napi_valuetype  res;

        status = napi_typeof(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to get typeof");
        }

        return res;
    }


    inline void *
    unwrap(napi_value val)
    {
        void         *res;
        napi_status  status;

        status = napi_unwrap(env_, val, &res);
        if (status != napi_ok) {
            throw exception("Failed to unwrap");
        }

        return res;
    }


    inline napi_ref
    wrap(napi_value val, void *obj, napi_finalize fin_cb, void *hint = nullptr)
    {
        napi_ref     res;
        napi_status  status;

        status = napi_wrap(env_, val, obj, fin_cb, hint, &res);
        if (status != napi_ok) {
            throw exception("Failed to wrap");
        }

        return res;
    }


    inline
    operator napi_env()
    {
        return env_;
    }


    napi_env env()
    {
        return env_;
    }

private:
    napi_env  env_;
};


struct nxt_handle_scope : public nxt_napi {
    nxt_handle_scope(napi_env env) : nxt_napi(env)
    {
        napi_status  status;

        status = napi_open_handle_scope(env, &scope_);
        if (status != napi_ok) {
            throw exception("Failed to open handle scope");
        }
    }

    ~nxt_handle_scope()
    {
        napi_status  status;

        status = napi_close_handle_scope(env(), scope_);
        if (status != napi_ok) {
            throw_error("Failed to close handle scope");
        }
    }

private:
    napi_handle_scope  scope_;
};


struct nxt_async_context : public nxt_napi {
    nxt_async_context(napi_env env, const char *name) :
        nxt_napi(env)
    {
        napi_value   name_val;
        napi_status  status;

        name_val = create_string_latin1(name, NAPI_AUTO_LENGTH);

        status = napi_async_init(env, NULL, name_val, &context_);
        if (status != napi_ok) {
            throw exception("Failed to init async object");
        }
    }

    operator napi_async_context() {
        return context_;
    }

    ~nxt_async_context()
    {
        napi_status  status;

        status = napi_async_destroy(env(), context_);
        if (status != napi_ok) {
            throw_error("Failed to destroy async object");
        }
    }

private:
    napi_async_context  context_;
};


struct nxt_callback_scope : public nxt_napi {
    nxt_callback_scope(nxt_async_context& ctx) :
        nxt_napi(ctx.env())
    {
        napi_value   resource;
        napi_status  status;

        resource = create_object();

        status = napi_open_callback_scope(env(), resource, ctx, &scope_);
        if (status != napi_ok) {
            throw exception("Failed to open callback scope");
        }
    }

    ~nxt_callback_scope()
    {
        napi_status  status;

        status = napi_close_callback_scope(env(), scope_);
        if (status != napi_ok) {
            throw_error("Failed to close callback scope");
        }
    }

private:
    napi_callback_scope  scope_;
};


#endif /* _NXT_NODEJS_NAPI_H_INCLUDED_ */
