
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <nxt_unit.h>
#include <nxt_unit_response.h>
#include <jni.h>
#include <stdio.h>

#include "nxt_jni.h"
#include "nxt_jni_Response.h"
#include "nxt_jni_HeadersEnumeration.h"
#include "nxt_jni_HeaderNamesEnumeration.h"
#include "nxt_jni_OutputStream.h"
#include "nxt_jni_URLClassLoader.h"


static jclass     nxt_java_Response_class;
static jmethodID  nxt_java_Response_ctor;


static void JNICALL nxt_java_Response_addHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name, jarray value);

static nxt_unit_request_info_t *nxt_java_get_response_info(
    jlong req_info_ptr, uint32_t extra_fields, uint32_t extra_data);

static void JNICALL nxt_java_Response_addIntHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name, jint value);

static void nxt_java_add_int_header(nxt_unit_request_info_t *req,
    const char *name, uint8_t name_len, int value);

static jboolean JNICALL nxt_java_Response_containsHeader(JNIEnv *env,
    jclass cls, jlong req_info_ptr, jarray name);

static jstring JNICALL nxt_java_Response_getHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name);

static jobject JNICALL nxt_java_Response_getHeaderNames(JNIEnv *env,
    jclass cls, jlong req_info_ptr);

static jobject JNICALL nxt_java_Response_getHeaders(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name);

static jint JNICALL nxt_java_Response_getStatus(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static jobject JNICALL nxt_java_Response_getRequest(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_commit(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_sendRedirect(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray loc);

static int nxt_java_response_set_header(jlong req_info_ptr,
    const char *name, jint name_len, const char *value, jint value_len);

static void JNICALL nxt_java_Response_setHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name, jarray value);

static void JNICALL nxt_java_Response_removeHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name);

static int nxt_java_response_remove_header(jlong req_info_ptr,
    const char *name, jint name_len);

static void JNICALL nxt_java_Response_setIntHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name, jint value);

static void JNICALL nxt_java_Response_setStatus(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jint sc);

static jstring JNICALL nxt_java_Response_getContentType(JNIEnv *env,
    jclass cls, jlong req_info_ptr);

static jboolean JNICALL nxt_java_Response_isCommitted(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_reset(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_resetBuffer(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_setBufferSize(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jint size);

static jint JNICALL nxt_java_Response_getBufferSize(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_setContentLength(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jlong len);

static void JNICALL nxt_java_Response_setContentType(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray type);

static void JNICALL nxt_java_Response_removeContentType(JNIEnv *env, jclass cls,
    jlong req_info_ptr);

static void JNICALL nxt_java_Response_log(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray msg);

static void JNICALL nxt_java_Response_trace(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray msg);

int
nxt_java_initResponse(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.Response");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_Response_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    cls = nxt_java_Response_class;

    nxt_java_Response_ctor = (*env)->GetMethodID(env, cls, "<init>", "(J)V");
    if (nxt_java_Response_ctor == NULL) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    JNINativeMethod resp_methods[] = {
        { (char *) "addHeader",
          (char *) "(J[B[B)V",
          nxt_java_Response_addHeader },

        { (char *) "addIntHeader",
          (char *) "(J[BI)V",
          nxt_java_Response_addIntHeader },

        { (char *) "containsHeader",
          (char *) "(J[B)Z",
          nxt_java_Response_containsHeader },

        { (char *) "getHeader",
          (char *) "(J[B)Ljava/lang/String;",
          nxt_java_Response_getHeader },

        { (char *) "getHeaderNames",
          (char *) "(J)Ljava/util/Enumeration;",
          nxt_java_Response_getHeaderNames },

        { (char *) "getHeaders",
          (char *) "(J[B)Ljava/util/Enumeration;",
          nxt_java_Response_getHeaders },

        { (char *) "getStatus",
          (char *) "(J)I",
          nxt_java_Response_getStatus },

        { (char *) "getRequest",
          (char *) "(J)Lnginx/unit/Request;",
          nxt_java_Response_getRequest },

        { (char *) "commit",
          (char *) "(J)V",
          nxt_java_Response_commit },

        { (char *) "sendRedirect",
          (char *) "(J[B)V",
          nxt_java_Response_sendRedirect },

        { (char *) "setHeader",
          (char *) "(J[B[B)V",
          nxt_java_Response_setHeader },

        { (char *) "removeHeader",
          (char *) "(J[B)V",
          nxt_java_Response_removeHeader },

        { (char *) "setIntHeader",
          (char *) "(J[BI)V",
          nxt_java_Response_setIntHeader },

        { (char *) "setStatus",
          (char *) "(JI)V",
          nxt_java_Response_setStatus },

        { (char *) "getContentType",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Response_getContentType },

        { (char *) "isCommitted",
          (char *) "(J)Z",
          nxt_java_Response_isCommitted },

        { (char *) "reset",
          (char *) "(J)V",
          nxt_java_Response_reset },

        { (char *) "resetBuffer",
          (char *) "(J)V",
          nxt_java_Response_resetBuffer },

        { (char *) "setBufferSize",
          (char *) "(JI)V",
          nxt_java_Response_setBufferSize },

        { (char *) "getBufferSize",
          (char *) "(J)I",
          nxt_java_Response_getBufferSize },

        { (char *) "setContentLength",
          (char *) "(JJ)V",
          nxt_java_Response_setContentLength },

        { (char *) "setContentType",
          (char *) "(J[B)V",
          nxt_java_Response_setContentType },

        { (char *) "removeContentType",
          (char *) "(J)V",
          nxt_java_Response_removeContentType },

        { (char *) "log",
          (char *) "(J[B)V",
          nxt_java_Response_log },

        { (char *) "trace",
          (char *) "(J[B)V",
          nxt_java_Response_trace },

    };

    res = (*env)->RegisterNatives(env, nxt_java_Response_class,
                                  resp_methods,
                                  sizeof(resp_methods)
                                      / sizeof(resp_methods[0]));

    nxt_unit_debug(NULL, "registered Response methods: %d", res);

    if (res != 0) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


jobject
nxt_java_newResponse(JNIEnv *env, nxt_unit_request_info_t *req)
{
    return (*env)->NewObject(env, nxt_java_Response_class,
                             nxt_java_Response_ctor, nxt_ptr2jlong(req));
}


static void JNICALL
nxt_java_Response_addHeader(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jarray name, jarray value)
{
    int                      rc;
    char                     *name_str, *value_str;
    jsize                    name_len, value_len;
    nxt_unit_request_info_t  *req;

    name_len = (*env)->GetArrayLength(env, name);
    value_len = (*env)->GetArrayLength(env, value);

    req = nxt_java_get_response_info(req_info_ptr, 1, name_len + value_len + 2);
    if (req == NULL) {
        return;
    }

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        nxt_unit_req_warn(req, "addHeader: failed to get name content");
        return;
    }

    value_str = (*env)->GetPrimitiveArrayCritical(env, value, NULL);
    if (value_str == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);
        nxt_unit_req_warn(req, "addHeader: failed to get value content");

        return;
    }

    rc = nxt_unit_response_add_field(req, name_str, name_len,
                                     value_str, value_len);
    if (rc != NXT_UNIT_OK) {
        // throw
    }

    (*env)->ReleasePrimitiveArrayCritical(env, value, value_str, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);
}


static nxt_unit_request_info_t *
nxt_java_get_response_info(jlong req_info_ptr, uint32_t extra_fields,
    uint32_t extra_data)
{
    int                      rc;
    char                     *p;
    uint32_t                 max_size;
    nxt_unit_buf_t           *buf;
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);

    if (nxt_unit_response_is_sent(req)) {
        return NULL;
    }

    data = req->data;

    if (!nxt_unit_response_is_init(req)) {
        max_size = nxt_unit_buf_max();
        max_size = max_size < data->header_size ? max_size : data->header_size;

        rc = nxt_unit_response_init(req, 200, 16, max_size);
        if (rc != NXT_UNIT_OK) {
            return NULL;
        }
    }

    buf = req->response_buf;

    if (extra_fields > req->response_max_fields
                       - req->response->fields_count
        || extra_data > (uint32_t) (buf->end - buf->free))
    {
        p = buf->start + req->response_max_fields * sizeof(nxt_unit_field_t);

        max_size = 2 * (buf->end - p);
        if (max_size > nxt_unit_buf_max()) {
            nxt_unit_req_warn(req, "required max_size is too big: %"PRIu32,
                max_size);
            return NULL;
        }

        rc = nxt_unit_response_realloc(req, 2 * req->response_max_fields,
                                       max_size);
        if (rc != NXT_UNIT_OK) {
            nxt_unit_req_warn(req, "reallocation failed: %"PRIu32", %"PRIu32,
                2 * req->response_max_fields, max_size);
            return NULL;
        }
    }

    return req;
}


static void JNICALL
nxt_java_Response_addIntHeader(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jarray name, jint value)
{
    char                     *name_str;
    jsize                    name_len;
    nxt_unit_request_info_t  *req;

    name_len = (*env)->GetArrayLength(env, name);

    req = nxt_java_get_response_info(req_info_ptr, 1, name_len + 40);
    if (req == NULL) {
        return;
    }

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        nxt_unit_req_warn(req, "addIntHeader: failed to get name content");
        return;
    }

    nxt_java_add_int_header(req, name_str, name_len, value);

    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);
}


static void
nxt_java_add_int_header(nxt_unit_request_info_t *req, const char *name,
    uint8_t name_len, int value)
{
    char                 *p;
    nxt_unit_field_t     *f;
    nxt_unit_response_t  *resp;

    resp = req->response;

    f = resp->fields + resp->fields_count;
    p = req->response_buf->free;

    f->hash = nxt_unit_field_hash(name, name_len);
    f->skip = 0;
    f->name_length = name_len;

    nxt_unit_sptr_set(&f->name, p);
    memcpy(p, name, name_len);
    p += name_len;

    nxt_unit_sptr_set(&f->value, p);
    f->value_length = snprintf(p, 40, "%d", (int) value);
    p += f->value_length + 1;

    resp->fields_count++;
    req->response_buf->free = p;

}


static jboolean JNICALL
nxt_java_Response_containsHeader(JNIEnv *env,
    jclass cls, jlong req_info_ptr, jarray name)
{
    jboolean                 res;
    char                     *name_str;
    jsize                    name_len;
    nxt_unit_response_t      *resp;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_req_debug(req, "containsHeader: response is not initialized");
        return 0;
    }

    if (nxt_unit_response_is_sent(req)) {
        nxt_unit_req_debug(req, "containsHeader: response already sent");
        return 0;
    }

    name_len = (*env)->GetArrayLength(env, name);

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        nxt_unit_req_warn(req, "containsHeader: failed to get name content");
        return 0;
    }

    resp = req->response;

    res = nxt_java_findHeader(resp->fields,
                              resp->fields + resp->fields_count,
                              name_str, name_len) != NULL;

    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);

    return res;
}


static jstring JNICALL
nxt_java_Response_getHeader(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jarray name)
{
    char                     *name_str;
    jsize                    name_len;
    nxt_unit_field_t         *f;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_req_debug(req, "getHeader: response is not initialized");
        return NULL;
    }

    if (nxt_unit_response_is_sent(req)) {
        nxt_unit_req_debug(req, "getHeader: response already sent");
        return NULL;
    }

    name_len = (*env)->GetArrayLength(env, name);

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        nxt_unit_req_warn(req, "getHeader: failed to get name content");
        return NULL;
    }

    f = nxt_java_findHeader(req->response->fields,
                            req->response->fields + req->response->fields_count,
                            name_str, name_len);

    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);

    if (f == NULL) {
        return NULL;
    }

    return nxt_java_newString(env, nxt_unit_sptr_get(&f->value),
                              f->value_length);
}


static jobject JNICALL
nxt_java_Response_getHeaderNames(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_req_debug(req, "getHeaderNames: response is not initialized");
        return NULL;
    }

    if (nxt_unit_response_is_sent(req)) {
        nxt_unit_req_debug(req, "getHeaderNames: response already sent");
        return NULL;
    }

    return nxt_java_newHeaderNamesEnumeration(env, req->response->fields,
                                              req->response->fields_count);
}


static jobject JNICALL
nxt_java_Response_getHeaders(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name)
{
    char                     *name_str;
    jsize                    name_len;
    nxt_unit_field_t         *f;
    nxt_unit_response_t      *resp;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_req_debug(req, "getHeaders: response is not initialized");
        return NULL;
    }

    if (nxt_unit_response_is_sent(req)) {
        nxt_unit_req_debug(req, "getHeaders: response already sent");
        return NULL;
    }

    resp = req->response;

    name_len = (*env)->GetArrayLength(env, name);

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        nxt_unit_req_warn(req, "getHeaders: failed to get name content");
        return NULL;
    }

    f = nxt_java_findHeader(resp->fields, resp->fields + resp->fields_count,
                            name_str, name_len);

    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);

    if (f == NULL) {
        f = resp->fields + resp->fields_count;
    }

    return nxt_java_newHeadersEnumeration(env, resp->fields, resp->fields_count,
                                          f - resp->fields);
}


static jint JNICALL
nxt_java_Response_getStatus(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_req_debug(req, "getStatus: response is not initialized");
        return 200;
    }

    if (nxt_unit_response_is_sent(req)) {
        nxt_unit_req_debug(req, "getStatus: response already sent");
        return 200;
    }

    return req->response->status;
}


static jobject JNICALL
nxt_java_Response_getRequest(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    return data->jreq;
}


static void JNICALL
nxt_java_Response_commit(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    nxt_java_OutputStream_flush_buf(env, req);
}


static void JNICALL
nxt_java_Response_sendRedirect(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray loc)
{
    int                      rc;
    char                     *loc_str;
    jsize                    loc_len;
    nxt_unit_request_info_t  *req;

    static const char        location[] = "Location";
    static const uint32_t    location_len = sizeof(location) - 1;

    req = nxt_jlong2ptr(req_info_ptr);

    if (nxt_unit_response_is_sent(req)) {
        nxt_java_throw_IllegalStateException(env, "Response already sent");

        return;
    }

    loc_len = (*env)->GetArrayLength(env, loc);

    req = nxt_java_get_response_info(req_info_ptr, 1,
                                     location_len + loc_len + 2);
    if (req == NULL) {
        return;
    }

    loc_str = (*env)->GetPrimitiveArrayCritical(env, loc, NULL);
    if (loc_str == NULL) {
        nxt_unit_req_warn(req, "sendRedirect: failed to get loc content");
        return;
    }

    req->response->status = 302;

    rc = nxt_java_response_set_header(req_info_ptr, location, location_len,
                                      loc_str, loc_len);
    if (rc != NXT_UNIT_OK) {
        // throw
    }

    (*env)->ReleasePrimitiveArrayCritical(env, loc, loc_str, 0);

    nxt_unit_response_send(req);
}


static int
nxt_java_response_set_header(jlong req_info_ptr,
    const char *name, jint name_len, const char *value, jint value_len)
{
    int                      add_field;
    char                     *dst;
    nxt_unit_field_t         *f, *e;
    nxt_unit_response_t      *resp;
    nxt_unit_request_info_t  *req;

    req = nxt_java_get_response_info(req_info_ptr, 0, 0);
    if (req == NULL) {
        return NXT_UNIT_ERROR;
    }

    resp = req->response;

    f = resp->fields;
    e = f + resp->fields_count;

    add_field = 1;

    for ( ;; ) {
        f = nxt_java_findHeader(f, e, name, name_len);
        if (f == NULL) {
            break;
        }

        if (add_field && f->value_length >= (uint32_t) value_len) {
            dst = nxt_unit_sptr_get(&f->value);
            memcpy(dst, value, value_len);
            dst[value_len] = '\0';
            f->value_length = value_len;

            add_field = 0;
            f->skip = 0;

        } else {
            f->skip = 1;
        }

        ++f;
    }

    if (!add_field) {
        return NXT_UNIT_OK;
    }

    req = nxt_java_get_response_info(req_info_ptr, 1, name_len + value_len + 2);
    if (req == NULL) {
        return NXT_UNIT_ERROR;
    }

    return nxt_unit_response_add_field(req, name, name_len, value, value_len);
}


static void JNICALL
nxt_java_Response_setHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name, jarray value)
{
    int                      rc;
    char                     *name_str, *value_str;
    jsize                    name_len, value_len;
    nxt_unit_request_info_t  *req;

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        req = nxt_jlong2ptr(req_info_ptr);
        nxt_unit_req_warn(req, "setHeader: failed to get name content");
        return;
    }

    value_str = (*env)->GetPrimitiveArrayCritical(env, value, NULL);
    if (value_str == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);

        req = nxt_jlong2ptr(req_info_ptr);
        nxt_unit_req_warn(req, "setHeader: failed to get value content");

        return;
    }

    name_len = (*env)->GetArrayLength(env, name);
    value_len = (*env)->GetArrayLength(env, value);

    rc = nxt_java_response_set_header(req_info_ptr, name_str, name_len,
                                      value_str, value_len);
    if (rc != NXT_UNIT_OK) {
        // throw
    }

    (*env)->ReleasePrimitiveArrayCritical(env, value, value_str, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);
}


static void JNICALL
nxt_java_Response_removeHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name)
{
    int                      rc;
    char                     *name_str;
    jsize                    name_len;
    nxt_unit_request_info_t  *req;

    name_len = (*env)->GetArrayLength(env, name);

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        req = nxt_jlong2ptr(req_info_ptr);
        nxt_unit_req_warn(req, "setHeader: failed to get name content");
        return;
    }

    rc = nxt_java_response_remove_header(req_info_ptr, name_str, name_len);
    if (rc != NXT_UNIT_OK) {
        // throw
    }

    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);
}


static int
nxt_java_response_remove_header(jlong req_info_ptr,
    const char *name, jint name_len)
{
    nxt_unit_field_t         *f, *e;
    nxt_unit_response_t      *resp;
    nxt_unit_request_info_t  *req;

    req = nxt_java_get_response_info(req_info_ptr, 0, 0);
    if (req == NULL) {
        return NXT_UNIT_ERROR;
    }

    resp = req->response;

    f = resp->fields;
    e = f + resp->fields_count;

    for ( ;; ) {
        f = nxt_java_findHeader(f, e, name, name_len);
        if (f == NULL) {
            break;
        }

        f->skip = 1;

        ++f;
    }

    return NXT_UNIT_OK;
}


static void JNICALL
nxt_java_Response_setIntHeader(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray name, jint value)
{
    int    value_len, rc;
    char   value_str[40];
    char   *name_str;
    jsize  name_len;

    value_len = snprintf(value_str, sizeof(value_str), "%d", (int) value);

    name_len = (*env)->GetArrayLength(env, name);

    name_str = (*env)->GetPrimitiveArrayCritical(env, name, NULL);
    if (name_str == NULL) {
        nxt_unit_req_warn(nxt_jlong2ptr(req_info_ptr),
                          "setIntHeader: failed to get name content");
        return;
    }

    rc = nxt_java_response_set_header(req_info_ptr, name_str, name_len,
                                      value_str, value_len);
    if (rc != NXT_UNIT_OK) {
        // throw
    }

    (*env)->ReleasePrimitiveArrayCritical(env, name, name_str, 0);
}


static void JNICALL
nxt_java_Response_setStatus(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jint sc)
{
    nxt_unit_request_info_t  *req;

    req = nxt_java_get_response_info(req_info_ptr, 0, 0);
    if (req == NULL) {
        return;
    }

    req->response->status = sc;
}


static jstring JNICALL
nxt_java_Response_getContentType(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_field_t         *f;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (!nxt_unit_response_is_init(req)) {
        nxt_unit_req_debug(req, "getContentType: response is not initialized");
        return NULL;
    }

    if (nxt_unit_response_is_sent(req)) {
        nxt_unit_req_debug(req, "getContentType: response already sent");
        return NULL;
    }

    f = nxt_java_findHeader(req->response->fields,
                            req->response->fields + req->response->fields_count,
                            "Content-Type", sizeof("Content-Type") - 1);

    if (f == NULL) {
        return NULL;
    }

    return nxt_java_newString(env, nxt_unit_sptr_get(&f->value),
                              f->value_length);
}


static jboolean JNICALL
nxt_java_Response_isCommitted(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    if (nxt_unit_response_is_sent(req)) {
        return 1;
    }

    return 0;
}


static void JNICALL
nxt_java_Response_reset(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_buf_t           *buf;
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);

    if (nxt_unit_response_is_sent(req)) {
        nxt_java_throw_IllegalStateException(env, "Response already sent");

        return;
    }

    data = req->data;

    if (data->buf != NULL && data->buf->free > data->buf->start) {
        data->buf->free = data->buf->start;
    }

    if (nxt_unit_response_is_init(req)) {
        req->response->status = 200;
        req->response->fields_count = 0;

        buf = req->response_buf;

        buf->free = buf->start + req->response_max_fields
                                  * sizeof(nxt_unit_field_t);
    }
}


static void JNICALL
nxt_java_Response_resetBuffer(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    if (data->buf != NULL && data->buf->free > data->buf->start) {
        data->buf->free = data->buf->start;
    }
}


static void JNICALL
nxt_java_Response_setBufferSize(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jint size)
{
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    if (data->buf_size == (uint32_t) size) {
        return;
    }

    if (data->buf != NULL && data->buf->free > data->buf->start) {
        nxt_java_throw_IllegalStateException(env, "Buffer is not empty");

        return;
    }

    data->buf_size = size;

    if (data->buf_size > nxt_unit_buf_max()) {
        data->buf_size = nxt_unit_buf_max();
    }

    if (data->buf != NULL
        && (uint32_t) (data->buf->end - data->buf->start) < data->buf_size)
    {
        nxt_unit_buf_free(data->buf);

        data->buf = NULL;
    }
}


static jint JNICALL
nxt_java_Response_getBufferSize(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    return data->buf_size;
}


static void JNICALL
nxt_java_Response_setContentLength(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jlong len)
{
    nxt_unit_request_info_t  *req;

    req = nxt_java_get_response_info(req_info_ptr, 0, 0);
    if (req == NULL) {
        return;
    }

    req->response->content_length = len;
}


static void JNICALL
nxt_java_Response_setContentType(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jarray type)
{
    int    rc;
    char   *type_str;
    jsize  type_len;

    static const char      content_type[] = "Content-Type";
    static const uint32_t  content_type_len = sizeof(content_type) - 1;

    type_len = (*env)->GetArrayLength(env, type);

    type_str = (*env)->GetPrimitiveArrayCritical(env, type, NULL);
    if (type_str == NULL) {
        return;
    }

    rc = nxt_java_response_set_header(req_info_ptr,
                                      content_type, content_type_len,
                                      type_str, type_len);
    if (rc != NXT_UNIT_OK) {
        // throw
    }

    (*env)->ReleasePrimitiveArrayCritical(env, type, type_str, 0);
}


static void JNICALL
nxt_java_Response_removeContentType(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_java_response_remove_header(req_info_ptr, "Content-Type",
                                    sizeof("Content-Type") - 1);
}


static void JNICALL
nxt_java_Response_log(JNIEnv *env, jclass cls, jlong req_info_ptr, jarray msg)
{
    char                     *msg_str;
    jsize                    msg_len;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);
    msg_len = (*env)->GetArrayLength(env, msg);

    msg_str = (*env)->GetPrimitiveArrayCritical(env, msg, NULL);
    if (msg_str == NULL) {
        nxt_unit_req_warn(req, "log: failed to get msg content");
        return;
    }

    nxt_unit_req_log(req, NXT_UNIT_LOG_INFO, "%.*s", msg_len, msg_str);

    (*env)->ReleasePrimitiveArrayCritical(env, msg, msg_str, 0);
}


static void JNICALL
nxt_java_Response_trace(JNIEnv *env, jclass cls, jlong req_info_ptr, jarray msg)
{
#if (NXT_DEBUG)
    char                     *msg_str;
    jsize                    msg_len;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);
    msg_len = (*env)->GetArrayLength(env, msg);

    msg_str = (*env)->GetPrimitiveArrayCritical(env, msg, NULL);
    if (msg_str == NULL) {
        nxt_unit_req_warn(req, "trace: failed to get msg content");
        return;
    }

    nxt_unit_req_debug(req, "%.*s", msg_len, msg_str);

    (*env)->ReleasePrimitiveArrayCritical(env, msg, msg_str, 0);
#endif
}

