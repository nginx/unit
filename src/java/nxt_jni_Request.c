
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>

#include "nxt_jni.h"
#include "nxt_jni_Request.h"
#include "nxt_jni_URLClassLoader.h"
#include "nxt_jni_HeadersEnumeration.h"
#include "nxt_jni_HeaderNamesEnumeration.h"


static jstring JNICALL nxt_java_Request_getHeader(JNIEnv *env, jclass cls,
    jlong req_ptr, jstring name, jint name_len);
static jobject JNICALL nxt_java_Request_getHeaderNames(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jobject JNICALL nxt_java_Request_getHeaders(JNIEnv *env, jclass cls,
    jlong req_ptr, jstring name, jint name_len);
static jint JNICALL nxt_java_Request_getIntHeader(JNIEnv *env, jclass cls,
    jlong req_ptr, jstring name, jint name_len);
static jstring JNICALL nxt_java_Request_getMethod(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getQueryString(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getRequestURI(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jlong JNICALL nxt_java_Request_getContentLength(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getContentType(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getLocalAddr(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getLocalName(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jint JNICALL nxt_java_Request_getLocalPort(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getProtocol(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getRemoteAddr(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getRemoteHost(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jint JNICALL nxt_java_Request_getRemotePort(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getScheme(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jstring JNICALL nxt_java_Request_getServerName(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jint JNICALL nxt_java_Request_getServerPort(JNIEnv *env, jclass cls,
    jlong req_ptr);
static jboolean JNICALL nxt_java_Request_isSecure(JNIEnv *env, jclass cls,
    jlong req_ptr);
static void JNICALL nxt_java_Request_log(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jstring msg, jint msg_len);
static void JNICALL nxt_java_Request_trace(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jstring msg, jint msg_len);
static jobject JNICALL nxt_java_Request_getResponse(JNIEnv *env, jclass cls,
    jlong req_info_ptr);


static jclass     nxt_java_Request_class;
static jmethodID  nxt_java_Request_ctor;


int
nxt_java_initRequest(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.Request");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_Request_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    cls = nxt_java_Request_class;

    nxt_java_Request_ctor = (*env)->GetMethodID(env, cls, "<init>", "(Lnginx/unit/Context;JJ)V");
    if (nxt_java_Request_ctor == NULL) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    JNINativeMethod request_methods[] = {
        { (char *) "getHeader",
          (char *) "(JLjava/lang/String;I)Ljava/lang/String;",
          nxt_java_Request_getHeader },

        { (char *) "getHeaderNames",
          (char *) "(J)Ljava/util/Enumeration;",
          nxt_java_Request_getHeaderNames },

        { (char *) "getHeaders",
          (char *) "(JLjava/lang/String;I)Ljava/util/Enumeration;",
          nxt_java_Request_getHeaders },

        { (char *) "getIntHeader",
          (char *) "(JLjava/lang/String;I)I",
          nxt_java_Request_getIntHeader },

        { (char *) "getMethod",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getMethod },

        { (char *) "getQueryString",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getQueryString },

        { (char *) "getRequestURI",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getRequestURI },

        { (char *) "getContentLength",
          (char *) "(J)J",
          nxt_java_Request_getContentLength },

        { (char *) "getContentType",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getContentType },

        { (char *) "getLocalAddr",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getLocalAddr },

        { (char *) "getLocalName",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getLocalName },

        { (char *) "getLocalPort",
          (char *) "(J)I",
          nxt_java_Request_getLocalPort },

        { (char *) "getProtocol",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getProtocol },

        { (char *) "getRemoteAddr",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getRemoteAddr },

        { (char *) "getRemoteHost",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getRemoteHost },

        { (char *) "getRemotePort",
          (char *) "(J)I",
          nxt_java_Request_getRemotePort },

        { (char *) "getScheme",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getScheme },

        { (char *) "getServerName",
          (char *) "(J)Ljava/lang/String;",
          nxt_java_Request_getServerName },

        { (char *) "getServerPort",
          (char *) "(J)I",
          nxt_java_Request_getServerPort },

        { (char *) "isSecure",
          (char *) "(J)Z",
          nxt_java_Request_isSecure },

        { (char *) "log",
          (char *) "(JLjava/lang/String;I)V",
          nxt_java_Request_log },

        { (char *) "trace",
          (char *) "(JLjava/lang/String;I)V",
          nxt_java_Request_trace },

        { (char *) "getResponse",
          (char *) "(J)Lnginx/unit/Response;",
          nxt_java_Request_getResponse },

    };

    res = (*env)->RegisterNatives(env, nxt_java_Request_class,
                                  request_methods,
                                  sizeof(request_methods) / sizeof(request_methods[0]));

    nxt_unit_debug(NULL, "registered Request methods: %d", res);

    if (res != 0) {
        nxt_unit_warn(NULL, "registering natives for Request failed");
        goto failed;
    }

    res = nxt_java_initHeadersEnumeration(env, cl);
    if (res != NXT_UNIT_OK) {
        goto failed;
    }

    res = nxt_java_initHeaderNamesEnumeration(env, cl);
    if (res != NXT_UNIT_OK) {
        goto failed;
    }

    return NXT_UNIT_OK;

failed:

    (*env)->DeleteGlobalRef(env, cls);
    return NXT_UNIT_ERROR;
}


jobject
nxt_java_newRequest(JNIEnv *env, jobject ctx, nxt_unit_request_info_t *req)
{
    return (*env)->NewObject(env, nxt_java_Request_class,
        nxt_java_Request_ctor, ctx, nxt_ptr2jlong(req),
        nxt_ptr2jlong(req->request));
}


static jstring JNICALL
nxt_java_Request_getHeader(JNIEnv *env, jclass cls, jlong req_ptr,
    jstring name, jint name_len)
{
    const char          *name_str;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    name_str = (*env)->GetStringUTFChars(env, name, NULL);
    if (name_str == NULL) {
        return NULL;
    }

    r = nxt_jlong2ptr(req_ptr);

    f = nxt_java_findHeader(r->fields, r->fields + r->fields_count,
                            name_str, name_len);

    (*env)->ReleaseStringUTFChars(env, name, name_str);

    if (f == NULL) {
        return NULL;
    }

    return (*env)->NewStringUTF(env, nxt_unit_sptr_get(&f->value));
}


static jobject JNICALL
nxt_java_Request_getHeaderNames(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return nxt_java_newHeaderNamesEnumeration(env, r->fields, r->fields_count);
}


static jobject JNICALL
nxt_java_Request_getHeaders(JNIEnv *env, jclass cls, jlong req_ptr,
    jstring name, jint name_len)
{
    const char          *name_str;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    name_str = (*env)->GetStringUTFChars(env, name, NULL);
    if (name_str == NULL) {
        return NULL;
    }

    r = nxt_jlong2ptr(req_ptr);

    f = nxt_java_findHeader(r->fields, r->fields + r->fields_count,
                            name_str, name_len);

    (*env)->ReleaseStringUTFChars(env, name, name_str);

    if (f == NULL) {
        f = r->fields + r->fields_count;
    }

    return nxt_java_newHeadersEnumeration(env, r->fields, r->fields_count,
                                          f - r->fields);
}


static jint JNICALL
nxt_java_Request_getIntHeader(JNIEnv *env, jclass cls, jlong req_ptr,
    jstring name, jint name_len)
{
    jint                res;
    char                *value, *end;
    const char          *name_str;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    res = -1;

    name_str = (*env)->GetStringUTFChars(env, name, NULL);
    if (name_str == NULL) {
        return res;
    }

    r = nxt_jlong2ptr(req_ptr);

    f = nxt_java_findHeader(r->fields, r->fields + r->fields_count,
                            name_str, name_len);

    (*env)->ReleaseStringUTFChars(env, name, name_str);

    if (f == NULL) {
        return res;
    }

    value = nxt_unit_sptr_get(&f->value);
    end = value + f->value_length;

    res = strtol(value, &end, 10);

    if (end < value + f->value_length) {
        // TODO throw NumberFormatException.forInputString(value)
    }

    return res;
}


static jstring JNICALL
nxt_java_Request_getMethod(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return (*env)->NewStringUTF(env, nxt_unit_sptr_get(&r->method));
}


static jstring JNICALL
nxt_java_Request_getQueryString(JNIEnv *env, jclass cls, jlong req_ptr)
{
    char                *query;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    if (r->query.offset != 0) {
        query = nxt_unit_sptr_get(&r->query);
        return (*env)->NewStringUTF(env, query);
    }

    return NULL;
}


static jstring JNICALL
nxt_java_Request_getRequestURI(JNIEnv *env, jclass cls, jlong req_ptr)
{
    char                *target, *query;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    target = nxt_unit_sptr_get(&r->target);

    if (r->query.offset != 0) {
        query = nxt_unit_sptr_get(&r->query);
        return nxt_java_newString(env, target, query - target - 1);
    }

    return (*env)->NewStringUTF(env, target);
}


static jlong JNICALL
nxt_java_Request_getContentLength(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return r->content_length;
}


static jstring JNICALL
nxt_java_Request_getContentType(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    if (r->content_type_field != NXT_UNIT_NONE_FIELD) {
        f = r->fields + r->content_type_field;

        return (*env)->NewStringUTF(env, nxt_unit_sptr_get(&f->value));
    }

    return NULL;
}


static jstring JNICALL
nxt_java_Request_getLocalAddr(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return nxt_java_newString(env, nxt_unit_sptr_get(&r->local),
                              r->local_length);
}


static jstring JNICALL
nxt_java_Request_getLocalName(JNIEnv *env, jclass cls, jlong req_ptr)
{
    char                *local, *colon;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    local = nxt_unit_sptr_get(&r->local);
    colon = memchr(local, ':', r->local_length);

    if (colon == NULL) {
        colon = local + r->local_length;
    }

    return nxt_java_newString(env, local, colon - local);
}


static jint JNICALL
nxt_java_Request_getLocalPort(JNIEnv *env, jclass cls, jlong req_ptr)
{
    jint                res;
    char                *local, *colon, tmp;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    local = nxt_unit_sptr_get(&r->local);
    colon = memchr(local, ':', r->local_length);

    if (colon == NULL) {
        return 80;
    }

    tmp = local[r->local_length];

    local[r->local_length] = '\0';

    res = strtol(colon + 1, NULL, 10);

    local[r->local_length] = tmp;

    return res;
}


static jstring JNICALL
nxt_java_Request_getProtocol(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return (*env)->NewStringUTF(env, nxt_unit_sptr_get(&r->version));
}


static jstring JNICALL
nxt_java_Request_getRemoteAddr(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return nxt_java_newString(env, nxt_unit_sptr_get(&r->remote),
                              r->remote_length);
}


static jstring JNICALL
nxt_java_Request_getRemoteHost(JNIEnv *env, jclass cls, jlong req_ptr)
{
    char                *remote, *colon;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    remote = nxt_unit_sptr_get(&r->remote);
    colon = memchr(remote, ':', r->remote_length);

    if (colon == NULL) {
        colon = remote + r->remote_length;
    }

    return nxt_java_newString(env, remote, colon - remote);
}


static jint JNICALL
nxt_java_Request_getRemotePort(JNIEnv *env, jclass cls, jlong req_ptr)
{
    jint                res;
    char                *remote, *colon, tmp;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    remote = nxt_unit_sptr_get(&r->remote);
    colon = memchr(remote, ':', r->remote_length);

    if (colon == NULL) {
        return 80;
    }

    tmp = remote[r->remote_length];

    remote[r->remote_length] = '\0';

    res = strtol(colon + 1, NULL, 10);

    remote[r->remote_length] = tmp;

    return res;
}


static jstring JNICALL
nxt_java_Request_getScheme(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return (*env)->NewStringUTF(env, r->tls ? "https" : "http");
}


static jstring JNICALL
nxt_java_Request_getServerName(JNIEnv *env, jclass cls, jlong req_ptr)
{
    char                *host, *colon;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    f = nxt_java_findHeader(r->fields, r->fields + r->fields_count,
                            "Host", 4);
    if (f != NULL) {
        host = nxt_unit_sptr_get(&f->value);

        colon = memchr(host, ':', f->value_length);

        if (colon == NULL) {
            colon = host + f->value_length;
        }

        return nxt_java_newString(env, host, colon - host);
    }

    return nxt_java_Request_getLocalName(env, cls, req_ptr);
}


static jint JNICALL
nxt_java_Request_getServerPort(JNIEnv *env, jclass cls, jlong req_ptr)
{
    jint                res;
    char                *host, *colon, tmp;
    nxt_unit_field_t    *f;
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    f = nxt_java_findHeader(r->fields, r->fields + r->fields_count,
                            "Host", 4);
    if (f != NULL) {
        host = nxt_unit_sptr_get(&f->value);

        colon = memchr(host, ':', f->value_length);

        if (colon == NULL) {
            return 80;
        }

        tmp = host[f->value_length];

        host[f->value_length] = '\0';

        res = strtol(colon + 1, NULL, 10);

        host[f->value_length] = tmp;

        return res;
    }

    return nxt_java_Request_getLocalPort(env, cls, req_ptr);
}


static jboolean JNICALL
nxt_java_Request_isSecure(JNIEnv *env, jclass cls, jlong req_ptr)
{
    nxt_unit_request_t  *r;

    r = nxt_jlong2ptr(req_ptr);

    return r->tls != 0;
}


static void JNICALL
nxt_java_Request_log(JNIEnv *env, jclass cls, jlong req_info_ptr, jstring msg,
    jint msg_len)
{
    const char               *msg_str;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    msg_str = (*env)->GetStringUTFChars(env, msg, NULL);
    if (msg_str == NULL) {
        return;
    }

    nxt_unit_req_log(req, NXT_UNIT_LOG_INFO, "%.*s", msg_len, msg_str);

    (*env)->ReleaseStringUTFChars(env, msg, msg_str);
}


static void JNICALL
nxt_java_Request_trace(JNIEnv *env, jclass cls, jlong req_info_ptr, jstring msg,
    jint msg_len)
{
#if (NXT_DEBUG)
    const char               *msg_str;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    msg_str = (*env)->GetStringUTFChars(env, msg, NULL);
    if (msg_str == NULL) {
        return;
    }

    nxt_unit_req_debug(req, "%.*s", msg_len, msg_str);

    (*env)->ReleaseStringUTFChars(env, msg, msg_str);
#endif
}


static jobject JNICALL
nxt_java_Request_getResponse(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    return data->jresp;
}
