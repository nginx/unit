
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <jni.h>
#include <nxt_unit.h>
#include <string.h>

#include "nxt_jni.h"
#include "nxt_jni_InputStream.h"
#include "nxt_jni_URLClassLoader.h"


static jint JNICALL nxt_java_InputStream_readLine(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray b, jint off, jint len);
static jboolean JNICALL nxt_java_InputStream_isFinished(JNIEnv *env, jclass cls,
    jlong req_info_ptr);
static jint JNICALL nxt_java_InputStream_readByte(JNIEnv *env, jclass cls,
    jlong req_info_ptr);
static jint JNICALL nxt_java_InputStream_read(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray b, jint off, jint len);
static jlong JNICALL nxt_java_InputStream_skip(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jlong n);
static jint JNICALL nxt_java_InputStream_available(JNIEnv *env, jclass cls,
    jlong req_info_ptr);


static jclass  nxt_java_InputStream_class;


int
nxt_java_initInputStream(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.InputStream");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_InputStream_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);

    JNINativeMethod is_methods[] = {
        { (char *) "readLine",
          (char *) "(J[BII)I",
          nxt_java_InputStream_readLine },

        { (char *) "isFinished",
          (char *) "(J)Z",
          nxt_java_InputStream_isFinished },

        { (char *) "read",
          (char *) "(J)I",
          nxt_java_InputStream_readByte },

        { (char *) "read",
          (char *) "(J[BII)I",
          nxt_java_InputStream_read },

        { (char *) "skip",
          (char *) "(JJ)J",
          nxt_java_InputStream_skip },

        { (char *) "available",
          (char *) "(J)I",
          nxt_java_InputStream_available },
    };

    res = (*env)->RegisterNatives(env, nxt_java_InputStream_class,
                                  is_methods,
                                  sizeof(is_methods) / sizeof(is_methods[0]));

    nxt_unit_debug(NULL, "registered InputStream methods: %d", res);

    if (res != 0) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static jint JNICALL
nxt_java_InputStream_readLine(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray out, jint off, jint len)
{
    char                     *p;
    jint                     size, b_size;
    uint8_t                  *data;
    ssize_t                  res;
    nxt_unit_buf_t           *b;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    size = 0;

    for (b = req->content_buf; b; b = nxt_unit_buf_next(b)) {
        b_size = b->end - b->free;
        p = memchr(b->free, '\n', b_size);

        if (p != NULL) {
            p++;
            size += p - b->free;
            break;
        }

        size += b_size;

        if (size >= len) {
            break;
        }
    }

    len = len < size ? len : size;

    data = (*env)->GetPrimitiveArrayCritical(env, out, NULL);

    res = nxt_unit_request_read(req, data + off, len);

    nxt_unit_req_debug(req, "readLine '%.*s'", res, (char *) data + off);

    (*env)->ReleasePrimitiveArrayCritical(env, out, data, 0);

    return res > 0 ? res : -1;
}


static jboolean JNICALL
nxt_java_InputStream_isFinished(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    return req->content_length == 0;
}


static jint JNICALL
nxt_java_InputStream_readByte(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    uint8_t                  b;
    ssize_t                  size;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    size = nxt_unit_request_read(req, &b, 1);

    return size == 1 ? b : -1;
}


static jint JNICALL
nxt_java_InputStream_read(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jarray b, jint off, jint len)
{
    uint8_t                  *data;
    ssize_t                  res;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    data = (*env)->GetPrimitiveArrayCritical(env, b, NULL);

    res = nxt_unit_request_read(req, data + off, len);

    nxt_unit_req_debug(req, "read '%.*s'", res, (char *) data + off);

    (*env)->ReleasePrimitiveArrayCritical(env, b, data, 0);

    return res > 0 ? res : -1;
}


static jlong JNICALL
nxt_java_InputStream_skip(JNIEnv *env, jclass cls, jlong req_info_ptr, jlong n)
{
    size_t                   rest, b_size;
    nxt_unit_buf_t           *buf;
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    rest = n;

    buf = req->content_buf;

    while (buf != NULL) {
        b_size = buf->end - buf->free;
        b_size = rest < b_size ? rest : b_size;

        buf->free += b_size;
        rest -= b_size;

        if (rest == 0) {
            if (buf->end == buf->free) {
                buf = nxt_unit_buf_next(buf);
            }

            break;
        }

        buf = nxt_unit_buf_next(buf);
    }

    n = n < (jlong) req->content_length ? n : (jlong) req->content_length;

    req->content_length -= n;

    return n;
}


static jint JNICALL
nxt_java_InputStream_available(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;

    req = nxt_jlong2ptr(req_info_ptr);

    return req->content_length;
}
