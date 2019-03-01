
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <jni.h>
#include <nxt_unit.h>

#include "nxt_jni.h"
#include "nxt_jni_OutputStream.h"
#include "nxt_jni_URLClassLoader.h"


static void JNICALL nxt_java_OutputStream_writeByte(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jint b);
static nxt_unit_buf_t *nxt_java_OutputStream_req_buf(JNIEnv *env,
    nxt_unit_request_info_t *req);
static void JNICALL nxt_java_OutputStream_write(JNIEnv *env, jclass cls,
    jlong req_info_ptr, jarray b, jint off, jint len);
static void JNICALL nxt_java_OutputStream_flush(JNIEnv *env, jclass cls,
    jlong req_info_ptr);
static void JNICALL nxt_java_OutputStream_close(JNIEnv *env, jclass cls,
    jlong req_info_ptr);


static jclass  nxt_java_OutputStream_class;


int
nxt_java_initOutputStream(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.OutputStream");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_OutputStream_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);

    cls = nxt_java_OutputStream_class;

    JNINativeMethod os_methods[] = {
        { (char *) "write",
          (char *) "(JI)V",
          nxt_java_OutputStream_writeByte },

        { (char *) "write",
          (char *) "(J[BII)V",
          nxt_java_OutputStream_write },

        { (char *) "flush",
          (char *) "(J)V",
          nxt_java_OutputStream_flush },

        { (char *) "close",
          (char *) "(J)V",
          nxt_java_OutputStream_close },
    };

    res = (*env)->RegisterNatives(env, nxt_java_OutputStream_class,
                                  os_methods,
                                  sizeof(os_methods) / sizeof(os_methods[0]));

    nxt_unit_debug(NULL, "registered OutputStream methods: %d", res);

    if (res != 0) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


static void JNICALL
nxt_java_OutputStream_writeByte(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jint b)
{
    nxt_unit_buf_t           *buf;
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    buf = nxt_java_OutputStream_req_buf(env, req);
    if (buf == NULL) {
        return;
    }

    *buf->free++ = b;

    if ((uint32_t) (buf->free - buf->start) >= data->buf_size) {
        nxt_java_OutputStream_flush_buf(env, req);
    }
}


int
nxt_java_OutputStream_flush_buf(JNIEnv *env, nxt_unit_request_info_t *req)
{
    int                      rc;
    nxt_java_request_data_t  *data;

    data = req->data;

    if (!nxt_unit_response_is_init(req)) {
        rc = nxt_unit_response_init(req, 200, 0, 0);
        if (rc != NXT_UNIT_OK) {
            nxt_java_throw_IOException(env, "Failed to allocate response");

            return rc;
        }
    }

    if (!nxt_unit_response_is_sent(req)) {
        rc = nxt_unit_response_send(req);
        if (rc != NXT_UNIT_OK) {
            nxt_java_throw_IOException(env, "Failed to send response headers");

            return rc;
        }
    }

    if (data->buf != NULL) {
        rc = nxt_unit_buf_send(data->buf);
        if (rc != NXT_UNIT_OK) {
            nxt_java_throw_IOException(env, "Failed to send buffer");

        } else {
            data->buf = NULL;
        }

    } else {
        rc = NXT_UNIT_OK;
    }

    return rc;
}


static nxt_unit_buf_t *
nxt_java_OutputStream_req_buf(JNIEnv *env, nxt_unit_request_info_t *req)
{
    uint32_t                 size;
    nxt_unit_buf_t           *buf;
    nxt_java_request_data_t  *data;

    data = req->data;
    buf = data->buf;

    if (buf == NULL || buf->free >= buf->end) {
        size = data->buf_size == 0 ? nxt_unit_buf_min() : data->buf_size;

        buf = nxt_unit_response_buf_alloc(req, size);
        if (buf == NULL) {
            nxt_java_throw_IOException(env, "Failed to allocate buffer");

            return NULL;
        }

        data->buf = buf;
    }

    return buf;
}


static void JNICALL
nxt_java_OutputStream_write(JNIEnv *env, jclass cls, jlong req_info_ptr,
    jarray b, jint off, jint len)
{
    int                      rc;
    jint                     copy;
    uint8_t                  *ptr;
    nxt_unit_buf_t           *buf;
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    ptr = (*env)->GetPrimitiveArrayCritical(env, b, NULL);

    while (len > 0) {
        buf = nxt_java_OutputStream_req_buf(env, req);
        if (buf == NULL) {
            return;
        }

        copy = buf->end - buf->free;
        copy = copy < len ? copy : len;

        memcpy(buf->free, ptr + off, copy);
        buf->free += copy;

        len -= copy;
        off += copy;

        if ((uint32_t) (buf->free - buf->start) >= data->buf_size) {
            rc = nxt_java_OutputStream_flush_buf(env, req);
            if (rc != NXT_UNIT_OK) {
                break;
            }
        }
    }

    (*env)->ReleasePrimitiveArrayCritical(env, b, ptr, 0);
}


static void JNICALL
nxt_java_OutputStream_flush(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_unit_request_info_t  *req;
    nxt_java_request_data_t  *data;

    req = nxt_jlong2ptr(req_info_ptr);
    data = req->data;

    if (data->buf != NULL && data->buf->free > data->buf->start) {
        nxt_java_OutputStream_flush_buf(env, req);
    }
}


static void JNICALL
nxt_java_OutputStream_close(JNIEnv *env, jclass cls, jlong req_info_ptr)
{
    nxt_java_OutputStream_flush_buf(env, nxt_jlong2ptr(req_info_ptr));
}
