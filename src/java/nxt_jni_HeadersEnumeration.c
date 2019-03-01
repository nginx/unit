
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <nxt_unit.h>
#include <nxt_unit_request.h>
#include <jni.h>
#include <stdio.h>

#include "nxt_jni.h"
#include "nxt_jni_URLClassLoader.h"
#include "nxt_jni_HeadersEnumeration.h"


static jclass     nxt_java_HeadersEnumeration_class;
static jmethodID  nxt_java_HeadersEnumeration_ctor;


static jlong JNICALL nxt_java_HeadersEnumeration_nextElementPos(JNIEnv *env,
    jclass cls, jlong headers_ptr, jlong size, jlong ipos, jlong pos);

static jstring JNICALL nxt_java_HeadersEnumeration_nextElement(JNIEnv *env,
    jclass cls, jlong headers_ptr, jlong size, jlong ipos, jlong pos);


int
nxt_java_initHeadersEnumeration(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.HeadersEnumeration");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_HeadersEnumeration_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    cls = nxt_java_HeadersEnumeration_class;

    nxt_java_HeadersEnumeration_ctor = (*env)->GetMethodID(env, cls,
        "<init>", "(JJJ)V");
    if (nxt_java_HeadersEnumeration_ctor == NULL) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    JNINativeMethod methods[] = {
        { (char *) "nextElementPos",
          (char *) "(JJJJ)J",
          nxt_java_HeadersEnumeration_nextElementPos },

        { (char *) "nextElement",
          (char *) "(JJJJ)Ljava/lang/String;",
          nxt_java_HeadersEnumeration_nextElement },
    };

    res = (*env)->RegisterNatives(env, nxt_java_HeadersEnumeration_class,
                                  methods,
                                  sizeof(methods) / sizeof(methods[0]));

    nxt_unit_debug(NULL, "registered HeadersEnumeration methods: %d", res);

    if (res != 0) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


jobject
nxt_java_newHeadersEnumeration(JNIEnv *env, nxt_unit_field_t *f,
    uint32_t fields_count, uint32_t pos)
{
    return (*env)->NewObject(env,
        nxt_java_HeadersEnumeration_class,
        nxt_java_HeadersEnumeration_ctor, nxt_ptr2jlong(f),
        (jlong) fields_count, (jlong) pos);
}


static jlong JNICALL
nxt_java_HeadersEnumeration_nextElementPos(JNIEnv *env, jclass cls,
    jlong headers_ptr, jlong size, jlong ipos, jlong pos)
{
    nxt_unit_field_t  *f, *init_field;

    f = nxt_jlong2ptr(headers_ptr);

    init_field = f + ipos;

    if (pos >= size) {
        return size;
    }

    f += pos;

    if (f->hash != init_field->hash
        || f->name_length != init_field->name_length)
    {
        return size;
    }

    if (!nxt_java_strcaseeq(nxt_unit_sptr_get(&f->name),
                            nxt_unit_sptr_get(&init_field->name),
                            init_field->name_length))
    {
        return size;
    }

    return pos;
}


static jstring JNICALL
nxt_java_HeadersEnumeration_nextElement(JNIEnv *env, jclass cls,
    jlong headers_ptr, jlong size, jlong ipos, jlong pos)
{
    nxt_unit_field_t  *f, *init_field;

    f = nxt_jlong2ptr(headers_ptr);

    init_field = f + ipos;

    if (pos >= size) {
        nxt_java_throw_IOException(env, "pos >= size");

        return NULL;
    }

    f += pos;

    if (f->hash != init_field->hash
        || f->name_length != init_field->name_length)
    {
        nxt_java_throw_IOException(env, "f->hash != hash");

        return NULL;
    }

    return nxt_java_newString(env, nxt_unit_sptr_get(&f->value),
                              f->value_length);
}
