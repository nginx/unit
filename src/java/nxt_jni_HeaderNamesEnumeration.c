
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
#include "nxt_jni_HeaderNamesEnumeration.h"


static jlong JNICALL nxt_java_HeaderNamesEnumeration_nextElementPos(JNIEnv *env,
    jclass cls, jlong headers_ptr, jlong size, jlong pos);
static jstring JNICALL nxt_java_HeaderNamesEnumeration_nextElement(JNIEnv *env,
    jclass cls, jlong headers_ptr, jlong size, jlong pos);


static jclass     nxt_java_HeaderNamesEnumeration_class;
static jmethodID  nxt_java_HeaderNamesEnumeration_ctor;


int
nxt_java_initHeaderNamesEnumeration(JNIEnv *env, jobject cl)
{
    int     res;
    jclass  cls;

    cls = nxt_java_loadClass(env, cl, "nginx.unit.HeaderNamesEnumeration");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_HeaderNamesEnumeration_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    cls = nxt_java_HeaderNamesEnumeration_class;

    nxt_java_HeaderNamesEnumeration_ctor = (*env)->GetMethodID(env, cls,
        "<init>", "(JJ)V");
    if (nxt_java_HeaderNamesEnumeration_ctor == NULL) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    JNINativeMethod hnenum_methods[] = {
        { (char *) "nextElementPos",
          (char *) "(JJJ)J",
          nxt_java_HeaderNamesEnumeration_nextElementPos },

        { (char *) "nextElement",
          (char *) "(JJJ)Ljava/lang/String;",
          nxt_java_HeaderNamesEnumeration_nextElement },
    };

    res = (*env)->RegisterNatives(env, nxt_java_HeaderNamesEnumeration_class,
                                  hnenum_methods,
                                  sizeof(hnenum_methods)
                                      / sizeof(hnenum_methods[0]));

    nxt_unit_debug(NULL, "registered HeaderNamesEnumeration methods: %d", res);

    if (res != 0) {
        (*env)->DeleteGlobalRef(env, cls);
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


jobject
nxt_java_newHeaderNamesEnumeration(JNIEnv *env, nxt_unit_field_t *f,
    uint32_t fields_count)
{
    return (*env)->NewObject(env,
        nxt_java_HeaderNamesEnumeration_class,
        nxt_java_HeaderNamesEnumeration_ctor, nxt_ptr2jlong(f),
        (jlong) fields_count);
}


static jlong JNICALL
nxt_java_HeaderNamesEnumeration_nextElementPos(JNIEnv *env, jclass cls,
    jlong headers_ptr, jlong size, jlong pos)
{
    nxt_unit_field_t  *f;

    f = nxt_jlong2ptr(headers_ptr);

    if (pos >= size) {
        return size;
    }

    if (pos > 0) {
        while (pos < size
               && f[pos].hash == f[pos - 1].hash
               && f[pos].name_length == f[pos - 1].name_length)
        {
            pos++;
        }
    }

    return pos;
}


static jstring JNICALL
nxt_java_HeaderNamesEnumeration_nextElement(JNIEnv *env, jclass cls,
    jlong headers_ptr, jlong size, jlong pos)
{
    char              *name, tmp;
    jstring           res;
    nxt_unit_field_t  *f;

    f = nxt_jlong2ptr(headers_ptr);

    if (pos > 0) {
        while (pos < size
               && f[pos].hash == f[pos - 1].hash
               && f[pos].name_length == f[pos - 1].name_length)
        {
            pos++;
        }
    }

    if (pos >= size) {
        nxt_java_throw_NoSuchElementException(env, "pos >= size");

        return NULL;
    }

    f += pos;

    name = nxt_unit_sptr_get(&f->name);
    tmp = name[f->name_length];

    if (tmp != '\0') {
        name[f->name_length] = '\0';
    }

    res = (*env)->NewStringUTF(env, name);

    if (tmp != '\0') {
        name[f->name_length] = tmp;
    }

    return res;
}
