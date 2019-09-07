
/*
 * Copyright (C) NGINX, Inc.
 */

#include <nxt_auto_config.h>

#include <jni.h>
#include <nxt_unit.h>
#include <nxt_unit_field.h>

#include "nxt_jni.h"


static jclass     nxt_java_NoSuchElementException_class;
static jclass     nxt_java_IOException_class;
static jclass     nxt_java_IllegalStateException_class;
static jclass     nxt_java_File_class;
static jmethodID  nxt_java_File_ctor;

static inline char nxt_java_lowcase(char c);


int
nxt_java_jni_init(JNIEnv *env)
{
    jclass  cls;

    cls = (*env)->FindClass(env, "java/util/NoSuchElementException");
    if (cls == NULL) {
        return NXT_UNIT_ERROR;
    }

    nxt_java_NoSuchElementException_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);


    cls = (*env)->FindClass(env, "java/io/IOException");
    if (cls == NULL) {
        (*env)->DeleteGlobalRef(env, nxt_java_NoSuchElementException_class);
        return NXT_UNIT_ERROR;
    }

    nxt_java_IOException_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);


    cls = (*env)->FindClass(env, "java/lang/IllegalStateException");
    if (cls == NULL) {
        (*env)->DeleteGlobalRef(env, nxt_java_NoSuchElementException_class);
        (*env)->DeleteGlobalRef(env, nxt_java_IOException_class);
        return NXT_UNIT_ERROR;
    }

    nxt_java_IllegalStateException_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);


    cls = (*env)->FindClass(env, "java/io/File");
    if (cls == NULL) {
        (*env)->DeleteGlobalRef(env, nxt_java_NoSuchElementException_class);
        (*env)->DeleteGlobalRef(env, nxt_java_IOException_class);
        (*env)->DeleteGlobalRef(env, nxt_java_IllegalStateException_class);
        return NXT_UNIT_ERROR;
    }

    nxt_java_File_class = (*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);


    nxt_java_File_ctor = (*env)->GetMethodID(env, nxt_java_File_class, "<init>",
                                             "(Ljava/lang/String;)V");
    if (nxt_java_File_ctor == NULL) {
        (*env)->DeleteGlobalRef(env, nxt_java_NoSuchElementException_class);
        (*env)->DeleteGlobalRef(env, nxt_java_IOException_class);
        (*env)->DeleteGlobalRef(env, nxt_java_IllegalStateException_class);
        (*env)->DeleteGlobalRef(env, nxt_java_File_class);
        return NXT_UNIT_ERROR;
    }

    return NXT_UNIT_OK;
}


void
nxt_java_throw_NoSuchElementException(JNIEnv *env, const char *msg)
{
    (*env)->ThrowNew(env, nxt_java_NoSuchElementException_class, msg);
}


void
nxt_java_throw_IOException(JNIEnv *env, const char *msg)
{
    (*env)->ThrowNew(env, nxt_java_IOException_class, msg);
}


void
nxt_java_throw_IllegalStateException(JNIEnv *env, const char *msg)
{
    (*env)->ThrowNew(env, nxt_java_IllegalStateException_class, msg);
}


nxt_unit_field_t *
nxt_java_findHeader(nxt_unit_field_t *f, nxt_unit_field_t *end,
    const char *name, uint8_t name_len)
{
    const char  *field_name;

    for (/* void */ ; f < end; f++) {
        if (f->skip != 0 || f->name_length != name_len) {
            continue;
        }

        field_name = nxt_unit_sptr_get(&f->name);

        if (nxt_java_strcaseeq(name, field_name, name_len)) {
            return f;
        }
    }

    return NULL;
}


int
nxt_java_strcaseeq(const char *str1, const char *str2, int len)
{
    char        c1, c2;
    const char  *end1;

    end1 = str1 + len;

    while (str1 < end1) {
        c1 = nxt_java_lowcase(*str1++);
        c2 = nxt_java_lowcase(*str2++);

        if (c1 != c2) {
            return 0;
        }
    }

    return 1;
}


static inline char
nxt_java_lowcase(char c)
{
    return (c >= 'A' && c <= 'Z') ? c | 0x20 : c;
}


jstring
nxt_java_newString(JNIEnv *env, char *str, uint32_t len)
{
    char     tmp;
    jstring  res;

    tmp = str[len];

    if (tmp != '\0') {
        str[len] = '\0';
    }

    res = (*env)->NewStringUTF(env, str);

    if (tmp != '\0') {
        str[len] = tmp;
    }

    return res;
}
