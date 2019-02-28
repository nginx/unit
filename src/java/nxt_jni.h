
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JAVA_JNI_H_INCLUDED_
#define _NXT_JAVA_JNI_H_INCLUDED_


#include <jni.h>
#include <nxt_unit_typedefs.h>


int nxt_java_jni_init(JNIEnv *env);

void nxt_java_throw_NoSuchElementException(JNIEnv *env, const char *msg);

void nxt_java_throw_IOException(JNIEnv *env, const char *msg);

void nxt_java_throw_IllegalStateException(JNIEnv *env, const char *msg);

nxt_unit_field_t *nxt_java_findHeader(nxt_unit_field_t *f, nxt_unit_field_t *e,
    const char *name, uint8_t name_len);

int nxt_java_strcaseeq(const char *str1, const char *str2, int len);

jstring nxt_java_newString(JNIEnv *env, char *str, uint32_t len);


typedef struct {
    uint32_t          header_size;
    uint32_t          buf_size;

    jobject           jreq;
    jobject           jresp;

    nxt_unit_buf_t    *first;
    nxt_unit_buf_t    *buf;

} nxt_java_request_data_t;


static inline jlong
nxt_ptr2jlong(void *ptr)
{
    return (jlong) (intptr_t) ptr;
}

static inline void *
nxt_jlong2ptr(jlong l)
{
    return (void *) (intptr_t) l;
}

#endif  /* _NXT_JAVA_JNI_H_INCLUDED_ */
