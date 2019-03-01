
/*
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_JAVA_HEADERNAMESENUMERATION_H_INCLUDED_
#define _NXT_JAVA_HEADERNAMESENUMERATION_H_INCLUDED_


#include <jni.h>
#include <nxt_unit_typedefs.h>


int nxt_java_initHeaderNamesEnumeration(JNIEnv *env, jobject cl);

jobject nxt_java_newHeaderNamesEnumeration(JNIEnv *env, nxt_unit_field_t *f,
    uint32_t fields_count);

#endif  /* _NXT_JAVA_HEADERNAMESENUMERATION_H_INCLUDED_ */
