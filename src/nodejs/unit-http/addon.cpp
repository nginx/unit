
/*
 * Copyright (C) NGINX, Inc.
 */

#include "unit.h"


napi_value
Init(napi_env env, napi_value exports)
{
    return Unit::init(env, exports);
}

NAPI_MODULE(Unit, Init)
