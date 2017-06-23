
/*
 * Copyright (C) Max Romanov
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NXT_GO_PORT_H_INCLUDED_
#define _NXT_GO_PORT_H_INCLUDED_


#include <sys/types.h>
#include "nxt_go_lib.h"

nxt_go_request_t
nxt_go_port_on_read(void *buf, size_t buf_size, void *oob, size_t oob_size);


#endif /* _NXT_GO_PORT_H_INCLUDED_ */
