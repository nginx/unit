
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

module.exports = {
    'server'       : require('./websocket_server'),
    'router'       : require('./websocket_router'),
    'frame'        : require('./websocket_frame'),
    'request'      : require('./websocket_request'),
    'connection'   : require('./websocket_connection'),
};
