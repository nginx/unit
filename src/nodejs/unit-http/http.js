
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

const server = require('unit-http/http_server');

const { Server } = server;

function createServer (requestHandler) {
    return new Server(requestHandler);
}


module.exports = {
    Server,
    STATUS_CODES: server.STATUS_CODES,
    createServer,
    IncomingMessage: server.ServerRequest,
    ServerResponse: server.ServerResponse
};
