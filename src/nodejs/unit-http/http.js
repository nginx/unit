
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

const {
    Server,
    ServerRequest,
    ServerResponse,
} = require('./http_server');

function createServer (requestHandler) {
    return new Server(requestHandler);
}

const http = require("http")

module.exports = {
    ...http,
    Server,
    createServer,
    IncomingMessage: ServerRequest,
    ServerResponse,
};
