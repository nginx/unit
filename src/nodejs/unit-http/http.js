
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

const {
    Server,
    ServerRequest,
    ServerResponse,
} = require('./http_server');

function createServer (options, requestHandler) {
    return new Server(options, requestHandler);
}

const http = require("http")

module.exports = {
    ...http,
    Server,
    createServer,
    IncomingMessage: ServerRequest,
    ServerResponse,
};
