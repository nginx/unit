
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

const EventEmitter = require('events');
const http = require('http');
const util = require('util');
const unit_lib = require('unit-http/build/Release/unit-http.node');
const unit_socket = require('unit-http/socket');

const { Socket } = unit_socket;


function ServerResponse(req) {
    EventEmitter.call(this);

    this.headers = {};
}
util.inherits(ServerResponse, EventEmitter);

ServerResponse.prototype.statusCode = 200;
ServerResponse.prototype.statusMessage = undefined;
ServerResponse.prototype.headers_len = 0;
ServerResponse.prototype.headers_count = 0;
ServerResponse.prototype.headersSent = false;
ServerResponse.prototype.finished = false;

ServerResponse.prototype._finish = function _finish() {
    this.headers = {};
    this.headers_len = 0;
    this.headers_count = 0;
    this.finished = true;
};

ServerResponse.prototype.assignSocket = function assignSocket(socket) {
};

ServerResponse.prototype.detachSocket = function detachSocket(socket) {
};

ServerResponse.prototype.writeContinue = function writeContinue(cb) {
};

ServerResponse.prototype.writeProcessing = function writeProcessing(cb) {
};

ServerResponse.prototype.setHeader = function setHeader(key, value) {
    if (typeof key !== 'string') {
        throw new TypeError('Key argument must be a string');
    }

    let header_key_len = Buffer.byteLength(key, 'latin1');
    let header_len = 0
    let header_count = 0;

    if (Array.isArray(value)) {
        header_count = value.length;

        value.forEach(function(val) {
            if (typeof val !== 'string' && typeof val !== 'number') {
                throw new TypeError('Array entries must be string or number');
            }

            header_len += Buffer.byteLength(val + "", 'latin1');
        });

    } else {
        if (typeof value !== 'string' && typeof value !== 'number') {
            throw new TypeError('Value argument must be string, number, or array');
        }

        header_count = 1;
        header_len = Buffer.byteLength(value + "", 'latin1');
    }

    this.removeHeader(key);

    this.headers[key] = value;
    this.headers_len += header_len + (header_key_len * header_count);
    this.headers_count += header_count;
};

ServerResponse.prototype.getHeader = function getHeader(name) {
    return this.headers[name];
};

ServerResponse.prototype.getHeaderNames = function getHeaderNames() {
    return Object.keys(this.headers);
};

ServerResponse.prototype.getHeaders = function getHeaders() {
    return this.headers;
};

ServerResponse.prototype.hasHeader = function hasHeader(name) {
    return name in this.headers;
};

ServerResponse.prototype.removeHeader = function removeHeader(name) {
    if (!(name in this.headers)) {
        return;
    }

    let name_len = Buffer.byteLength(name + "", 'latin1');

    if (Array.isArray(this.headers[name])) {
        this.headers_count -= this.headers[name].length;
        this.headers_len -= this.headers[name].length * name_len;

        this.headers[name].forEach(function(val) {
            this.headers_len -= Buffer.byteLength(val + "", 'latin1');
        });

    } else {
        this.headers_count--;
        this.headers_len -= name_len + Buffer.byteLength(this.headers[name] + "", 'latin1');
    }

    delete this.headers[name];
};

ServerResponse.prototype.sendDate = function sendDate() {
    throw new Error("Not supported");
};

ServerResponse.prototype.setTimeout = function setTimeout(msecs, callback) {
    this.timeout = msecs;

    if (callback) {
        this.on('timeout', callback);
    }

    return this;
};

// for Express
ServerResponse.prototype._implicitHeader = function _implicitHeader() {
    this.writeHead(this.statusCode);
};

ServerResponse.prototype.writeHead = writeHead;
ServerResponse.prototype.writeHeader = ServerResponse.prototype.writeHead;

function writeHead(statusCode, reason, obj) {
    var originalStatusCode = statusCode;

    statusCode |= 0;

    if (statusCode < 100 || statusCode > 999) {
        throw new ERR_HTTP_INVALID_STATUS_CODE(originalStatusCode);
    }

    if (typeof reason === 'string') {
        this.statusMessage = reason;

    } else {
        if (!this.statusMessage) {
            this.statusMessage = http.STATUS_CODES[statusCode] || 'unknown';
        }

        obj = reason;
    }

    this.statusCode = statusCode;

    if (obj) {
        var k;
        var keys = Object.keys(obj);

        for (var i = 0; i < keys.length; i++) {
            k = keys[i];

            if (k) {
                this.setHeader(k, obj[k]);
            }
        }
    }

    unit_lib.unit_response_headers(this, statusCode, this.headers, this.headers_count, this.headers_len);

    this.headersSent = true;
};

ServerResponse.prototype._writeBody = function(chunk, encoding, callback) {
    var contentLength = 0;

    if (!this.headersSent) {
        this.writeHead(this.statusCode);
    }

    if (this.finished) {
        return this;
    }

    if (typeof chunk === 'function') {
        callback = chunk;
        chunk = null;

    } else if (typeof encoding === 'function') {
        callback = encoding;
        encoding = null;
    }

    if (chunk) {
        if (typeof chunk !== 'string' && !(chunk instanceof Buffer)) {
            throw new TypeError('First argument must be a string or Buffer');
        }

        if (typeof chunk === 'string') {
            contentLength = Buffer.byteLength(chunk, encoding);

        } else {
            contentLength = chunk.length;
        }

        unit_lib.unit_response_write(this, chunk, contentLength);
    }

    if (typeof callback === 'function') {
        callback(this);
    }
};

ServerResponse.prototype.write = function write(chunk, encoding, callback) {
    this._writeBody(chunk, encoding, callback);

    return true;
};

ServerResponse.prototype.end = function end(chunk, encoding, callback) {
    this._writeBody(chunk, encoding, callback);

    this.finished = true;

    return this;
};

function ServerRequest(server) {
    EventEmitter.call(this);

    this.server = server;
}
util.inherits(ServerRequest, EventEmitter);

ServerRequest.prototype.unpipe = undefined;

ServerRequest.prototype.setTimeout = function setTimeout(msecs, callback) {
    this.timeout = msecs;

    if (callback) {
        this.on('timeout', callback);
    }

    return this;
};

ServerRequest.prototype.statusCode = function statusCode() {
    /* Only valid for response obtained from http.ClientRequest. */
};

ServerRequest.prototype.statusMessage = function statusMessage() {
    /* Only valid for response obtained from http.ClientRequest. */
};

ServerRequest.prototype.trailers = function trailers() {
    throw new Error("Not supported");
};

ServerRequest.prototype.METHODS = function METHODS() {
    return http.METHODS;
};

ServerRequest.prototype.STATUS_CODES = function STATUS_CODES() {
    return http.STATUS_CODES;
};

ServerRequest.prototype.listeners = function listeners() {
    return [];
};

ServerRequest.prototype.resume = function resume() {
    return [];
};

function Server(requestListener) {
    EventEmitter.call(this);

    this.unit = new unit_lib.Unit();
    this.unit.server = this;

    this.unit.createServer();

    this.socket = Socket;
    this.request = ServerRequest;
    this.response = ServerResponse;

    if (requestListener) {
        this.on('request', requestListener);
    }
}
util.inherits(Server, EventEmitter);

Server.prototype.setTimeout = function setTimeout(msecs, callback) {
    this.timeout = msecs;

    if (callback) {
        this.on('timeout', callback);
    }

    return this;
};

Server.prototype.listen = function () {
    this.unit.listen();
};

Server.prototype.run_events = function (server, req, res) {
    /* Important!!! setImmediate starts the next iteration in Node.js loop. */
    setImmediate(function () {
        server.emit("request", req, res);

        Promise.resolve().then(() => {
            let buf = server.unit._read(req.socket.req_pointer);

            if (buf.length != 0) {
                req.emit("data", buf);
            }

            req.emit("end");
        });

        Promise.resolve().then(() => {
            req.emit("finish");

            if (res.finished) {
                unit_lib.unit_response_end(res);
            }
        });
    });
};

function connectionListener(socket) {
}

module.exports = {
    STATUS_CODES: http.STATUS_CODES,
    Server,
    ServerResponse,
    ServerRequest,
    _connectionListener: connectionListener
};
