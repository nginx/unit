
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

ServerResponse.prototype.setHeader = function setHeader(name, value) {
    if (typeof name !== 'string') {
        throw new TypeError('Name argument must be a string');
    }

    let value_len = 0
    let count = 0;

    if (Array.isArray(value)) {
        count = value.length;

        value.forEach(function(val) {
            value_len += Buffer.byteLength(val + "", 'latin1');
        });

    } else {
        count = 1;
        value_len = Buffer.byteLength(value + "", 'latin1');
    }

    let lc_name = name.toLowerCase();

    if (lc_name in this.headers) {
        this._removeHeader(lc_name);
    }

    let name_len = Buffer.byteLength(name, 'latin1');

    this.headers[lc_name] = [name, value];
    this.headers_len += value_len + (name_len * count);
    this.headers_count += count;
};

ServerResponse.prototype.getHeader = function getHeader(name) {
    const entry = this.headers[name.toLowerCase()];

    return entry && entry[1];
};

ServerResponse.prototype.getHeaderNames = function getHeaderNames() {
    return Object.keys(this.headers);
};

ServerResponse.prototype.getHeaders = function getHeaders() {
    const ret = Object.create(null);

    if (this.headers) {
        const keys = Object.keys(this.headers);

        for (var i = 0; i < keys.length; i++) {
            const key = keys[i];

            ret[key] = this.headers[key][1];
        }
    }

    return ret;
};

ServerResponse.prototype.hasHeader = function hasHeader(name) {
    return name.toLowerCase() in this.headers;
};

ServerResponse.prototype.removeHeader = function removeHeader(name) {
    if (typeof name !== 'string') {
        throw new TypeError('Name argument must be a string');
    }

    let lc_name = name.toLowerCase();

    if (lc_name in this.headers) {
        this._removeHeader(lc_name);
    }
};

ServerResponse.prototype._removeHeader = function _removeHeader(lc_name) {
    let entry = this.headers[lc_name];
    let name_len = Buffer.byteLength(entry[0] + "", 'latin1');
    let value = entry[1];

    delete this.headers[lc_name];

    if (Array.isArray(value)) {
        this.headers_count -= value.length;
        this.headers_len -= value.length * name_len;

        value.forEach(function(val) {
            this.headers_len -= Buffer.byteLength(val + "", 'latin1');
        });

        return;
    }

    this.headers_count--;
    this.headers_len -= name_len + Buffer.byteLength(value + "", 'latin1');
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
};

ServerResponse.prototype._writeBody = function(chunk, encoding, callback) {
    var contentLength = 0;

    if (!this.headersSent) {
        unit_lib.unit_response_headers(this, this.statusCode, this.headers,
                                       this.headers_count, this.headers_len);

        this.headersSent = true;
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
        /*
         * The callback must be called only when response.write() caller
         * completes.  process.nextTick() postpones the callback execution.
         *
         * process.nextTick() is not technically part of the event loop.
         * Instead, the nextTickQueue will be processed after the current
         * operation completes, regardless of the current phase of
         * the event loop.  All callbacks passed to process.nextTick()
         * will be resolved before the event loop continues.
         */
        process.nextTick(function () {
            callback(this);
        }.bind(this));
    }
};

ServerResponse.prototype.write = function write(chunk, encoding, callback) {
    if (this.finished) {
        throw new Error("Write after end");
    }

    this._writeBody(chunk, encoding, callback);

    return true;
};

ServerResponse.prototype.end = function end(chunk, encoding, callback) {
    if (!this.finished) {
        this._writeBody(chunk, encoding, callback);

        unit_lib.unit_response_end(this);

        this.finished = true;
    }

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

/*
 * The "on" method is overridden to defer reading data until user code is
 * ready, that is (ev === "data").  This can occur after req.emit("end") is
 * executed, since the user code can be scheduled asynchronously by Promises
 * and so on.  Passing the data is postponed by process.nextTick() until
 * the "on" method caller completes.
 */
ServerRequest.prototype.on = function on(ev, fn) {
    Server.prototype.on.call(this, ev, fn);

    if (ev === "data") {
        process.nextTick(function () {
            if (this.server.buffer.length !== 0) {
                this.emit("data", this.server.buffer);
            }

        }.bind(this));
    }
};

ServerRequest.prototype.addListener = ServerRequest.prototype.on;

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

Server.prototype.emit_events = function (server, req, res) {
    req.server = server;
    res.server = server;
    req.res = res;
    res.req = req;

    server.buffer = server.unit._read(req.socket.req_pointer);

    server.emit("request", req, res);

    process.nextTick(() => {
        req.emit("finish");
        req.emit("end");
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
