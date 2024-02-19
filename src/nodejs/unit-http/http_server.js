
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

const EventEmitter = require('events');
const http = require('http');
const util = require('util');
const unit_lib = require('./build/Release/unit-http');
const Socket = require('./socket');
const WebSocketFrame = require('./websocket_frame');
const Readable = require('stream').Readable;


function ServerResponse(req) {
    EventEmitter.call(this);

    this.headers = {};

    this.server = req.server;
    this._request = req;
    req._response = this;
    this.socket = req.socket;
    this.connection = req.connection;
    this.writable = true;
}
util.inherits(ServerResponse, EventEmitter);

ServerResponse.prototype.statusCode = 200;
ServerResponse.prototype.statusMessage = undefined;
ServerResponse.prototype.headers_len = 0;
ServerResponse.prototype.headers_count = 0;
ServerResponse.prototype.headersSent = false;
ServerResponse.prototype.destroyed = false;
ServerResponse.prototype.finished = false;

ServerResponse.prototype.destroy = function destroy(error) {
    if (!this.destroyed) {
        this.destroyed = true;
    }

    return this;
};

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

ServerResponse.prototype.flushHeaders = function flushHeaders() {
    this._sendHeaders();
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

    return this;
};

/*
 * Some Node.js packages are known to be using this undocumented function,
 * notably "compression" middleware.
 */
ServerResponse.prototype._implicitHeader = function _implicitHeader() {
    this.writeHead(this.statusCode);
};

ServerResponse.prototype._send_headers = unit_lib.response_send_headers;

ServerResponse.prototype._sendHeaders = function _sendHeaders() {
    if (!this.headersSent) {
        this._send_headers(this.statusCode, this.headers, this.headers_count,
                           this.headers_len);

        this.headersSent = true;
    }
};

ServerResponse.prototype._write = unit_lib.response_write;

ServerResponse.prototype._writeBody = function(chunk, encoding, callback) {
    var contentLength = 0;
    var res, o;

    this._sendHeaders();

    if (typeof chunk === 'function') {
        callback = chunk;
        chunk = null;

    } else if (typeof encoding === 'function') {
        callback = encoding;
        encoding = null;
    }

    if (chunk) {
        if (typeof chunk !== 'string' && !(chunk instanceof Buffer ||
                chunk instanceof Uint8Array)) {
            throw new TypeError(
                'First argument must be a string, Buffer, ' +
                'or Uint8Array');
        }

        if (typeof chunk === 'string') {
            contentLength = Buffer.byteLength(chunk, encoding);

            if (contentLength > unit_lib.buf_min) {
                chunk = Buffer.from(chunk, encoding);

                contentLength = chunk.length;
            }

        } else {
            contentLength = chunk.length;
        }

        if (this.server._output.length > 0 || !this.socket.writable) {
            o = new BufferedOutput(this, 0, chunk, encoding, callback);
            this.server._output.push(o);

            return false;
        }

        res = this._write(chunk, 0, contentLength);
        if (res < contentLength) {
            this.socket.writable = false;
            this.writable = false;

            o = new BufferedOutput(this, res, chunk, encoding, callback);
            this.server._output.push(o);

            return false;
        }
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
        process.nextTick(callback);
    }

    return true;
};

ServerResponse.prototype.write = function write(chunk, encoding, callback) {
    if (this.finished) {
        if (typeof encoding === 'function') {
            callback = encoding;
            encoding = null;
        }

        var err = new Error("Write after end");
        process.nextTick(() => {
            this.emit('error', err);

            if (typeof callback === 'function') {
                callback(err);
            }
        })
    }

    return this._writeBody(chunk, encoding, callback);
};

ServerResponse.prototype._end = unit_lib.response_end;

ServerResponse.prototype.end = function end(chunk, encoding, callback) {
    if (!this.finished) {
        if (typeof encoding === 'function') {
            callback = encoding;
            encoding = null;
        }

        this._writeBody(chunk, encoding, () => {
            this._end();

            if (typeof callback === 'function') {
                callback();
            }

            this.emit("finish");
        });

        this.finished = true;
    }

    return this;
};

function ServerRequest(server, socket) {
    Readable.call(this);

    this.server = server;
    this.socket = socket;
    this.connection = socket;
    this._pushed_eofchunk = false;
}
util.inherits(ServerRequest, Readable);

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

ServerRequest.prototype._request_read = unit_lib.request_read;

ServerRequest.prototype._read = function _read(n) {
    const b = this._request_read(n);

    if (b != null) {
        this.push(b);
    }

    if (!this._pushed_eofchunk && (b == null || b.length < n)) {
        this._pushed_eofchunk = true;
        this.push(null);
    }
};


function Server(options, requestListener) {
    if (typeof options === 'function') {
        requestListener = options;
        options = {};
    } else {
        console.warn("http.Server constructor was called with unsupported options, using default settings");
    }

    EventEmitter.call(this);

    this.unit = new unit_lib.Unit();
    this.unit.server = this;

    this.unit.createServer();

    this.Socket = Socket;
    this.ServerRequest = ServerRequest;
    this.ServerResponse = ServerResponse;
    this.WebSocketFrame = WebSocketFrame;

    if (requestListener) {
        this.on('request', requestListener);
    }

    this._upgradeListenerCount = 0;
    this.on('newListener', function(ev) {
        if (ev === 'upgrade'){
            this._upgradeListenerCount++;
        }
      }).on('removeListener', function(ev) {
        if (ev === 'upgrade') {
            this._upgradeListenerCount--;
        }
    });

    this._output = [];
    this._drain_resp = new Set();
}

util.inherits(Server, EventEmitter);

Server.prototype.setTimeout = function setTimeout(msecs, callback) {
    this.timeout = msecs;

    if (callback) {
        this.on('timeout', callback);
    }

    return this;
};

Server.prototype.listen = function (...args) {
    this.unit.listen();

    if (typeof args[args.length - 1] === 'function') {
        this.once('listening', args[args.length - 1]);
    }

    /*
     * Some express.js apps use the returned server object inside the listening
     * callback, so we timeout the listening event to occur after this function
     * returns.
     */
    setImmediate(function() {
        this.emit('listening')
    }.bind(this))

    return this;
};

Server.prototype.address = function () {
    return  {
        family: "IPv4",
        address: "127.0.0.1",
        port: 80
    }
}

Server.prototype.emit_request = function (req, res) {
    if (req._websocket_handshake && this._upgradeListenerCount > 0) {
        this.emit('upgrade', req, req.socket);

    } else {
        this.emit("request", req, res);
    }
};

Server.prototype.emit_close = function () {
    this.emit('close');
};

Server.prototype.emit_drain = function () {
    var res, o, l;

    if (this._output.length <= 0) {
        return;
    }

    while (this._output.length > 0) {
        o = this._output[0];

        if (typeof o.chunk === 'string') {
            l = Buffer.byteLength(o.chunk, o.encoding);

        } else {
            l = o.chunk.length;
        }

        res = o.resp._write(o.chunk, o.offset, l);

        o.offset += res;
        if (o.offset < l) {
            return;
        }

        this._drain_resp.add(o.resp);

        if (typeof o.callback === 'function') {
            process.nextTick(o.callback);
        }

        this._output.shift();
    }

    for (var resp of this._drain_resp) {

        if (resp.socket.writable) {
            continue;
        }

        resp.socket.writable = true;
        resp.writable = true;

        process.nextTick(() => {
            resp.emit("drain");
        });
    }

    this._drain_resp.clear();
};

function BufferedOutput(resp, offset, chunk, encoding, callback) {
    this.resp = resp;
    this.offset = offset;
    this.chunk = chunk;
    this.encoding = encoding;
    this.callback = callback;
}

function connectionListener(socket) {
}

module.exports = {
    Server,
    ServerResponse,
    ServerRequest,
    _connectionListener: connectionListener
};
