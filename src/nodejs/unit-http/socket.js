
/*
 * Copyright (C) NGINX, Inc.
 */

'use strict';

const EventEmitter = require('events');
const util = require('util');
const unit_lib = require('./build/Release/unit-http');

function Socket(options) {
    EventEmitter.call(this);

    options = options || {};

    if (typeof options !== 'object') {
        throw new TypeError('Options must be object');
    }

    if ("fd" in options) {
        throw new TypeError('Working with file descriptors not supported');
    }

    /*
     * For HTTP TCP socket 'readable' and 'writable' are always true.
     * These options are required by Express and Koa frameworks.
     */
    this.readable = true;
    this.writable = true;
}
util.inherits(Socket, EventEmitter);

Socket.prototype.bufferSize = 0;
Socket.prototype.bytesRead = 0;
Socket.prototype.bytesWritten = 0;
Socket.prototype.connecting = false;
Socket.prototype.destroyed = false;
Socket.prototype.localAddress = "";
Socket.prototype.localPort = 0;
Socket.prototype.remoteAddress = "";
Socket.prototype.remoteFamily = "";
Socket.prototype.remotePort = 0;

Socket.prototype.address = function address() {
};

Socket.prototype.connect = function connect(options, connectListener) {
    this.once('connect', connectListener);

    this.connecting = true;

    return this;
};

Socket.prototype.destroy = function destroy(exception) {
    this.connecting = false;
    this.readable = false;
    this.writable = false;

    return this;
};

Socket.prototype.end = function end(data, encoding, callback) {
};

Socket.prototype.pause = function pause() {
};

Socket.prototype.ref = function ref() {
};

Socket.prototype.resume = function resume() {
};

Socket.prototype.setEncoding = function setEncoding(encoding) {
};

Socket.prototype.setKeepAlive = function setKeepAlive(enable, initialDelay) {
};

Socket.prototype.setNoDelay = function setNoDelay(noDelay) {
};

Socket.prototype.setTimeout = function setTimeout(timeout, callback) {
    if (typeof timeout !== 'number') {
        throw new TypeError('Timeout must be number');
    }

    this.timeout = timeout;

    // this.on('timeout', callback);

    return this;
};

Socket.prototype.unref = function unref() {
};

Socket.prototype.write = function write(data, encoding, callback) {
};


module.exports = Socket;
