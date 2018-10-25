#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.setHeader('X-Header', 'test');
    res.setHeader('Was-Header', res.hasHeader('X-Header').toString());

    res.removeHeader('X-Header');
    res.setHeader('Has-Header', res.hasHeader('X-Header').toString());

    res.end();
}).listen(7080);
