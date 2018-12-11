#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.setHeader('X-Has-Header', res.hasHeader(req['headers']['X-Header']) + '');
    res.end();
}).listen(7080);
