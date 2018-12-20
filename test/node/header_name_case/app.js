#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.setHeader('X-Header', '1');
    res.setHeader('X-header', '2');
    res.setHeader('X-HEADER', '3');
    res.end();
}).listen(7080);
