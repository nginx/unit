#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Length': 12, 'Content-Type': 'text/plain'});
    res.end('Hello World\n');
}).listen(7080);
