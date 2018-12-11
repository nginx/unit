#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain', 'Content-Length': 14});
    res.write('write');
    res.write('write2');
    res.end('end');
}).listen(7080);
