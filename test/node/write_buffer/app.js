#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(new Buffer([0x62, 0x75, 0x66, 0x66, 0x65, 0x72]));
}).listen(7080);
