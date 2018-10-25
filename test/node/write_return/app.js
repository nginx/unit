#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    res.end(res.write('body').toString());
}).listen(7080);
