#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    req.on('end', () => {
        res.writeHead(200, {'Content-Length': Buffer.byteLength(body)});
        res.end(body);
    });
}).listen(7080);
