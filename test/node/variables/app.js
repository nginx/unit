#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    req.on('end', () => {
        res.setHeader('Request-Method', req.method);
        res.setHeader('Request-Uri', req.url);
        res.setHeader('Server-Protocol', req.httpVersion);
        res.setHeader('Request-Raw-Headers', req.rawHeaders.join());
        res.setHeader('Content-Length', Buffer.byteLength(body));
        res.setHeader('Content-Type', req.headers['Content-Type']);
        res.setHeader('Custom-Header', req.headers['Custom-Header']);
        res.setHeader('Http-Host', req.headers['Host']);
        res.writeHead(200, {});
        res.end(body);
    });
}).listen(7080);
