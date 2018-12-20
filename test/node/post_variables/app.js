#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });
    req.on('end', () => {
        let query = require('querystring').parse(body);
        res.setHeader('X-Var-1', query.var1);
        res.setHeader('X-Var-2', query.var2);
        res.setHeader('X-Var-3', query.var3);
        res.end();
    });
}).listen(7080);
