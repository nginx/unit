#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    let query = require('url').parse(req.url, true).query;
    res.setHeader('X-Var-1', query.var1);
    res.setHeader('X-Var-2', query.var2);
    res.setHeader('X-Var-3', query.var3);
    res.end();
}).listen(7080);
