#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.end();
    res.end();
}).listen(7080);
