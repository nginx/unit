#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.end().end();
}).listen(7080);
