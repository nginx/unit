#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.setHeader('Set-Cookie', ['tc=one,two,three', 'tc=four,five,six']);
    res.end();
}).listen(7080);
