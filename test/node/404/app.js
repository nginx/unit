#!/usr/bin/env node

var fs = require('fs');

require('unit-http').createServer(function (req, res) {
    res.writeHead(404, {}).end(fs.readFileSync('404.html'));
}).listen(7080);
