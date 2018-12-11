#!/usr/bin/env node

var fs = require('fs');

require('unit-http').createServer(function (req, res) {
    res.write('blah');

    Promise.resolve().then(() => {
        res.end();
    });

    req.on('data', (data) => {
        fs.appendFile('callback', '', function() {});
    });

}).listen(7080);
