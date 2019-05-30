#!/usr/bin/env node

var fs = require('fs');

require('unit-http').createServer(function (req, res) {
    res.end();

    if (req.headers['x-write-call']) {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.write('blah');
    }

    Promise.resolve().then(() => {
        req.on('data', (data) => {
            fs.appendFile(data.toString(), '', function() {});
        });
    });
}).listen(7080);
