#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    var a = 'blah';
    res.write('hello', 'utf8', function() {
            a = 'world';
    });
    res.end(a);
}).listen(7080);
