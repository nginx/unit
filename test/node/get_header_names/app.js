#!/usr/bin/env node

require('unit-http').createServer(function (req, res) {
    res.setHeader('DATE', ['date1', 'date2']);
    res.setHeader('X-Header', 'blah');
    res.setHeader('X-Names', res.getHeaderNames());
    res.end();
}).listen(7080);
