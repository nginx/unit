
require('http').createServer(function (req, res) {
    res.setHeader('X-Header', 'blah');
    res.flushHeaders();
    res.flushHeaders(); // Should be idempotent.
    res.end();
}).listen(8080);
