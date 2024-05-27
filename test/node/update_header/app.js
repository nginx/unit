
require('http').createServer(function (req, res) {
    res.setHeader('X-Header', 'test');
    res.setHeader('X-Header', 'new');
    res.end();
}).listen(8080);
