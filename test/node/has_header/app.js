
require('http').createServer(function (req, res) {
    res.setHeader('X-Has-Header', res.hasHeader(req.headers['x-header']) + '');
    res.end();
}).listen(8080);
