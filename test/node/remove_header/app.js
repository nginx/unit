
require('http').createServer(function (req, res) {
    res.setHeader('X-Header', 'test');
    res.setHeader('Was-Header', res.hasHeader('X-Header').toString());

    res.removeHeader(req.headers['x-remove']);
    res.setHeader('Has-Header', res.hasHeader('X-Header').toString());

    res.end();
}).listen(8080);
