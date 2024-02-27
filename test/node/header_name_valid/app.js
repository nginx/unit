
require('http').createServer(function (req, res) {
    res.writeHead(200, {});
    res.setHeader('@$', 'test');
    res.end();
}).listen(8080);
