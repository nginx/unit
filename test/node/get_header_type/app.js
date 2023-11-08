
require('http').createServer(function (req, res) {
    res.setHeader('X-Number', 100);
    res.setHeader('X-Type', typeof(res.getHeader('X-Number')));
    res.end();
}).listen(8080);
