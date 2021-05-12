
require('http').createServer(function (req, res) {
    res.setHeader('X-Header', {});
    res.end();
}).listen(7080);
