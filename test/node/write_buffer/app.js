
require('http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'})
       .end(Buffer.from('buffer', 'utf8'));
}).listen(8080);
