require('http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Length': 5, 'Content-Type': 'text/plain'})
        .end(new Uint8Array(Buffer.from('array', 'utf8')));
}).listen(8080);
