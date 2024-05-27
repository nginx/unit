
require('http').createServer(function (req, res) {
    res.writeHead(200, 'blah', {'Content-Type': 'text/plain'}).end();
}).listen(8080);
