
require('http').createServer(function (req, res) {
    res.write('blah');
    res.writeHead(200, {'Content-Type': 'text/plain'}).end();
}).listen(8080);
