
var fs = require('fs');

require('http').createServer(function (req, res) {
    res.writeHead(404, {}).end(fs.readFileSync('404.html'));
}).listen(8080);
