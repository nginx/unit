
var fs = require('fs');

require('http').createServer(function (req, res) {
    res.writeHead(200, {'Content-Type': 'text/plain'});
    var a = 'world';
    res.write('hello', 'utf8', function() {
            a = 'blah';
            fs.appendFile('callback', '', function() {});
    });
    res.end(a);
}).listen(8080);
