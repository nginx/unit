
var fs = require('fs');

require('http').createServer(function (req, res) {
    res.end();

    if (req.headers['x-write-call']) {
        res.writeHead(200, {'Content-Type': 'text/plain'}).write('blah');
    }

    Promise.resolve().then(() => {
        req.on('data', (data) => {
            fs.appendFile(data.toString(), '', function() {});
        });
    });
}).listen(8080);
