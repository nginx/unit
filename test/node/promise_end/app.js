
var fs = require('fs');

require('http').createServer(function (req, res) {
    res.write('blah');

    Promise.resolve().then(() => {
        res.end();
    });

    req.on('data', (data) => {
        fs.appendFile('callback', '', function() {});
    });

}).listen(8080);
