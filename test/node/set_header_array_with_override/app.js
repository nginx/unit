
require('http').createServer(function (req, res) {
    res.setHeader('Set-Cookie', ['tc=one,two,three', 'tc=four,five,six']);
    res.setHeader('Set-Cookie', ['tc=one,two,three', 'tc=four,five,six', 'tc=seven,eight,nine']);
    res.end();
}).listen(8080);
