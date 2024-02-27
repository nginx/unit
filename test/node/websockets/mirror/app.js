
server = require('http').createServer(function() {});
webSocketServer = require('websocket').server;

server.listen(8080, function() {});

var wsServer = new webSocketServer({
    maxReceivedMessageSize: 0x1000000000,
    maxReceivedFrameSize: 0x1000000000,
    fragmentOutgoingMessages: false,
    fragmentationThreshold: 0x1000000000,
    httpServer: server,
});

wsServer.on('request', function(request) {
    var connection = request.accept(null);

    connection.on('message', function(message) {
        if (message.type === 'utf8') {
            connection.send(message.utf8Data);
        } else if (message.type === 'binary') {
            connection.send(message.binaryData);
        }

  });

  connection.on('close', function(r) {});
});
