#!/usr/bin/env node

server = require('unit-http').createServer(function() {});
webSocketServer = require('unit-http/websocket').server;
//server = require('http').createServer(function() {});
//webSocketServer = require('websocket').server;

server.listen(7080, function() {});

var wsServer = new webSocketServer({
  httpServer: server
});

wsServer.on('request', function(request) {
  //console.log('request');
  var connection = request.accept(null);

  connection.on('message', function(message) {
    //console.log('message');
    connection.send(message.utf8Data);
  });

  connection.on('close', function(r) {
      //console.log('close');
  });
});
