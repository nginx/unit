const dgram = require('dgram')
const server = dgram.createSocket('udp4')
server.bind(5678)

server.on('listening', function () {
  console.log('udp server linstening 5678.') // eslint-disable-line
})

server.on('message', function (msg, rinfo) {
  const message = msg.toString()
  console.log(`${new Date().getTime()}: ${message}`) // eslint-disable-line
})

server.on('error', err => {
  console.log('some error on udp server.', err.message) // eslint-disable-line
  server.close()
})
