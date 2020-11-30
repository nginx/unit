/**
 * Created by Wu Jian Ping on - 2020/11/25.
 */

const dgram = require('dgram')
const client = dgram.createSocket('udp4')

client.on('close', function () {
  console.log('udp client closed.') // eslint-disable-line
})

client.on('error', function () {
  console.log('some error on udp client.')  // eslint-disable-line
})

const send = message => {
  client.send(message, 0, message.length, 5678, '127.0.0.1')
}

module.exports.info = send

send('hello world from nodejs')