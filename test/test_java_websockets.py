import time
import struct
import unittest
from unit.applications.lang.java import TestApplicationJava
from unit.applications.websockets import TestApplicationWebsocket


class TestJavaWebsockets(TestApplicationJava):
    prerequisites = {'modules': ['java']}

    ws = TestApplicationWebsocket()

    def setUp(self):
        super().setUp()

        self.assertIn(
            'success',
            self.conf(
                {'http': {'websocket': {'keepalive_interval': 0}}}, 'settings'
            ),
            'clear keepalive_interval',
        )

        self.skip_alerts.extend(
            [r'last message send failed', r'socket close\(\d+\) failed']
        )

    def close_connection(self, sock):
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty sock')

        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())

        self.check_close(sock)

    def check_close(self, sock, code=1000, no_close=False):
        frame = self.ws.frame_read(sock)

        self.assertEqual(frame['fin'], True, 'close fin')
        self.assertEqual(frame['opcode'], self.ws.OP_CLOSE, 'close opcode')
        self.assertEqual(frame['code'], code, 'close code')

        if not no_close:
            sock.close()

    def check_frame(self, frame, fin, opcode, payload, decode=True):
        if opcode == self.ws.OP_BINARY or not decode:
            data = frame['data']
        else:
            data = frame['data'].decode('utf-8')

        self.assertEqual(frame['fin'], fin, 'fin')
        self.assertEqual(frame['opcode'], opcode, 'opcode')
        self.assertEqual(data, payload, 'payload')

    def test_java_websockets_handshake(self):
        self.load('websockets_mirror')

        resp, sock, key = self.ws.upgrade()
        sock.close()

        self.assertEqual(resp['status'], 101, 'status')
        self.assertEqual(resp['headers']['Upgrade'], 'websocket', 'upgrade')
        self.assertEqual(
            resp['headers']['Connection'], 'Upgrade', 'connection'
        )
        self.assertEqual(
            resp['headers']['Sec-WebSocket-Accept'], self.ws.accept(key), 'key'
        )

    def test_java_websockets_mirror(self):
        self.load('websockets_mirror')

        message = 'blah'

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, message)
        frame = self.ws.frame_read(sock)

        self.assertEqual(message, frame['data'].decode('utf-8'), 'mirror')

        self.ws.frame_write(sock, self.ws.OP_TEXT, message)
        frame = self.ws.frame_read(sock)

        self.assertEqual(message, frame['data'].decode('utf-8'), 'mirror 2')

        sock.close()

    def test_java_websockets_no_mask(self):
        self.load('websockets_mirror')

        message = 'blah'

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, message, mask=False)

        frame = self.ws.frame_read(sock)

        self.assertEqual(frame['opcode'], self.ws.OP_CLOSE, 'no mask opcode')
        self.assertEqual(frame['code'], 1002, 'no mask close code')

        sock.close()

    def test_java_websockets_fragmentation(self):
        self.load('websockets_mirror')

        message = 'blah'

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, message, fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, ' ', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, message)

        frame = self.ws.frame_read(sock)

        self.assertEqual(
            message + ' ' + message,
            frame['data'].decode('utf-8'),
            'mirror framing',
        )

        sock.close()

    def test_java_websockets_frame_fragmentation_invalid(self):
        self.load('websockets_mirror')

        message = 'blah'

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_PING, message, fin=False)

        frame = self.ws.frame_read(sock)

        frame.pop('data')
        self.assertDictEqual(
            frame,
            {
                'fin': True,
                'rsv1': False,
                'rsv2': False,
                'rsv3': False,
                'opcode': self.ws.OP_CLOSE,
                'mask': 0,
                'code': 1002,
                'reason': 'Fragmented control frame',
            },
            'close frame',
        )

        sock.close()

    def test_java_websockets_two_clients(self):
        self.load('websockets_mirror')

        message1 = 'blah1'
        message2 = 'blah2'

        _, sock1, _ = self.ws.upgrade()
        _, sock2, _ = self.ws.upgrade()

        self.ws.frame_write(sock1, self.ws.OP_TEXT, message1)
        self.ws.frame_write(sock2, self.ws.OP_TEXT, message2)

        frame1 = self.ws.frame_read(sock1)
        frame2 = self.ws.frame_read(sock2)

        self.assertEqual(message1, frame1['data'].decode('utf-8'), 'client 1')
        self.assertEqual(message2, frame2['data'].decode('utf-8'), 'client 2')

        sock1.close()
        sock2.close()

    @unittest.skip('not yet')
    def test_java_websockets_handshake_upgrade_absent(
        self
    ):  # FAIL https://tools.ietf.org/html/rfc6455#section-4.2.1
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 400, 'upgrade absent')

    def test_java_websockets_handshake_case_insensitive(self):
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'WEBSOCKET',
                'Connection': 'UPGRADE',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 101, 'status')

    @unittest.skip('not yet')
    def test_java_websockets_handshake_connection_absent(self):  # FAIL
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 400, 'status')

    def test_java_websockets_handshake_version_absent(self):
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 426, 'status')

    @unittest.skip('not yet')
    def test_java_websockets_handshake_key_invalid(self):
        self.load('websockets_mirror')

        self.get()

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': '!',
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 400, 'key length')

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': [key, key],
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(
            resp['status'], 400, 'key double'
        )  # FAIL https://tools.ietf.org/html/rfc6455#section-11.3.1

    def test_java_websockets_handshake_method_invalid(self):
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.post(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 400, 'status')

    def test_java_websockets_handshake_http_10(self):
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            http_10=True,
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 400, 'status')

    def test_java_websockets_handshake_uri_invalid(self):
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat',
                'Sec-WebSocket-Version': 13,
            },
            url='!',
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 400, 'status')

    def test_java_websockets_protocol_absent(self):
        self.load('websockets_mirror')

        self.get()

        key = self.ws.key()
        resp = self.get(
            headers={
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Version': 13,
            },
            read_timeout=1,
        )

        self.assertEqual(resp['status'], 101, 'status')
        self.assertEqual(resp['headers']['Upgrade'], 'websocket', 'upgrade')
        self.assertEqual(
            resp['headers']['Connection'], 'Upgrade', 'connection'
        )
        self.assertEqual(
            resp['headers']['Sec-WebSocket-Accept'], self.ws.accept(key), 'key'
        )

    # autobahn-testsuite
    #
    # Some following tests fail because of Unit does not support UTF-8
    # validation for websocket frames.  It should be implemented
    # by application, if necessary.

    def test_java_websockets_1_1_1__1_1_8(self):
        self.load('websockets_mirror')

        opcode = self.ws.OP_TEXT

        _, sock, _ = self.ws.upgrade()

        def check_length(length, chopsize=None):
            payload = '*' * length

            self.ws.frame_write(sock, opcode, payload, chopsize=chopsize)

            frame = self.ws.message_read(sock)
            self.check_frame(frame, True, opcode, payload)

        check_length(0)                      # 1_1_1
        check_length(125)                    # 1_1_2
        check_length(126)                    # 1_1_3
        check_length(127)                    # 1_1_4
        check_length(128)                    # 1_1_5
        check_length(65535)                  # 1_1_6
        check_length(65536)                  # 1_1_7
        check_length(65536, chopsize = 997)  # 1_1_8

        self.close_connection(sock)

    def test_java_websockets_1_2_1__1_2_8(self):
        self.load('websockets_mirror')

        opcode = self.ws.OP_BINARY

        _, sock, _ = self.ws.upgrade()

        def check_length(length, chopsize=None):
            payload = b'\xfe' * length

            self.ws.frame_write(sock, opcode, payload, chopsize=chopsize)

            frame = self.ws.message_read(sock)
            self.check_frame(frame, True, opcode, payload)

        check_length(0)                      # 1_2_1
        check_length(125)                    # 1_2_2
        check_length(126)                    # 1_2_3
        check_length(127)                    # 1_2_4
        check_length(128)                    # 1_2_5
        check_length(65535)                  # 1_2_6
        check_length(65536)                  # 1_2_7
        check_length(65536, chopsize = 997)  # 1_2_8

        self.close_connection(sock)

    def test_java_websockets_2_1__2_6(self):
        self.load('websockets_mirror')

        op_ping = self.ws.OP_PING
        op_pong = self.ws.OP_PONG

        _, sock, _ = self.ws.upgrade()

        def check_ping(payload, chopsize=None, decode=True):
            self.ws.frame_write(sock, op_ping, payload, chopsize=chopsize)
            frame = self.ws.frame_read(sock)

            self.check_frame(frame, True, op_pong, payload, decode=decode)

        check_ping('')                                                 # 2_1
        check_ping('Hello, world!')                                    # 2_2
        check_ping(b'\x00\xff\xfe\xfd\xfc\xfb\x00\xff', decode=False)  # 2_3
        check_ping(b'\xfe' * 125, decode=False)                        # 2_4
        check_ping(b'\xfe' * 125, chopsize=1, decode=False)            # 2_6

        self.close_connection(sock)

        # 2_5

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_PING, b'\xfe' * 126)
        self.check_close(sock, 1002)

    def test_java_websockets_2_7__2_9(self):
        self.load('websockets_mirror')

        # 2_7

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_PONG, '')
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', '2_7')

        # 2_8

        self.ws.frame_write(sock, self.ws.OP_PONG, 'unsolicited pong payload')
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', '2_8')

        # 2_9

        payload = 'ping payload'

        self.ws.frame_write(sock, self.ws.OP_PONG, 'unsolicited pong payload')
        self.ws.frame_write(sock, self.ws.OP_PING, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, payload)

        self.close_connection(sock)

    def test_java_websockets_2_10__2_11(self):
        self.load('websockets_mirror')

        # 2_10

        _, sock, _ = self.ws.upgrade()

        for i in range(0, 10):
            self.ws.frame_write(sock, self.ws.OP_PING, 'payload-%d' % i)

        for i in range(0, 10):
            frame = self.ws.frame_read(sock)
            self.check_frame(frame, True, self.ws.OP_PONG, 'payload-%d' % i)

        # 2_11

        for i in range(0, 10):
            opcode = self.ws.OP_PING
            self.ws.frame_write(sock, opcode, 'payload-%d' % i, chopsize=1)

        for i in range(0, 10):
            frame = self.ws.frame_read(sock)
            self.check_frame(frame, True, self.ws.OP_PONG, 'payload-%d' % i)

        self.close_connection(sock)

    @unittest.skip('not yet')
    def test_java_websockets_3_1__3_7(self):
        self.load('websockets_mirror')

        payload = 'Hello, world!'

        # 3_1

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload, rsv1=True)
        self.check_close(sock, 1002)

        # 3_2

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)
        self.ws.frame_write(sock, self.ws.OP_TEXT, payload, rsv2=True)
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.check_close(sock, 1002, no_close=True)

        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty 3_2')
        sock.close()

        # 3_3

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(
            sock, self.ws.OP_TEXT, payload, rsv1=True, rsv2=True
        )

        self.check_close(sock, 1002, no_close=True)

        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty 3_3')
        sock.close()

        # 3_4

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload, chopsize=1)
        self.ws.frame_write(
            sock, self.ws.OP_TEXT, payload, rsv3=True, chopsize=1
        )
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.check_close(sock, 1002, no_close=True)

        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty 3_4')
        sock.close()

        # 3_5

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock,
            self.ws.OP_BINARY,
            b'\x00\xff\xfe\xfd\xfc\xfb\x00\xff',
            rsv1=True,
            rsv3=True,
        )

        self.check_close(sock, 1002)

        # 3_6

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock, self.ws.OP_PING, payload, rsv2=True, rsv3=True
        )

        self.check_close(sock, 1002)

        # 3_7

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock, self.ws.OP_CLOSE, payload, rsv1=True, rsv2=True, rsv3=True
        )

        self.check_close(sock, 1002)

    def test_java_websockets_4_1_1__4_2_5(self):
        self.load('websockets_mirror')

        payload = 'Hello, world!'

        # 4_1_1

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, 0x03, '')
        self.check_close(sock, 1002)

        # 4_1_2

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, 0x04, 'reserved opcode payload')
        self.check_close(sock, 1002)

        # 4_1_3

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(sock, 0x05, '')
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        self.check_close(sock, 1002)

        # 4_1_4

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(sock, 0x06, payload)
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        self.check_close(sock, 1002)

        # 4_1_5

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload, chopsize=1)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(sock, 0x07, payload, chopsize=1)
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        self.check_close(sock, 1002)

        # 4_2_1

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, 0x0B, '')
        self.check_close(sock, 1002)

        # 4_2_2

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, 0x0C, 'reserved opcode payload')
        self.check_close(sock, 1002)

        # 4_2_3

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(sock, 0x0D, '')
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        self.check_close(sock, 1002)

        # 4_2_4

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(sock, 0x0E, payload)
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        self.check_close(sock, 1002)

        # 4_2_5

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload, chopsize=1)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.ws.frame_write(sock, 0x0F, payload, chopsize=1)
        self.ws.frame_write(sock, self.ws.OP_PING, '')

        self.check_close(sock, 1002)

    def test_java_websockets_5_1__5_20(self):
        self.load('websockets_mirror')

        # 5_1

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_PING, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)
        self.check_close(sock, 1002)

        # 5_2

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_PONG, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)
        self.check_close(sock, 1002)

        # 5_3

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, 'fragment1fragment2')

        # 5_4

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', '5_4')
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, 'fragment1fragment2')

        # 5_5

        self.ws.frame_write(
            sock, self.ws.OP_TEXT, 'fragment1', fin=False, chopsize=1
        )
        self.ws.frame_write(
            sock, self.ws.OP_CONT, 'fragment2', fin=True, chopsize=1
        )

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, 'fragment1fragment2')

        # 5_6

        ping_payload = 'ping payload'

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_PING, ping_payload)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, ping_payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, 'fragment1fragment2')

        # 5_7

        ping_payload = 'ping payload'

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', '5_7')

        self.ws.frame_write(sock, self.ws.OP_PING, ping_payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, ping_payload)

        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, 'fragment1fragment2')

        # 5_8

        ping_payload = 'ping payload'

        self.ws.frame_write(
            sock, self.ws.OP_TEXT, 'fragment1', fin=False, chopsize=1
        )
        self.ws.frame_write(sock, self.ws.OP_PING, ping_payload, chopsize=1)
        self.ws.frame_write(
            sock, self.ws.OP_CONT, 'fragment2', fin=True, chopsize=1
        )

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, ping_payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, 'fragment1fragment2')

        # 5_9

        self.ws.frame_write(
            sock, self.ws.OP_CONT, 'non-continuation payload', fin=True
        )
        self.ws.frame_write(sock, self.ws.OP_TEXT, 'Hello, world!', fin=True)
        self.check_close(sock, 1002)

        # 5_10

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock, self.ws.OP_CONT, 'non-continuation payload', fin=True
        )
        self.ws.frame_write(sock, self.ws.OP_TEXT, 'Hello, world!', fin=True)
        self.check_close(sock, 1002)

        # 5_11

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock,
            self.ws.OP_CONT,
            'non-continuation payload',
            fin=True,
            chopsize=1,
        )
        self.ws.frame_write(
            sock, self.ws.OP_TEXT, 'Hello, world!', fin=True, chopsize=1
        )
        self.check_close(sock, 1002)

        # 5_12

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock, self.ws.OP_CONT, 'non-continuation payload', fin=False
        )
        self.ws.frame_write(sock, self.ws.OP_TEXT, 'Hello, world!', fin=True)
        self.check_close(sock, 1002)

        # 5_13

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock, self.ws.OP_CONT, 'non-continuation payload', fin=False
        )
        self.ws.frame_write(sock, self.ws.OP_TEXT, 'Hello, world!', fin=True)
        self.check_close(sock, 1002)

        # 5_14

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(
            sock,
            self.ws.OP_CONT,
            'non-continuation payload',
            fin=False,
            chopsize=1,
        )
        self.ws.frame_write(
            sock, self.ws.OP_TEXT, 'Hello, world!', fin=True, chopsize=1
        )
        self.check_close(sock, 1002)

        # 5_15

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=True)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment3', fin=False)
        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment4', fin=True)
        self.check_close(sock, 1002)

        # 5_16

        _, sock, _ = self.ws.upgrade()

        for i in range(0, 2):
            self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment1', fin=False)
            self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment2', fin=False)
            self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment3', fin=True)
        self.check_close(sock, 1002)

        # 5_17

        _, sock, _ = self.ws.upgrade()

        for i in range(0, 2):
            self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment1', fin=True)
            self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment2', fin=False)
            self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment3', fin=True)
        self.check_close(sock, 1002)

        # 5_18

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment2')
        self.check_close(sock, 1002)

        # 5_19

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=False)
        self.ws.frame_write(sock, self.ws.OP_PING, 'pongme 1!')

        time.sleep(1)

        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment3', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment4', fin=False)
        self.ws.frame_write(sock, self.ws.OP_PING, 'pongme 2!')
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment5')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, 'pongme 1!')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, 'pongme 2!')

        self.check_frame(
            self.ws.frame_read(sock),
            True,
            self.ws.OP_TEXT,
            'fragment1fragment2fragment3fragment4fragment5',
        )

        # 5_20

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2', fin=False)
        self.ws.frame_write(sock, self.ws.OP_PING, 'pongme 1!')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, 'pongme 1!')

        time.sleep(1)

        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment3', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment4', fin=False)
        self.ws.frame_write(sock, self.ws.OP_PING, 'pongme 2!')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PONG, 'pongme 2!')

        self.assertEqual(self.recvall(sock, read_timeout=1), b'', '5_20')
        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment5')

        self.check_frame(
            self.ws.frame_read(sock),
            True,
            self.ws.OP_TEXT,
            'fragment1fragment2fragment3fragment4fragment5',
        )

        self.close_connection(sock)

    def test_java_websockets_6_1_1__6_4_4(self):
        self.load('websockets_mirror')

        # 6_1_1

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, '')
        frame = self.ws.frame_read(sock, read_timeout=3)
        self.check_frame(frame, True, self.ws.OP_TEXT, '')

        # 6_1_2

        self.ws.frame_write(sock, self.ws.OP_TEXT, '', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, '', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, '')

        frame = self.ws.frame_read(sock, read_timeout=3)
        self.check_frame(frame, True, self.ws.OP_TEXT, '')

        # 6_1_3

        payload = 'middle frame payload'

        self.ws.frame_write(sock, self.ws.OP_TEXT, '', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, payload, fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, '')

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        # 6_2_1

        payload = 'Hello-µ@ßöäüàá-UTF-8!!'

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        # 6_2_2

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload[:12], fin=False)
        self.ws.frame_write(sock, self.ws.OP_CONT, payload[12:])

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        # 6_2_3

        self.ws.message(sock, self.ws.OP_TEXT, payload, fragmention_size=1)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        # 6_2_4

        payload = '\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5'

        self.ws.message(sock, self.ws.OP_TEXT, payload, fragmention_size=1)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.close_connection(sock)

#        Unit does not support UTF-8 validation
#
#        # 6_3_1 FAIL
#
#        payload_1 = '\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5'
#        payload_2 = '\xed\xa0\x80'
#        payload_3 = '\x65\x64\x69\x74\x65\x64'
#
#        payload = payload_1 + payload_2 + payload_3
#
#        self.ws.message(sock, self.ws.OP_TEXT, payload)
#        self.check_close(sock, 1007)
#
#        # 6_3_2 FAIL
#
#        _, sock, _ = self.ws.upgrade()
#
#        self.ws.message(sock, self.ws.OP_TEXT, payload, fragmention_size=1)
#        self.check_close(sock, 1007)
#
#        # 6_4_1 ... 6_4_4 FAIL

    def test_java_websockets_7_1_1__7_5_1(self):
        self.load('websockets_mirror')

        # 7_1_1

        _, sock, _ = self.ws.upgrade()

        payload = "Hello World!"

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.close_connection(sock)

        # 7_1_2

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())
        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())

        self.check_close(sock)

        # 7_1_3

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())
        self.check_close(sock, no_close=True)

        self.ws.frame_write(sock, self.ws.OP_PING, '')
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty sock')

        sock.close()

        # 7_1_4

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())
        self.check_close(sock, no_close=True)

        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty sock')

        sock.close()

        # 7_1_5

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'fragment1', fin=False)
        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())
        self.check_close(sock, no_close=True)

        self.ws.frame_write(sock, self.ws.OP_CONT, 'fragment2')
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty sock')

        sock.close()

        # 7_1_6

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_TEXT, 'BAsd7&jh23' * 26 * 2 ** 10)
        self.ws.frame_write(sock, self.ws.OP_TEXT, payload)
        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())

        self.recvall(sock, read_timeout=1)

        self.ws.frame_write(sock, self.ws.OP_PING, '')
        self.assertEqual(self.recvall(sock, read_timeout=1), b'', 'empty sock')

        sock.close()

        # 7_3_1 # FAIL

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_CLOSE, '')
        self.check_close(sock)

        # 7_3_2

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_CLOSE, 'a')
        self.check_close(sock, 1002)

        # 7_3_3

        _, sock, _ = self.ws.upgrade()

        self.ws.frame_write(sock, self.ws.OP_CLOSE, self.ws.serialize_close())
        self.check_close(sock)

        # 7_3_4

        _, sock, _ = self.ws.upgrade()

        payload = self.ws.serialize_close(reason='Hello World!')

        self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
        self.check_close(sock)

        # 7_3_5

        _, sock, _ = self.ws.upgrade()

        payload = self.ws.serialize_close(reason='*' * 123)

        self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
        self.check_close(sock)

        # 7_3_6

        _, sock, _ = self.ws.upgrade()

        payload = self.ws.serialize_close(reason='*' * 124)

        self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
        self.check_close(sock, 1002)

#        # 7_5_1 FAIL Unit does not support UTF-8 validation
#
#        _, sock, _ = self.ws.upgrade()
#
#        payload = self.ws.serialize_close(reason = '\xce\xba\xe1\xbd\xb9\xcf' \
#            '\x83\xce\xbc\xce\xb5\xed\xa0\x80\x65\x64\x69\x74\x65\x64')
#
#        self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
#        self.check_close(sock, 1007)

    def test_java_websockets_7_7_X__7_9_X(self):
        self.load('websockets_mirror')

        valid_codes = [
            1000,
            1001,
            1002,
            1003,
            1007,
            1008,
            1009,
            1010,
            1011,
            3000,
            3999,
            4000,
            4999,
        ]

        invalid_codes = [0, 999, 1004, 1005, 1006, 1016, 1100, 2000, 2999]

        for code in valid_codes:
            _, sock, _ = self.ws.upgrade()

            payload = self.ws.serialize_close(code=code)

            self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
            self.check_close(sock, code=code)

        for code in invalid_codes:
            _, sock, _ = self.ws.upgrade()

            payload = self.ws.serialize_close(code=code)

            self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
            self.check_close(sock, 1002)

    def test_java_websockets_7_13_1__7_13_2(self):
        self.load('websockets_mirror')

        # 7_13_1

        _, sock, _ = self.ws.upgrade()

        payload = self.ws.serialize_close(code=5000)

        self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
        self.check_close(sock, 1002)

        # 7_13_2

        _, sock, _ = self.ws.upgrade()

        payload = struct.pack('!I', 65536) + ''.encode('utf-8')

        self.ws.frame_write(sock, self.ws.OP_CLOSE, payload)
        self.check_close(sock, 1002)

    def test_java_websockets_9_1_1__9_6_6(self):
        if not self.unsafe:
            self.skipTest("unsafe, long run")

        self.load('websockets_mirror')

        self.assertIn(
            'success',
            self.conf(
                {
                    'http': {
                        'websocket': {
                            'max_frame_size': 33554432,
                            'keepalive_interval': 0,
                        }
                    }
                },
                'settings',
            ),
            'increase max_frame_size and keepalive_interval',
        )

        _, sock, _ = self.ws.upgrade()

        op_text = self.ws.OP_TEXT
        op_binary = self.ws.OP_BINARY

        def check_payload(opcode, length, chopsize=None):
            if opcode == self.ws.OP_TEXT:
                payload = '*' * length
            else:
                payload = b'*' * length

            self.ws.frame_write(sock, opcode, payload, chopsize=chopsize)
            frame = self.ws.frame_read(sock)
            self.check_frame(frame, True, opcode, payload)

        def check_message(opcode, f_size):
            if opcode == self.ws.OP_TEXT:
                payload = '*' * 4 * 2 ** 20
            else:
                payload = b'*' * 4 * 2 ** 20

            self.ws.message(sock, opcode, payload, fragmention_size=f_size)
            frame = self.ws.frame_read(sock, read_timeout=5)
            self.check_frame(frame, True, opcode, payload)

        check_payload(op_text, 64 * 2 ** 10)              # 9_1_1
        check_payload(op_text, 256 * 2 ** 10)             # 9_1_2
        check_payload(op_text, 2 ** 20)                   # 9_1_3
        check_payload(op_text, 4 * 2 ** 20)               # 9_1_4
        check_payload(op_text, 8 * 2 ** 20)               # 9_1_5
        check_payload(op_text, 16 * 2 ** 20)              # 9_1_6

        check_payload(op_binary, 64 * 2 ** 10)            # 9_2_1
        check_payload(op_binary, 256 * 2 ** 10)           # 9_2_2
        check_payload(op_binary, 2 ** 20)                 # 9_2_3
        check_payload(op_binary, 4 * 2 ** 20)             # 9_2_4
        check_payload(op_binary, 8 * 2 ** 20)             # 9_2_5
        check_payload(op_binary, 16 * 2 ** 20)            # 9_2_6

        if self.system != 'Darwin' and self.system != 'FreeBSD':
            check_message(op_text, 64)                    # 9_3_1
            check_message(op_text, 256)                   # 9_3_2
            check_message(op_text, 2 ** 10)               # 9_3_3
            check_message(op_text, 4 * 2 ** 10)           # 9_3_4
            check_message(op_text, 16 * 2 ** 10)          # 9_3_5
            check_message(op_text, 64 * 2 ** 10)          # 9_3_6
            check_message(op_text, 256 * 2 ** 10)         # 9_3_7
            check_message(op_text, 2 ** 20)               # 9_3_8
            check_message(op_text, 4 * 2 ** 20)           # 9_3_9

            check_message(op_binary, 64)                  # 9_4_1
            check_message(op_binary, 256)                 # 9_4_2
            check_message(op_binary, 2 ** 10)             # 9_4_3
            check_message(op_binary, 4 * 2 ** 10)         # 9_4_4
            check_message(op_binary, 16 * 2 ** 10)        # 9_4_5
            check_message(op_binary, 64 * 2 ** 10)        # 9_4_6
            check_message(op_binary, 256 * 2 ** 10)       # 9_4_7
            check_message(op_binary, 2 ** 20)             # 9_4_8
            check_message(op_binary, 4 * 2 ** 20)         # 9_4_9

        check_payload(op_text, 2 ** 20, chopsize=64)      # 9_5_1
        check_payload(op_text, 2 ** 20, chopsize=128)     # 9_5_2
        check_payload(op_text, 2 ** 20, chopsize=256)     # 9_5_3
        check_payload(op_text, 2 ** 20, chopsize=512)     # 9_5_4
        check_payload(op_text, 2 ** 20, chopsize=1024)    # 9_5_5
        check_payload(op_text, 2 ** 20, chopsize=2048)    # 9_5_6

        check_payload(op_binary, 2 ** 20, chopsize=64)    # 9_6_1
        check_payload(op_binary, 2 ** 20, chopsize=128)   # 9_6_2
        check_payload(op_binary, 2 ** 20, chopsize=256)   # 9_6_3
        check_payload(op_binary, 2 ** 20, chopsize=512)   # 9_6_4
        check_payload(op_binary, 2 ** 20, chopsize=1024)  # 9_6_5
        check_payload(op_binary, 2 ** 20, chopsize=2048)  # 9_6_6

        self.close_connection(sock)

    def test_java_websockets_10_1_1(self):
        self.load('websockets_mirror')

        _, sock, _ = self.ws.upgrade()

        payload = '*' * 65536

        self.ws.message(sock, self.ws.OP_TEXT, payload, fragmention_size=1300)

        frame = self.ws.message_read(sock)
        self.check_frame(frame, True, self.ws.OP_TEXT, payload)

        self.close_connection(sock)

    # settings

    def test_java_websockets_max_frame_size(self):
        self.load('websockets_mirror')

        self.assertIn(
            'success',
            self.conf(
                {'http': {'websocket': {'max_frame_size': 100}}}, 'settings'
            ),
            'configure max_frame_size',
        )

        _, sock, _ = self.ws.upgrade()

        payload = '*' * 94
        opcode = self.ws.OP_TEXT

        self.ws.frame_write(sock, opcode, payload)  # frame length is 100

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, opcode, payload)

        payload = '*' * 95

        self.ws.frame_write(sock, opcode, payload)  # frame length is 101
        self.check_close(sock, 1009)  # 1009 - CLOSE_TOO_LARGE

    def test_java_websockets_read_timeout(self):
        self.load('websockets_mirror')

        self.assertIn(
            'success',
            self.conf(
                {'http': {'websocket': {'read_timeout': 5}}}, 'settings'
            ),
            'configure read_timeout',
        )

        _, sock, _ = self.ws.upgrade()

        frame = self.ws.frame_to_send(self.ws.OP_TEXT, 'blah')
        sock.sendall(frame[:2])

        time.sleep(2)

        self.check_close(sock, 1001)  # 1001 - CLOSE_GOING_AWAY

    def test_java_websockets_keepalive_interval(self):
        self.load('websockets_mirror')

        self.assertIn(
            'success',
            self.conf(
                {'http': {'websocket': {'keepalive_interval': 5}}}, 'settings'
            ),
            'configure keepalive_interval',
        )

        _, sock, _ = self.ws.upgrade()

        frame = self.ws.frame_to_send(self.ws.OP_TEXT, 'blah')
        sock.sendall(frame[:2])

        time.sleep(2)

        frame = self.ws.frame_read(sock)
        self.check_frame(frame, True, self.ws.OP_PING, '')  # PING frame

        sock.close()


if __name__ == '__main__':
    TestJavaWebsockets.main()
