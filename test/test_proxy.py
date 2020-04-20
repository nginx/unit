import re
import time
import socket
import unittest
from unit.applications.lang.python import TestApplicationPython


class TestProxy(TestApplicationPython):
    prerequisites = {'modules': ['python']}

    SERVER_PORT = 7999

    @staticmethod
    def run_server(server_port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_address = ('', server_port)
        sock.bind(server_address)
        sock.listen(5)

        def recvall(sock):
            buff_size = 4096
            data = b''
            while True:
                part = sock.recv(buff_size)
                data += part
                if len(part) < buff_size:
                    break
            return data

        req = b"""HTTP/1.1 200 OK
Content-Length: 10

"""

        while True:
            connection, client_address = sock.accept()

            data = recvall(connection).decode()

            to_send = req

            m = re.search('X-Len: (\d+)', data)
            if m:
                to_send += b'X' * int(m.group(1))

            connection.sendall(to_send)

            connection.close()

    def get_http10(self, *args, **kwargs):
        return self.get(*args, http_10=True, **kwargs)

    def post_http10(self, *args, **kwargs):
        return self.post(*args, http_10=True, **kwargs)

    def setUp(self):
        super().setUp()

        self.run_process(self.run_server, self.SERVER_PORT)
        self.waitforsocket(self.SERVER_PORT)

        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "routes"},
                        "*:7081": {"pass": "applications/mirror"},
                    },
                    "routes": [{"action": {"proxy": "http://127.0.0.1:7081"}}],
                    "applications": {
                        "mirror": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/mirror",
                            "working_directory": self.current_dir
                            + "/python/mirror",
                            "module": "wsgi",
                        },
                        "custom_header": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/custom_header",
                            "working_directory": self.current_dir
                            + "/python/custom_header",
                            "module": "wsgi",
                        },
                        "delayed": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/delayed",
                            "working_directory": self.current_dir
                            + "/python/delayed",
                            "module": "wsgi",
                        },
                    },
                }
            ),
            'proxy initial configuration',
        )

    def test_proxy_http10(self):
        for _ in range(10):
            self.assertEqual(self.get_http10()['status'], 200, 'status')

    def test_proxy_chain(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "routes/first"},
                        "*:7081": {"pass": "routes/second"},
                        "*:7082": {"pass": "routes/third"},
                        "*:7083": {"pass": "routes/fourth"},
                        "*:7084": {"pass": "routes/fifth"},
                        "*:7085": {"pass": "applications/mirror"},
                    },
                    "routes": {
                        "first": [
                            {"action": {"proxy": "http://127.0.0.1:7081"}}
                        ],
                        "second": [
                            {"action": {"proxy": "http://127.0.0.1:7082"}}
                        ],
                        "third": [
                            {"action": {"proxy": "http://127.0.0.1:7083"}}
                        ],
                        "fourth": [
                            {"action": {"proxy": "http://127.0.0.1:7084"}}
                        ],
                        "fifth": [
                            {"action": {"proxy": "http://127.0.0.1:7085"}}
                        ],
                    },
                    "applications": {
                        "mirror": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/mirror",
                            "working_directory": self.current_dir
                            + "/python/mirror",
                            "module": "wsgi",
                        }
                    },
                }
            ),
            'proxy chain configuration',
        )

        self.assertEqual(self.get_http10()['status'], 200, 'status')

    def test_proxy_body(self):
        payload = '0123456789'
        for _ in range(10):
            resp = self.post_http10(body=payload)

            self.assertEqual(resp['status'], 200, 'status')
            self.assertEqual(resp['body'], payload, 'body')

        payload = 'X' * 4096
        for _ in range(10):
            resp = self.post_http10(body=payload)

            self.assertEqual(resp['status'], 200, 'status')
            self.assertEqual(resp['body'], payload, 'body')

        payload = 'X' * 4097
        for _ in range(10):
            resp = self.post_http10(body=payload)

            self.assertEqual(resp['status'], 200, 'status')
            self.assertEqual(resp['body'], payload, 'body')

        payload = 'X' * 4096 * 256
        for _ in range(10):
            resp = self.post_http10(body=payload, read_buffer_size=4096 * 128)

            self.assertEqual(resp['status'], 200, 'status')
            self.assertEqual(resp['body'], payload, 'body')

        payload = 'X' * 4096 * 257
        for _ in range(10):
            resp = self.post_http10(body=payload, read_buffer_size=4096 * 128)

            self.assertEqual(resp['status'], 200, 'status')
            self.assertEqual(resp['body'], payload, 'body')

        self.conf({'http': {'max_body_size': 32 * 1024 * 1024}}, 'settings')

        payload = '0123456789abcdef' * 32 * 64 * 1024
        resp = self.post_http10(body=payload, read_buffer_size=1024 * 1024)
        self.assertEqual(resp['status'], 200, 'status')
        self.assertEqual(resp['body'], payload, 'body')

    def test_proxy_parallel(self):
        payload = 'X' * 4096 * 257
        buff_size = 4096 * 258

        socks = []
        for i in range(10):
            _, sock = self.post_http10(
                body=payload + str(i),
                start=True,
                no_recv=True,
                read_buffer_size=buff_size,
            )
            socks.append(sock)

        for i in range(10):
            resp = self.recvall(socks[i], buff_size=buff_size).decode()
            socks[i].close()

            resp = self._resp_to_dict(resp)

            self.assertEqual(resp['status'], 200, 'status')
            self.assertEqual(resp['body'], payload + str(i), 'body')

    def test_proxy_header(self):
        self.assertIn(
            'success',
            self.conf(
                {"pass": "applications/custom_header"}, 'listeners/*:7081'
            ),
            'custom_header configure',
        )

        header_value = 'blah'
        self.assertEqual(
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header'],
            header_value,
            'custom header',
        )

        header_value = '(),/:;<=>?@[\]{}\t !#$%&\'*+-.^_`|~'
        self.assertEqual(
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header'],
            header_value,
            'custom header 2',
        )

        header_value = 'X' * 4096
        self.assertEqual(
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header'],
            header_value,
            'custom header 3',
        )

        header_value = 'X' * 8191
        self.assertEqual(
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header'],
            header_value,
            'custom header 4',
        )

        header_value = 'X' * 8192
        self.assertEqual(
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['status'],
            431,
            'custom header 5',
        )

    def test_proxy_fragmented(self):
        _, sock = self.http(
            b"""GET / HTT""", raw=True, start=True, no_recv=True
        )

        time.sleep(1)

        sock.sendall("P/1.0\r\nHost: localhos".encode())

        time.sleep(1)

        sock.sendall("t\r\n\r\n".encode())

        self.assertRegex(
            self.recvall(sock).decode(), '200 OK', 'fragmented send'
        )
        sock.close()

    def test_proxy_fragmented_close(self):
        _, sock = self.http(
            b"""GET / HTT""", raw=True, start=True, no_recv=True
        )

        time.sleep(1)

        sock.sendall("P/1.0\r\nHo".encode())

        sock.close()

    def test_proxy_fragmented_body(self):
        _, sock = self.http(
            b"""GET / HTT""", raw=True, start=True, no_recv=True
        )

        time.sleep(1)

        sock.sendall("P/1.0\r\nHost: localhost\r\n".encode())
        sock.sendall("Content-Length: 30000\r\n".encode())

        time.sleep(1)

        sock.sendall("\r\n".encode())
        sock.sendall(("X" * 10000).encode())

        time.sleep(1)

        sock.sendall(("X" * 10000).encode())

        time.sleep(1)

        sock.sendall(("X" * 10000).encode())

        resp = self._resp_to_dict(self.recvall(sock).decode())
        sock.close()

        self.assertEqual(resp['status'], 200, 'status')
        self.assertEqual(resp['body'], "X" * 30000, 'body')

    def test_proxy_fragmented_body_close(self):
        _, sock = self.http(
            b"""GET / HTT""", raw=True, start=True, no_recv=True
        )

        time.sleep(1)

        sock.sendall("P/1.0\r\nHost: localhost\r\n".encode())
        sock.sendall("Content-Length: 30000\r\n".encode())

        time.sleep(1)

        sock.sendall("\r\n".encode())
        sock.sendall(("X" * 10000).encode())

        sock.close()

    def test_proxy_nowhere(self):
        self.assertIn(
            'success',
            self.conf(
                [{"action": {"proxy": "http://127.0.0.1:7082"}}], 'routes'
            ),
            'proxy path changed',
        )

        self.assertEqual(self.get_http10()['status'], 502, 'status')

    def test_proxy_ipv6(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "routes"},
                    "[::1]:7081": {'application': 'mirror'},
                },
                'listeners',
            ),
            'add ipv6 listener configure',
        )

        self.assertIn(
            'success',
            self.conf([{"action": {"proxy": "http://[::1]:7081"}}], 'routes'),
            'proxy ipv6 configure',
        )

        self.assertEqual(self.get_http10()['status'], 200, 'status')

    def test_proxy_unix(self):
        addr = self.testdir + '/sock'

        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "routes"},
                    "unix:" + addr: {'application': 'mirror'},
                },
                'listeners',
            ),
            'add unix listener configure',
        )

        self.assertIn(
            'success',
            self.conf(
                [{"action": {"proxy": 'http://unix:' + addr}}], 'routes'
            ),
            'proxy unix configure',
        )

        self.assertEqual(self.get_http10()['status'], 200, 'status')

    def test_proxy_delayed(self):
        self.assertIn(
            'success',
            self.conf(
                {"pass": "applications/delayed"}, 'listeners/*:7081'
            ),
            'delayed configure',
        )

        body = '0123456789' * 1000
        resp = self.post_http10(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Content-Length': str(len(body)),
                'X-Parts': '2',
                'X-Delay': '1',
            },
            body=body,
        )

        self.assertEqual(resp['status'], 200, 'status')
        self.assertEqual(resp['body'], body, 'body')

        resp = self.post_http10(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Content-Length': str(len(body)),
                'X-Parts': '2',
                'X-Delay': '1',
            },
            body=body,
        )

        self.assertEqual(resp['status'], 200, 'status')
        self.assertEqual(resp['body'], body, 'body')

    def test_proxy_delayed_close(self):
        self.assertIn(
            'success',
            self.conf(
                {"pass": "applications/delayed"}, 'listeners/*:7081'
            ),
            'delayed configure',
        )

        _, sock = self.post_http10(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Content-Length': '10000',
                'X-Parts': '3',
                'X-Delay': '1',
            },
            body='0123456789' * 1000,
            start=True,
            no_recv=True,
        )

        self.assertRegex(
            sock.recv(100).decode(), '200 OK', 'first'
        )
        sock.close()

        _, sock = self.post_http10(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Content-Length': '10000',
                'X-Parts': '3',
                'X-Delay': '1',
            },
            body='0123456789' * 1000,
            start=True,
            no_recv=True,
        )

        self.assertRegex(
            sock.recv(100).decode(), '200 OK', 'second'
        )
        sock.close()

    @unittest.skip('not yet')
    def test_proxy_content_length(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "action": {
                            "proxy": "http://127.0.0.1:"
                            + str(self.SERVER_PORT)
                        }
                    }
                ],
                'routes',
            ),
            'proxy backend configure',
        )

        resp = self.get_http10()
        self.assertEqual(len(resp['body']), 0, 'body lt Content-Length 0')

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '5'})
        self.assertEqual(len(resp['body']), 5, 'body lt Content-Length 5')

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '9'})
        self.assertEqual(len(resp['body']), 9, 'body lt Content-Length 9')

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '11'})
        self.assertEqual(len(resp['body']), 10, 'body gt Content-Length 11')

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '15'})
        self.assertEqual(len(resp['body']), 10, 'body gt Content-Length 15')

    def test_proxy_invalid(self):
        self.assertIn(
            'error',
            self.conf([{"action": {"proxy": 'blah'}}], 'routes'),
            'proxy invalid',
        )
        self.assertIn(
            'error',
            self.conf([{"action": {"proxy": '/blah'}}], 'routes'),
            'proxy invalid 2',
        )
        self.assertIn(
            'error',
            self.conf([{"action": {"proxy": 'unix:/blah'}}], 'routes'),
            'proxy unix invalid 2',
        )
        self.assertIn(
            'error',
            self.conf([{"action": {"proxy": 'http://blah'}}], 'routes'),
            'proxy unix invalid 3',
        )
        self.assertIn(
            'error',
            self.conf([{"action": {"proxy": 'http://127.0.0.1'}}], 'routes'),
            'proxy ipv4 invalid',
        )
        self.assertIn(
            'error',
            self.conf([{"action": {"proxy": 'http://127.0.0.1:'}}], 'routes'),
            'proxy ipv4 invalid 2',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://127.0.0.1:blah'}}], 'routes'
            ),
            'proxy ipv4 invalid 3',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://127.0.0.1:-1'}}], 'routes'
            ),
            'proxy ipv4 invalid 4',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://127.0.0.1:7080b'}}], 'routes'
            ),
            'proxy ipv4 invalid 5',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://[]'}}], 'routes'
            ),
            'proxy ipv6 invalid',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://[]:7080'}}], 'routes'
            ),
            'proxy ipv6 invalid 2',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://[:]:7080'}}], 'routes'
            ),
            'proxy ipv6 invalid 3',
        )
        self.assertIn(
            'error',
            self.conf(
                [{"action": {"proxy": 'http://[::7080'}}], 'routes'
            ),
            'proxy ipv6 invalid 4',
        )

    def test_proxy_loop(self):
        self.skip_alerts.extend(
            [
                r'socket.*failed',
                r'accept.*failed',
                r'new connections are not accepted',
            ]
        )
        self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes"},
                    "*:7081": {"pass": "applications/mirror"},
                    "*:7082": {"pass": "routes"},
                },
                "routes": [{"action": {"proxy": "http://127.0.0.1:7082"}}],
                "applications": {
                    "mirror": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": self.current_dir + "/python/mirror",
                        "working_directory": self.current_dir
                        + "/python/mirror",
                        "module": "wsgi",
                    },
                },
            }
        )

        self.get_http10(no_recv=True)
        self.get_http10(read_timeout=1)

if __name__ == '__main__':
    TestProxy.main()
