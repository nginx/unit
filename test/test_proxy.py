import re
import socket
import time

import pytest
from conftest import run_process
from unit.applications.lang.python import TestApplicationPython
from unit.option import option
from unit.utils import waitforsocket


class TestProxy(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

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

            m = re.search(r'X-Len: (\d+)', data)
            if m:
                to_send += b'X' * int(m.group(1))

            connection.sendall(to_send)

            connection.close()

    def get_http10(self, *args, **kwargs):
        return self.get(*args, http_10=True, **kwargs)

    def post_http10(self, *args, **kwargs):
        return self.post(*args, http_10=True, **kwargs)

    def setup_method(self):
        run_process(self.run_server, self.SERVER_PORT)
        waitforsocket(self.SERVER_PORT)

        assert 'success' in self.conf(
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
                        "path": option.test_dir + "/python/mirror",
                        "working_directory": option.test_dir
                        + "/python/mirror",
                        "module": "wsgi",
                    },
                    "custom_header": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/custom_header",
                        "working_directory": option.test_dir
                        + "/python/custom_header",
                        "module": "wsgi",
                    },
                    "delayed": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/delayed",
                        "working_directory": option.test_dir
                        + "/python/delayed",
                        "module": "wsgi",
                    },
                },
            }
        ), 'proxy initial configuration'

    def test_proxy_http10(self):
        for _ in range(10):
            assert self.get_http10()['status'] == 200, 'status'

    def test_proxy_chain(self):
        assert 'success' in self.conf(
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
                    "first": [{"action": {"proxy": "http://127.0.0.1:7081"}}],
                    "second": [{"action": {"proxy": "http://127.0.0.1:7082"}}],
                    "third": [{"action": {"proxy": "http://127.0.0.1:7083"}}],
                    "fourth": [{"action": {"proxy": "http://127.0.0.1:7084"}}],
                    "fifth": [{"action": {"proxy": "http://127.0.0.1:7085"}}],
                },
                "applications": {
                    "mirror": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/mirror",
                        "working_directory": option.test_dir
                        + "/python/mirror",
                        "module": "wsgi",
                    }
                },
            }
        ), 'proxy chain configuration'

        assert self.get_http10()['status'] == 200, 'status'

    def test_proxy_body(self):
        payload = '0123456789'
        for _ in range(10):
            resp = self.post_http10(body=payload)

            assert resp['status'] == 200, 'status'
            assert resp['body'] == payload, 'body'

        payload = 'X' * 4096
        for _ in range(10):
            resp = self.post_http10(body=payload)

            assert resp['status'] == 200, 'status'
            assert resp['body'] == payload, 'body'

        payload = 'X' * 4097
        for _ in range(10):
            resp = self.post_http10(body=payload)

            assert resp['status'] == 200, 'status'
            assert resp['body'] == payload, 'body'

        payload = 'X' * 4096 * 256
        for _ in range(10):
            resp = self.post_http10(body=payload, read_buffer_size=4096 * 128)

            assert resp['status'] == 200, 'status'
            assert resp['body'] == payload, 'body'

        payload = 'X' * 4096 * 257
        for _ in range(10):
            resp = self.post_http10(body=payload, read_buffer_size=4096 * 128)

            assert resp['status'] == 200, 'status'
            assert resp['body'] == payload, 'body'

        assert 'success' in self.conf(
            {'http': {'max_body_size': 32 * 1024 * 1024}}, 'settings'
        )

        payload = '0123456789abcdef' * 32 * 64 * 1024
        resp = self.post_http10(body=payload, read_buffer_size=1024 * 1024)
        assert resp['status'] == 200, 'status'
        assert resp['body'] == payload, 'body'

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

            assert resp['status'] == 200, 'status'
            assert resp['body'] == payload + str(i), 'body'

    def test_proxy_header(self):
        assert 'success' in self.conf(
            {"pass": "applications/custom_header"}, 'listeners/*:7081'
        ), 'custom_header configure'

        header_value = 'blah'
        assert (
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header']
            == header_value
        ), 'custom header'

        header_value = r'(),/:;<=>?@[\]{}\t !#$%&\'*+-.^_`|~'
        assert (
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header']
            == header_value
        ), 'custom header 2'

        header_value = 'X' * 4096
        assert (
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header']
            == header_value
        ), 'custom header 3'

        header_value = 'X' * 8191
        assert (
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['headers']['Custom-Header']
            == header_value
        ), 'custom header 4'

        header_value = 'X' * 8192
        assert (
            self.get_http10(
                headers={'Host': 'localhost', 'Custom-Header': header_value}
            )['status']
            == 431
        ), 'custom header 5'

    def test_proxy_fragmented(self):
        _, sock = self.http(
            b"""GET / HTT""", raw=True, start=True, no_recv=True
        )

        time.sleep(1)

        sock.sendall("P/1.0\r\nHost: localhos".encode())

        time.sleep(1)

        sock.sendall("t\r\n\r\n".encode())

        assert re.search(
            '200 OK', self.recvall(sock).decode()
        ), 'fragmented send'
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

        assert resp['status'] == 200, 'status'
        assert resp['body'] == "X" * 30000, 'body'

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
        assert 'success' in self.conf(
            [{"action": {"proxy": "http://127.0.0.1:7082"}}], 'routes'
        ), 'proxy path changed'

        assert self.get_http10()['status'] == 502, 'status'

    def test_proxy_ipv6(self):
        assert 'success' in self.conf(
            {
                "*:7080": {"pass": "routes"},
                "[::1]:7081": {'application': 'mirror'},
            },
            'listeners',
        ), 'add ipv6 listener configure'

        assert 'success' in self.conf(
            [{"action": {"proxy": "http://[::1]:7081"}}], 'routes'
        ), 'proxy ipv6 configure'

        assert self.get_http10()['status'] == 200, 'status'

    def test_proxy_unix(self, temp_dir):
        addr = temp_dir + '/sock'

        assert 'success' in self.conf(
            {
                "*:7080": {"pass": "routes"},
                "unix:" + addr: {'application': 'mirror'},
            },
            'listeners',
        ), 'add unix listener configure'

        assert 'success' in self.conf(
            [{"action": {"proxy": 'http://unix:' + addr}}], 'routes'
        ), 'proxy unix configure'

        assert self.get_http10()['status'] == 200, 'status'

    def test_proxy_delayed(self):
        assert 'success' in self.conf(
            {"pass": "applications/delayed"}, 'listeners/*:7081'
        ), 'delayed configure'

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

        assert resp['status'] == 200, 'status'
        assert resp['body'] == body, 'body'

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

        assert resp['status'] == 200, 'status'
        assert resp['body'] == body, 'body'

    def test_proxy_delayed_close(self):
        assert 'success' in self.conf(
            {"pass": "applications/delayed"}, 'listeners/*:7081'
        ), 'delayed configure'

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

        assert re.search('200 OK', sock.recv(100).decode()), 'first'
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

        assert re.search('200 OK', sock.recv(100).decode()), 'second'
        sock.close()

    @pytest.mark.skip('not yet')
    def test_proxy_content_length(self):
        assert 'success' in self.conf(
            [
                {
                    "action": {
                        "proxy": "http://127.0.0.1:" + str(self.SERVER_PORT)
                    }
                }
            ],
            'routes',
        ), 'proxy backend configure'

        resp = self.get_http10()
        assert len(resp['body']) == 0, 'body lt Content-Length 0'

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '5'})
        assert len(resp['body']) == 5, 'body lt Content-Length 5'

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '9'})
        assert len(resp['body']) == 9, 'body lt Content-Length 9'

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '11'})
        assert len(resp['body']) == 10, 'body gt Content-Length 11'

        resp = self.get_http10(headers={'Host': 'localhost', 'X-Len': '15'})
        assert len(resp['body']) == 10, 'body gt Content-Length 15'

    def test_proxy_invalid(self):
        def check_proxy(proxy):
            assert 'error' in \
                self.conf([{"action": {"proxy": proxy}}], 'routes'), \
                'proxy invalid'

        check_proxy('blah')
        check_proxy('/blah')
        check_proxy('unix:/blah')
        check_proxy('http://blah')
        check_proxy('http://127.0.0.1')
        check_proxy('http://127.0.0.1:')
        check_proxy('http://127.0.0.1:blah')
        check_proxy('http://127.0.0.1:-1')
        check_proxy('http://127.0.0.1:7080b')
        check_proxy('http://[]')
        check_proxy('http://[]:7080')
        check_proxy('http://[:]:7080')
        check_proxy('http://[::7080')

    def test_proxy_loop(self, skip_alert):
        skip_alert(
            r'socket.*failed',
            r'accept.*failed',
            r'new connections are not accepted',
        )
        assert 'success' in self.conf(
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
                        "path": option.test_dir + "/python/mirror",
                        "working_directory": option.test_dir + "/python/mirror",
                        "module": "wsgi",
                    },
                },
            }
        )

        self.get_http10(no_recv=True)
        self.get_http10(read_timeout=1)
