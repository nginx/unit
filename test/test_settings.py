import pytest
import socket
import time

from unit.applications.lang.python import TestApplicationPython
import re


class TestSettings(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_settings_header_read_timeout(self):
        self.load('empty')

        self.conf({'http': {'header_read_timeout': 2}}, 'settings')

        (resp, sock) = self.http(
            b"""GET / HTTP/1.1
""",
            start=True,
            read_timeout=1,
            raw=True,
        )

        time.sleep(3)

        resp = self.http(
            b"""Host: localhost
Connection: close

""",
            sock=sock,
            raw=True,
        )

        assert resp['status'] == 408, 'status header read timeout'

    def test_settings_header_read_timeout_update(self):
        self.load('empty')

        self.conf({'http': {'header_read_timeout': 4}}, 'settings')

        (resp, sock) = self.http(
            b"""GET / HTTP/1.1
""",
            start=True,
            raw=True,
            no_recv=True,
        )

        time.sleep(2)

        (resp, sock) = self.http(
            b"""Host: localhost
""",
            start=True,
            sock=sock,
            raw=True,
            no_recv=True,
        )

        time.sleep(2)

        (resp, sock) = self.http(
            b"""X-Blah: blah
""",
            start=True,
            sock=sock,
            read_timeout=1,
            raw=True,
        )

        if len(resp) != 0:
            sock.close()

        else:
            time.sleep(2)

            resp = self.http(
                b"""Connection: close

""",
                sock=sock,
                raw=True,
            )

        assert resp['status'] == 408, 'status header read timeout update'

    def test_settings_body_read_timeout(self):
        self.load('empty')

        self.conf({'http': {'body_read_timeout': 2}}, 'settings')

        (resp, sock) = self.http(
            b"""POST / HTTP/1.1
Host: localhost
Content-Length: 10
Connection: close

""",
            start=True,
            raw_resp=True,
            read_timeout=1,
            raw=True,
        )

        time.sleep(3)

        resp = self.http(b"""0123456789""", sock=sock, raw=True)

        assert resp['status'] == 408, 'status body read timeout'

    def test_settings_body_read_timeout_update(self):
        self.load('empty')

        self.conf({'http': {'body_read_timeout': 4}}, 'settings')

        (resp, sock) = self.http(
            b"""POST / HTTP/1.1
Host: localhost
Content-Length: 10
Connection: close

""",
            start=True,
            read_timeout=1,
            raw=True,
        )

        time.sleep(2)

        (resp, sock) = self.http(
            b"""012""", start=True, sock=sock, read_timeout=1, raw=True
        )

        time.sleep(2)

        (resp, sock) = self.http(
            b"""345""", start=True, sock=sock, read_timeout=1, raw=True
        )

        time.sleep(2)

        resp = self.http(b"""6789""", sock=sock, raw=True)

        assert resp['status'] == 200, 'status body read timeout update'

    def test_settings_send_timeout(self):
        self.load('mirror')

        data_len = 1048576

        self.conf({'http': {'send_timeout': 1}}, 'settings')

        addr = self.temp_dir + '/sock'

        self.conf({"unix:" + addr: {'application': 'mirror'}}, 'listeners')

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(addr)

        req = """POST / HTTP/1.1
Host: localhost
Content-Type: text/html
Content-Length: %d
Connection: close

""" % data_len + (
            'X' * data_len
        )

        sock.sendall(req.encode())

        data = sock.recv(16).decode()

        time.sleep(3)

        data += self.recvall(sock).decode()

        sock.close()

        assert re.search(r'200 OK', data), 'status send timeout'
        assert len(data) < data_len, 'data send timeout'

    def test_settings_idle_timeout(self):
        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        self.conf({'http': {'idle_timeout': 2}}, 'settings')

        (resp, sock) = self.get(
            headers={'Host': 'localhost', 'Connection': 'keep-alive'},
            start=True,
            read_timeout=1,
        )

        time.sleep(3)

        resp = self.get(
            headers={'Host': 'localhost', 'Connection': 'close'}, sock=sock
        )

        assert resp['status'] == 408, 'status idle timeout'

    def test_settings_idle_timeout_2(self):
        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        self.conf({'http': {'idle_timeout': 1}}, 'settings')

        _, sock = self.http(b'', start=True, raw=True, no_recv=True)

        time.sleep(2)

        assert (
            self.get(
                headers={'Host': 'localhost', 'Connection': 'close'}, sock=sock
            )['status']
            == 408
        ), 'status idle timeout'

    def test_settings_max_body_size(self):
        self.load('empty')

        self.conf({'http': {'max_body_size': 5}}, 'settings')

        assert self.post(body='01234')['status'] == 200, 'status size'
        assert self.post(body='012345')['status'] == 413, 'status size max'

    def test_settings_max_body_size_large(self):
        self.load('mirror')

        self.conf({'http': {'max_body_size': 32 * 1024 * 1024}}, 'settings')

        body = '0123456789abcdef' * 4 * 64 * 1024
        resp = self.post(body=body, read_buffer_size=1024 * 1024)
        assert resp['status'] == 200, 'status size 4'
        assert resp['body'] == body, 'status body 4'

        body = '0123456789abcdef' * 8 * 64 * 1024
        resp = self.post(body=body, read_buffer_size=1024 * 1024)
        assert resp['status'] == 200, 'status size 8'
        assert resp['body'] == body, 'status body 8'

        body = '0123456789abcdef' * 16 * 64 * 1024
        resp = self.post(body=body, read_buffer_size=1024 * 1024)
        assert resp['status'] == 200, 'status size 16'
        assert resp['body'] == body, 'status body 16'

        body = '0123456789abcdef' * 32 * 64 * 1024
        resp = self.post(body=body, read_buffer_size=1024 * 1024)
        assert resp['status'] == 200, 'status size 32'
        assert resp['body'] == body, 'status body 32'

    @pytest.mark.skip('not yet')
    def test_settings_negative_value(self):
        assert 'error' in self.conf(
            {'http': {'max_body_size': -1}}, 'settings'
        ), 'settings negative value'
