import time
import socket
import unittest
import unit

class TestUnitSettings(unit.TestUnitApplicationPython):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_settings_header_read_timeout(self):
        self.load('empty')

        self.conf({'http': { 'header_read_timeout': 2 }}, 'settings')

        (resp, sock) = self.http(b"""GET / HTTP/1.1
""", start=True, read_timeout=1, raw=True)

        time.sleep(3)

        resp = self.http(b"""Host: localhost
Connection: close

""", sock=sock, raw=True)

        self.assertEqual(resp['status'], 408, 'status header read timeout')

    def test_settings_header_read_timeout_update(self):
        self.load('empty')

        self.conf({'http': { 'header_read_timeout': 4 }}, 'settings')

        (resp, sock) = self.http(b"""GET / HTTP/1.1
""", start=True, read_timeout=1, raw=True, no_recv=True)

        time.sleep(2)

        (resp, sock) = self.http(b"""Host: localhost
""", start=True, sock=sock, read_timeout=1, raw=True, no_recv=True)

        time.sleep(2)

        (resp, sock) = self.http(b"""X-Blah: blah
""", start=True, sock=sock, read_timeout=1, raw=True)

        if len(resp) != 0:
            sock.close()

        else:
            time.sleep(2)

            resp = self.http(b"""Connection: close

""", sock=sock, raw=True)

        self.assertEqual(resp['status'], 408,
            'status header read timeout update')

    def test_settings_body_read_timeout(self):
        self.load('empty')

        self.conf({'http': { 'body_read_timeout': 2 }}, 'settings')

        (resp, sock) = self.http(b"""POST / HTTP/1.1
Host: localhost
Content-Length: 10
Connection: close

""", start=True, raw_resp=True, read_timeout=1, raw=True)

        time.sleep(3)

        resp = self.http(b"""0123456789""", sock=sock, raw=True)

        self.assertEqual(resp['status'], 408, 'status body read timeout')

    def test_settings_body_read_timeout_update(self):
        self.load('empty')

        self.conf({'http': { 'body_read_timeout': 4 }}, 'settings')

        (resp, sock) = self.http(b"""POST / HTTP/1.1
Host: localhost
Content-Length: 10
Connection: close

""", start=True, read_timeout=1, raw=True)

        time.sleep(2)

        (resp, sock) = self.http(b"""012""", start=True, sock=sock,
            read_timeout=1, raw=True)

        time.sleep(2)

        (resp, sock) = self.http(b"""345""", start=True, sock=sock,
            read_timeout=1, raw=True)

        time.sleep(2)

        resp = self.http(b"""6789""", sock=sock, raw=True)

        self.assertEqual(resp['status'], 200, 'status body read timeout update')

    def test_settings_send_timeout(self):
        self.load('mirror')

        data_len = 1048576

        self.conf({'http': { 'send_timeout': 1 }}, 'settings')

        addr = self.testdir + '/sock'

        self.conf({"unix:" + addr: {'application': 'mirror'}}, 'listeners')

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(addr)

        req = """POST / HTTP/1.1
Host: localhost
Content-Type: text/html
Content-Length: %d
Connection: close

""" % data_len + ('X' * data_len)

        sock.sendall(req.encode())

        data = sock.recv(16).decode()

        time.sleep(3)

        data += self.recvall(sock).decode()

        sock.close()

        self.assertRegex(data, r'200 OK', 'status send timeout')
        self.assertLess(len(data), data_len, 'data send timeout')

    def test_settings_idle_timeout(self):
        self.load('empty')

        self.conf({'http': { 'idle_timeout': 2 }}, 'settings')

        (resp, sock) = self.get(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive'
        }, start=True, read_timeout=1)

        time.sleep(3)

        resp = self.get(headers={
            'Host': 'localhost',
            'Connection': 'close'
        }, sock=sock)

        self.assertEqual(resp['status'], 408, 'status idle timeout')

    def test_settings_max_body_size(self):
        self.load('empty')

        self.conf({'http': { 'max_body_size': 5 }}, 'settings')

        self.assertEqual(self.post(body='01234')['status'], 200, 'status size')
        self.assertEqual(self.post(body='012345')['status'], 413,
            'status size max')

    @unittest.expectedFailure
    def test_settings_negative_value(self):
        self.assertIn('error', self.conf({'http': { 'max_body_size': -1 }},
            'settings'), 'settings negative value')

if __name__ == '__main__':
    TestUnitSettings.main()
