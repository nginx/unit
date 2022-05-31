import socket
import ssl
import time

import pytest
from unit.applications.tls import TestApplicationTLS


class TestReconfigureTLS(TestApplicationTLS):
    prerequisites = {'modules': {'openssl': 'any'}}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self):
        if 'HAS_TLSv1_2' not in dir(ssl) or not ssl.HAS_TLSv1_2:
            pytest.skip('OpenSSL too old')

        self.certificate()

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {
                        "pass": "routes",
                        "tls": {"certificate": "default"},
                    }
                },
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        ), 'load application configuration'

    def create_socket(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ctx.wrap_socket(
            s, server_hostname='localhost', do_handshake_on_connect=False
        )
        ssl_sock.connect(('127.0.0.1', 7080))

        return ssl_sock

    def clear_conf(self):
        assert 'success' in self.conf({"listeners": {}, "applications": {}})

    @pytest.mark.skip('not yet')
    def test_reconfigure_tls_switch(self):
        assert 'success' in self.conf_delete('listeners/*:7080/tls')

        (_, sock) = self.get(
            headers={'Host': 'localhost', 'Connection': 'keep-alive'},
            start=True,
            read_timeout=1,
        )

        assert 'success' in self.conf(
            {"pass": "routes", "tls": {"certificate": "default"}},
            'listeners/*:7080',
        )

        assert self.get(sock=sock)['status'] == 200, 'reconfigure'
        assert self.get_ssl()['status'] == 200, 'reconfigure tls'

    def test_reconfigure_tls(self):
        ssl_sock = self.create_socket()

        ssl_sock.sendall("""GET / HTTP/1.1\r\n""".encode())

        self.clear_conf()

        ssl_sock.sendall(
            """Host: localhost\r\nConnection: close\r\n\r\n""".encode()
        )

        assert (
            self.recvall(ssl_sock).decode().startswith('HTTP/1.1 200 OK')
        ), 'finish request'

    def test_reconfigure_tls_2(self):
        ssl_sock = self.create_socket()

        # Waiting for connection completion.
        # Delay should be more than TCP_DEFER_ACCEPT.
        time.sleep(1.5)

        self.clear_conf()

        try:
            ssl_sock.do_handshake()
        except ssl.SSLError:
            ssl_sock.close()
            success = True

        if not success:
            pytest.fail('Connection is not closed.')

    def test_reconfigure_tls_3(self):
        ssl_sock = self.create_socket()
        ssl_sock.do_handshake()

        self.clear_conf()

        assert self.get(sock=ssl_sock)['status'] == 408, 'request timeout'
