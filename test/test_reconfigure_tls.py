import socket
import ssl
import time

import pytest

from unit.applications.tls import ApplicationTLS
from unit.option import option

prerequisites = {'modules': {'openssl': 'any'}}

client = ApplicationTLS()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    if 'HAS_TLSv1_2' not in dir(ssl) or not ssl.HAS_TLSv1_2:
        pytest.skip('OpenSSL too old')

    client.certificate()

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {
                    "pass": "routes",
                    "tls": {"certificate": "default"},
                }
            },
            "routes": [{"action": {"return": 200}}],
            "applications": {},
        }
    ), 'load application configuration'


def create_socket():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ctx.wrap_socket(
        s, server_hostname='localhost', do_handshake_on_connect=False
    )
    ssl_sock.connect(('127.0.0.1', 8080))

    return ssl_sock


def clear_conf():
    assert 'success' in client.conf({"listeners": {}, "applications": {}})


@pytest.mark.skip('not yet')
def test_reconfigure_tls_switch():
    assert 'success' in client.conf_delete('listeners/*:8080/tls')

    (_, sock) = client.get(
        headers={'Host': 'localhost', 'Connection': 'keep-alive'},
        start=True,
        read_timeout=1,
    )

    assert 'success' in client.conf(
        {"pass": "routes", "tls": {"certificate": "default"}},
        'listeners/*:8080',
    )

    assert client.get(sock=sock)['status'] == 200, 'reconfigure'
    assert client.get_ssl()['status'] == 200, 'reconfigure tls'


def test_reconfigure_tls():
    if option.configure_flag['asan']:
        pytest.skip('not yet, router crash')

    ssl_sock = create_socket()

    ssl_sock.sendall("""GET / HTTP/1.1\r\n""".encode())

    clear_conf()

    ssl_sock.sendall(
        """Host: localhost\r\nConnection: close\r\n\r\n""".encode()
    )

    assert (
        client.recvall(ssl_sock).decode().startswith('HTTP/1.1 200 OK')
    ), 'finish request'


def test_reconfigure_tls_2():
    ssl_sock = create_socket()

    # Waiting for connection completion.
    # Delay should be more than TCP_DEFER_ACCEPT.
    time.sleep(1.5)

    clear_conf()

    success = False

    try:
        ssl_sock.do_handshake()
    except ssl.SSLError:
        ssl_sock.close()
        success = True

    if not success:
        pytest.fail('Connection is not closed.')


def test_reconfigure_tls_3():
    if option.configure_flag['asan']:
        pytest.skip('not yet, router crash')

    ssl_sock = create_socket()
    ssl_sock.do_handshake()

    clear_conf()

    assert client.get(sock=ssl_sock)['status'] == 408, 'request timeout'
