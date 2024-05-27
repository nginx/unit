import re
import socket
import time

import pytest

from conftest import run_process
from unit.applications.lang.python import ApplicationPython
from unit.option import option
from unit.utils import waitforsocket

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()
SERVER_PORT = 7999


@pytest.fixture(autouse=True)
def setup_method_fixture():
    run_process(run_server, SERVER_PORT)
    waitforsocket(SERVER_PORT)

    python_dir = f'{option.test_dir}/python'
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "applications/mirror"},
            },
            "routes": [{"action": {"proxy": "http://127.0.0.1:8081"}}],
            "applications": {
                "mirror": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{python_dir}/mirror',
                    "working_directory": f'{python_dir}/mirror',
                    "module": "wsgi",
                },
                "custom_header": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{python_dir}/custom_header',
                    "working_directory": f'{python_dir}/custom_header',
                    "module": "wsgi",
                },
                "delayed": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{python_dir}/delayed',
                    "working_directory": f'{python_dir}/delayed',
                    "module": "wsgi",
                },
            },
        }
    ), 'proxy initial configuration'


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
        connection, _ = sock.accept()

        data = recvall(connection).decode()

        to_send = req

        m = re.search(r'X-Len: (\d+)', data)
        if m:
            to_send += b'X' * int(m.group(1))

        connection.sendall(to_send)

        connection.close()


def get_http10(*args, **kwargs):
    return client.get(*args, http_10=True, **kwargs)


def post_http10(*args, **kwargs):
    return client.post(*args, http_10=True, **kwargs)


def test_proxy_http10():
    for _ in range(10):
        assert get_http10()['status'] == 200, 'status'


def test_proxy_chain():
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes/first"},
                "*:8081": {"pass": "routes/second"},
                "*:8082": {"pass": "routes/third"},
                "*:8083": {"pass": "routes/fourth"},
                "*:8084": {"pass": "routes/fifth"},
                "*:8085": {"pass": "applications/mirror"},
            },
            "routes": {
                "first": [{"action": {"proxy": "http://127.0.0.1:8081"}}],
                "second": [{"action": {"proxy": "http://127.0.0.1:8082"}}],
                "third": [{"action": {"proxy": "http://127.0.0.1:8083"}}],
                "fourth": [{"action": {"proxy": "http://127.0.0.1:8084"}}],
                "fifth": [{"action": {"proxy": "http://127.0.0.1:8085"}}],
            },
            "applications": {
                "mirror": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{option.test_dir}/python/mirror',
                    "working_directory": f'{option.test_dir}/python/mirror',
                    "module": "wsgi",
                }
            },
        }
    ), 'proxy chain configuration'

    assert get_http10()['status'] == 200, 'status'


def test_proxy_body():
    payload = '0123456789'
    for _ in range(10):
        resp = post_http10(body=payload)

        assert resp['status'] == 200, 'status'
        assert resp['body'] == payload, 'body'

    payload = 'X' * 4096
    for _ in range(10):
        resp = post_http10(body=payload)

        assert resp['status'] == 200, 'status'
        assert resp['body'] == payload, 'body'

    payload = 'X' * 4097
    for _ in range(10):
        resp = post_http10(body=payload)

        assert resp['status'] == 200, 'status'
        assert resp['body'] == payload, 'body'

    payload = 'X' * 4096 * 256
    for _ in range(10):
        resp = post_http10(body=payload, read_buffer_size=4096 * 128)

        assert resp['status'] == 200, 'status'
        assert resp['body'] == payload, 'body'

    payload = 'X' * 4096 * 257
    for _ in range(10):
        resp = post_http10(body=payload, read_buffer_size=4096 * 128)

        assert resp['status'] == 200, 'status'
        assert resp['body'] == payload, 'body'

    assert 'success' in client.conf(
        {'http': {'max_body_size': 32 * 1024 * 1024}}, 'settings'
    )

    payload = '0123456789abcdef' * 32 * 64 * 1024
    resp = post_http10(body=payload, read_buffer_size=1024 * 1024)
    assert resp['status'] == 200, 'status'
    assert resp['body'] == payload, 'body'


def test_proxy_parallel():
    payload = 'X' * 4096 * 257
    buff_size = 4096 * 258

    socks = []
    for i in range(10):
        sock = post_http10(
            body=f'{payload}{i}',
            no_recv=True,
            read_buffer_size=buff_size,
        )
        socks.append(sock)

    for i in range(10):
        resp = client.recvall(socks[i], buff_size=buff_size).decode()
        socks[i].close()

        resp = client._resp_to_dict(resp)

        assert resp['status'] == 200, 'status'
        assert resp['body'] == f'{payload}{i}', 'body'


def test_proxy_header():
    assert 'success' in client.conf(
        {"pass": "applications/custom_header"}, 'listeners/*:8081'
    ), 'custom_header configure'

    header_value = 'blah'
    assert (
        get_http10(
            headers={'Host': 'localhost', 'Custom-Header': header_value}
        )['headers']['Custom-Header']
        == header_value
    ), 'custom header'

    header_value = r"(),/:;<=>?@[\]{}\t !#$%&'*+-.^_`|~"
    assert (
        get_http10(
            headers={'Host': 'localhost', 'Custom-Header': header_value}
        )['headers']['Custom-Header']
        == header_value
    ), 'custom header 2'

    header_value = 'X' * 4096
    assert (
        get_http10(
            headers={'Host': 'localhost', 'Custom-Header': header_value}
        )['headers']['Custom-Header']
        == header_value
    ), 'custom header 3'

    header_value = 'X' * 8191
    assert (
        get_http10(
            headers={'Host': 'localhost', 'Custom-Header': header_value}
        )['headers']['Custom-Header']
        == header_value
    ), 'custom header 4'

    header_value = 'X' * 8192
    assert (
        get_http10(
            headers={'Host': 'localhost', 'Custom-Header': header_value}
        )['status']
        == 431
    ), 'custom header 5'


def test_proxy_fragmented():
    sock = client.http(b"""GET / HTT""", raw=True, no_recv=True)

    time.sleep(1)

    sock.sendall("P/1.0\r\nHost: localhos".encode())

    time.sleep(1)

    sock.sendall("t\r\n\r\n".encode())

    assert re.search('200 OK', client.recvall(sock).decode()), 'fragmented send'
    sock.close()


def test_proxy_fragmented_close():
    sock = client.http(b"""GET / HTT""", raw=True, no_recv=True)

    time.sleep(1)

    sock.sendall("P/1.0\r\nHo".encode())

    sock.close()


def test_proxy_fragmented_body():
    sock = client.http(b"""GET / HTT""", raw=True, no_recv=True)

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

    resp = client._resp_to_dict(client.recvall(sock).decode())
    sock.close()

    assert resp['status'] == 200, 'status'
    assert resp['body'] == "X" * 30000, 'body'


def test_proxy_fragmented_body_close():
    sock = client.http(b"""GET / HTT""", raw=True, no_recv=True)

    time.sleep(1)

    sock.sendall("P/1.0\r\nHost: localhost\r\n".encode())
    sock.sendall("Content-Length: 30000\r\n".encode())

    time.sleep(1)

    sock.sendall("\r\n".encode())
    sock.sendall(("X" * 10000).encode())

    sock.close()


def test_proxy_nowhere():
    assert 'success' in client.conf(
        [{"action": {"proxy": "http://127.0.0.1:8082"}}], 'routes'
    ), 'proxy path changed'

    assert get_http10()['status'] == 502, 'status'


def test_proxy_ipv6():
    assert 'success' in client.conf(
        {
            "*:8080": {"pass": "routes"},
            "[::1]:8081": {'application': 'mirror'},
        },
        'listeners',
    ), 'add ipv6 listener configure'

    assert 'success' in client.conf(
        [{"action": {"proxy": "http://[::1]:8081"}}], 'routes'
    ), 'proxy ipv6 configure'

    assert get_http10()['status'] == 200, 'status'


def test_proxy_unix(temp_dir):
    addr = f'{temp_dir}/sock'

    assert 'success' in client.conf(
        {
            "*:8080": {"pass": "routes"},
            f'unix:{addr}': {'application': 'mirror'},
        },
        'listeners',
    ), 'add unix listener configure'

    assert 'success' in client.conf(
        [{"action": {"proxy": f'http://unix:{addr}'}}], 'routes'
    ), 'proxy unix configure'

    assert get_http10()['status'] == 200, 'status'


def test_proxy_delayed():
    assert 'success' in client.conf(
        {"pass": "applications/delayed"}, 'listeners/*:8081'
    ), 'delayed configure'

    body = '0123456789' * 1000
    resp = post_http10(
        headers={
            'Host': 'localhost',
            'Content-Length': str(len(body)),
            'X-Parts': '2',
            'X-Delay': '1',
        },
        body=body,
    )

    assert resp['status'] == 200, 'status'
    assert resp['body'] == body, 'body'

    resp = post_http10(
        headers={
            'Host': 'localhost',
            'Content-Length': str(len(body)),
            'X-Parts': '2',
            'X-Delay': '1',
        },
        body=body,
    )

    assert resp['status'] == 200, 'status'
    assert resp['body'] == body, 'body'


def test_proxy_delayed_close():
    assert 'success' in client.conf(
        {"pass": "applications/delayed"}, 'listeners/*:8081'
    ), 'delayed configure'

    sock = post_http10(
        headers={
            'Host': 'localhost',
            'Content-Length': '10000',
            'X-Parts': '3',
            'X-Delay': '1',
        },
        body='0123456789' * 1000,
        no_recv=True,
    )

    assert re.search('200 OK', sock.recv(100).decode()), 'first'
    sock.close()

    sock = post_http10(
        headers={
            'Host': 'localhost',
            'Content-Length': '10000',
            'X-Parts': '3',
            'X-Delay': '1',
        },
        body='0123456789' * 1000,
        no_recv=True,
    )

    assert re.search('200 OK', sock.recv(100).decode()), 'second'
    sock.close()


@pytest.mark.skip('not yet')
def test_proxy_content_length():
    assert 'success' in client.conf(
        [{"action": {"proxy": f'http://127.0.0.1:{SERVER_PORT}'}}],
        'routes',
    ), 'proxy backend configure'

    resp = get_http10()
    assert len(resp['body']) == 0, 'body lt Content-Length 0'

    resp = get_http10(headers={'Host': 'localhost', 'X-Len': '5'})
    assert len(resp['body']) == 5, 'body lt Content-Length 5'

    resp = get_http10(headers={'Host': 'localhost', 'X-Len': '9'})
    assert len(resp['body']) == 9, 'body lt Content-Length 9'

    resp = get_http10(headers={'Host': 'localhost', 'X-Len': '11'})
    assert len(resp['body']) == 10, 'body gt Content-Length 11'

    resp = get_http10(headers={'Host': 'localhost', 'X-Len': '15'})
    assert len(resp['body']) == 10, 'body gt Content-Length 15'


def test_proxy_invalid():
    def check_proxy(proxy):
        assert 'error' in client.conf(
            [{"action": {"proxy": proxy}}], 'routes'
        ), 'proxy invalid'

    check_proxy('blah')
    check_proxy('/blah')
    check_proxy('unix:/blah')
    check_proxy('http://blah')
    check_proxy('http://127.0.0.1')
    check_proxy('http://127.0.0.1:')
    check_proxy('http://127.0.0.1:blah')
    check_proxy('http://127.0.0.1:-1')
    check_proxy('http://127.0.0.1:8080b')
    check_proxy('http://[]')
    check_proxy('http://[]:8080')
    check_proxy('http://[:]:8080')
    check_proxy('http://[::8080')


@pytest.mark.skip('not yet')
def test_proxy_loop(skip_alert):
    skip_alert(
        r'socket.*failed',
        r'accept.*failed',
        r'new connections are not accepted',
    )
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "applications/mirror"},
                "*:8082": {"pass": "routes"},
            },
            "routes": [{"action": {"proxy": "http://127.0.0.1:8082"}}],
            "applications": {
                "mirror": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{option.test_dir}/python/mirror',
                    "working_directory": f'{option.test_dir}/python/mirror',
                    "module": "wsgi",
                },
            },
        }
    )

    get_http10(no_recv=True)
    get_http10(read_timeout=1)
