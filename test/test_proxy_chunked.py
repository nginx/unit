import re
import select
import socket
import time

import pytest

from conftest import run_process
from unit.applications.lang.python import ApplicationPython
from unit.utils import waitforsocket

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()
SERVER_PORT = 7999


@pytest.fixture(autouse=True)
def setup_method_fixture():
    run_process(run_server, SERVER_PORT)
    waitforsocket(SERVER_PORT)

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
            },
            "routes": [
                {"action": {"proxy": f'http://127.0.0.1:{SERVER_PORT}'}}
            ],
        }
    ), 'proxy initial configuration'


def run_server(server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    server_address = ('127.0.0.1', server_port)
    sock.bind(server_address)
    sock.listen(10)

    def recvall(sock):
        buff_size = 4096 * 4096
        data = b''
        while True:
            rlist = select.select([sock], [], [], 0.1)

            if not rlist[0]:
                break

            part = sock.recv(buff_size)
            data += part

            if not part:
                break

        return data

    while True:
        connection, _ = sock.accept()

        req = """HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked"""

        data = recvall(connection).decode()

        m = re.search('\x0d\x0a\x0d\x0a(.*)', data, re.M | re.S)
        if m is not None:
            body = m.group(1)

            for line in re.split('\r\n', body):
                add = ''
                m1 = re.search(r'(.*)\sX\s(\d+)', line)

                if m1 is not None:
                    add = m1.group(1) * int(m1.group(2))
                else:
                    add = line

                req = f'{req}{add}\r\n'

        for chunk in re.split(r'([@#])', req):
            if chunk in ('@', '#'):
                if chunk == '#':
                    time.sleep(0.1)
                continue

            connection.sendall(chunk.encode())

        connection.close()


def chunks(chunks_lst):
    body = '\r\n\r\n'

    for l, c in chunks_lst:
        body = f'{body}{l}\r\n{c}\r\n'

    return f'{body}0\r\n\r\n'


def get_http10(*args, **kwargs):
    return client.get(*args, http_10=True, **kwargs)


def test_proxy_chunked():
    for _ in range(10):
        assert get_http10(body='\r\n\r\n0\r\n\r\n')['status'] == 200


def test_proxy_chunked_body():
    part = '0123456789abcdef'

    assert (
        get_http10(body=chunks([('1000', f'{part} X 256')]))['body']
        == part * 256
    )
    assert (
        get_http10(body=chunks([('100000', f'{part} X 65536')]))['body']
        == part * 65536
    )
    assert (
        get_http10(
            body=chunks([('1000000', f'{part} X 1048576')]),
            read_buffer_size=4096 * 4096,
        )['body']
        == part * 1048576
    )

    assert (
        get_http10(
            body=chunks([('1000', f'{part} X 256'), ('1000', f'{part} X 256')])
        )['body']
        == part * 256 * 2
    )
    assert (
        get_http10(
            body=chunks(
                [
                    ('100000', f'{part} X 65536'),
                    ('100000', f'{part} X 65536'),
                ]
            )
        )['body']
        == part * 65536 * 2
    )
    assert (
        get_http10(
            body=chunks(
                [
                    ('1000000', f'{part} X 1048576'),
                    ('1000000', f'{part} X 1048576'),
                ]
            ),
            read_buffer_size=4096 * 4096,
        )['body']
        == part * 1048576 * 2
    )


def test_proxy_chunked_fragmented():
    part = '0123456789abcdef'

    assert (
        get_http10(
            body=chunks([('1', hex(i % 16)[2:]) for i in range(4096)]),
        )['body']
        == part * 256
    )


def test_proxy_chunked_send():
    assert get_http10(body='\r\n\r\n@0@\r\n\r\n')['status'] == 200
    assert (
        get_http10(body='\r@\n\r\n2\r@\na@b\r\n2\r\ncd@\r\n0\r@\n\r\n')['body']
        == 'abcd'
    )
    assert (
        get_http10(body='\r\n\r\n2\r#\na#b\r\n##2\r\n#cd\r\n0\r\n#\r#\n')[
            'body'
        ]
        == 'abcd'
    )


def test_proxy_chunked_invalid():
    def check_invalid(body):
        assert get_http10(body=body)['status'] != 200

    check_invalid('\r\n\r0')
    check_invalid('\r\n\r\n\r0')
    check_invalid('\r\n\r\n\r\n0')
    check_invalid('\r\nContent-Length: 5\r\n\r\n0\r\n\r\n')
    check_invalid('\r\n\r\n1\r\nXX\r\n0\r\n\r\n')
    check_invalid('\r\n\r\n2\r\nX\r\n0\r\n\r\n')
    check_invalid('\r\n\r\nH\r\nXX\r\n0\r\n\r\n')
    check_invalid('\r\n\r\n0\r\nX')

    resp = get_http10(body='\r\n\r\n65#\r\nA X 100')
    assert resp['status'] == 200, 'incomplete chunk status'
    assert resp['body'][-5:] != '0\r\n\r\n', 'incomplete chunk'

    resp = get_http10(body='\r\n\r\n64#\r\nA X 100')
    assert resp['status'] == 200, 'no zero chunk status'
    assert resp['body'][-5:] != '0\r\n\r\n', 'no zero chunk'

    assert get_http10(body='\r\n\r\n80000000\r\nA X 100')['status'] == 200
    assert (
        get_http10(body='\r\n\r\n10000000000000000\r\nA X 100')['status'] == 502
    )
    assert (
        len(
            get_http10(
                body='\r\n\r\n1000000\r\nA X 1048576\r\n1000000\r\nA X 100',
                read_buffer_size=4096 * 4096,
            )['body']
        )
        >= 1048576
    )
    assert (
        len(
            get_http10(
                body='\r\n\r\n1000000\r\nA X 1048576\r\nXXX\r\nA X 100',
                read_buffer_size=4096 * 4096,
            )['body']
        )
        >= 1048576
    )
