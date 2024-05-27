import re
import time

import pytest
from packaging import version

from unit.applications.lang.python import ApplicationPython

prerequisites = {
    'modules': {'python': lambda v: version.parse(v) >= version.parse('3.5')}
}

client = ApplicationPython(load_module='asgi')


def test_asgi_application_variables(date_to_sec_epoch, sec_epoch):
    client.load('variables')

    body = 'Test body string.'

    resp = client.http(
        f"""POST / HTTP/1.1
Host: localhost
Content-Length: {len(body)}
Custom-Header: blah
Custom-hEader: Blah
Content-Type: text/html
Connection: close
custom-header: BLAH

{body}""".encode(),
        raw=True,
    )

    assert resp['status'] == 200, 'status'
    headers = resp['headers']
    header_server = headers.pop('Server')
    assert re.search(r'Unit/[\d\.]+', header_server), 'server header'

    date = headers.pop('Date')
    assert date[-4:] == ' GMT', 'date header timezone'
    assert abs(date_to_sec_epoch(date) - sec_epoch) < 5, 'date header'

    assert headers == {
        'Connection': 'close',
        'content-length': str(len(body)),
        'content-type': 'text/html',
        'request-method': 'POST',
        'request-uri': '/',
        'http-host': 'localhost',
        'http-version': '1.1',
        'custom-header': 'blah, Blah, BLAH',
        'asgi-version': '3.0',
        'asgi-spec-version': '2.1',
        'scheme': 'http',
    }, 'headers'
    assert resp['body'] == body, 'body'


def test_asgi_application_ipv6():
    client.load('empty')

    assert 'success' in client.conf(
        {"[::1]:8080": {"pass": "applications/empty"}}, 'listeners'
    )

    assert client.get(sock_type='ipv6')['status'] == 200


def test_asgi_application_unix(temp_dir):
    client.load('empty')

    addr = f'{temp_dir}/sock'
    assert 'success' in client.conf(
        {f"unix:{addr}": {"pass": "applications/empty"}}, 'listeners'
    )

    assert client.get(sock_type='unix', addr=addr)['status'] == 200


def test_asgi_application_query_string():
    client.load('query_string')

    resp = client.get(url='/?var1=val1&var2=val2')

    assert (
        resp['headers']['query-string'] == 'var1=val1&var2=val2'
    ), 'query-string header'


def test_asgi_application_prefix():
    client.load('prefix', prefix='/api/rest')

    def set_prefix(prefix):
        client.conf(f'"{prefix}"', 'applications/prefix/prefix')

    def check_prefix(url, prefix):
        resp = client.get(url=url)
        assert resp['status'] == 200
        assert resp['headers']['prefix'] == prefix

    check_prefix('/ap', 'NULL')
    check_prefix('/api', 'NULL')
    check_prefix('/api/', 'NULL')
    check_prefix('/api/res', 'NULL')
    check_prefix('/api/restful', 'NULL')
    check_prefix('/api/rest', '/api/rest')
    check_prefix('/api/rest/', '/api/rest')
    check_prefix('/api/rest/get', '/api/rest')
    check_prefix('/api/rest/get/blah', '/api/rest')

    set_prefix('/api/rest/')
    check_prefix('/api/rest', '/api/rest')
    check_prefix('/api/restful', 'NULL')
    check_prefix('/api/rest/', '/api/rest')
    check_prefix('/api/rest/blah', '/api/rest')

    set_prefix('/app')
    check_prefix('/ap', 'NULL')
    check_prefix('/app', '/app')
    check_prefix('/app/', '/app')
    check_prefix('/application/', 'NULL')

    set_prefix('/')
    check_prefix('/', 'NULL')
    check_prefix('/app', 'NULL')


def test_asgi_application_query_string_space():
    client.load('query_string')

    resp = client.get(url='/ ?var1=val1&var2=val2')
    assert (
        resp['headers']['query-string'] == 'var1=val1&var2=val2'
    ), 'query-string space'

    resp = client.get(url='/ %20?var1=val1&var2=val2')
    assert (
        resp['headers']['query-string'] == 'var1=val1&var2=val2'
    ), 'query-string space 2'

    resp = client.get(url='/ %20 ?var1=val1&var2=val2')
    assert (
        resp['headers']['query-string'] == 'var1=val1&var2=val2'
    ), 'query-string space 3'

    resp = client.get(url='/blah %20 blah? var1= val1 & var2=val2')
    assert (
        resp['headers']['query-string'] == ' var1= val1 & var2=val2'
    ), 'query-string space 4'


def test_asgi_application_query_string_empty():
    client.load('query_string')

    resp = client.get(url='/?')

    assert resp['status'] == 200, 'query string empty status'
    assert resp['headers']['query-string'] == '', 'query string empty'


def test_asgi_application_query_string_absent():
    client.load('query_string')

    resp = client.get()

    assert resp['status'] == 200, 'query string absent status'
    assert resp['headers']['query-string'] == '', 'query string absent'


@pytest.mark.skip('not yet')
def test_asgi_application_server_port():
    client.load('server_port')

    assert (
        client.get()['headers']['Server-Port'] == '8080'
    ), 'Server-Port header'


@pytest.mark.skip('not yet')
def test_asgi_application_working_directory_invalid():
    client.load('empty')

    assert 'success' in client.conf(
        '"/blah"', 'applications/empty/working_directory'
    ), 'configure invalid working_directory'

    assert client.get()['status'] == 500, 'status'


def test_asgi_application_204_transfer_encoding():
    client.load('204_no_content')

    assert (
        'Transfer-Encoding' not in client.get()['headers']
    ), '204 header transfer encoding'


def test_asgi_application_shm_ack_handle():
    # Minimum possible limit
    shm_limit = 10 * 1024 * 1024

    client.load('mirror', limits={"shm": shm_limit})

    # Should exceed shm_limit
    max_body_size = 12 * 1024 * 1024

    assert 'success' in client.conf(
        f'{{"http":{{"max_body_size": {max_body_size} }}}}',
        'settings',
    )

    assert client.get()['status'] == 200, 'init'

    body = '0123456789AB' * 1024 * 1024  # 12 Mb
    resp = client.post(body=body, read_buffer_size=1024 * 1024)

    assert resp['body'] == body, 'keep-alive 1'


def test_asgi_application_body_bytearray():
    client.load('body_bytearray')

    body = '0123456789'

    assert client.post(body=body)['body'] == body


def test_asgi_keepalive_body():
    client.load('mirror')

    assert client.get()['status'] == 200, 'init'

    body = '0123456789' * 500
    (resp, sock) = client.post(
        headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
        },
        start=True,
        body=body,
        read_timeout=1,
    )

    assert resp['body'] == body, 'keep-alive 1'

    body = '0123456789'
    resp = client.post(sock=sock, body=body)

    assert resp['body'] == body, 'keep-alive 2'


def test_asgi_keepalive_reconfigure():
    client.load('mirror')

    assert client.get()['status'] == 200, 'init'

    body = '0123456789'
    conns = 3
    socks = []

    for i in range(conns):
        (resp, sock) = client.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
            },
            start=True,
            body=body,
            read_timeout=1,
        )

        assert resp['body'] == body, 'keep-alive open'

        client.load('mirror', processes=i + 1)

        socks.append(sock)

    for i in range(conns):
        (resp, sock) = client.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
            },
            start=True,
            sock=socks[i],
            body=body,
            read_timeout=1,
        )

        assert resp['body'] == body, 'keep-alive request'

        client.load('mirror', processes=i + 1)

    for i in range(conns):
        resp = client.post(sock=socks[i], body=body)

        assert resp['body'] == body, 'keep-alive close'

        client.load('mirror', processes=i + 1)


def test_asgi_keepalive_reconfigure_2():
    client.load('mirror')

    assert client.get()['status'] == 200, 'init'

    body = '0123456789'

    (resp, sock) = client.post(
        headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
        },
        start=True,
        body=body,
        read_timeout=1,
    )

    assert resp['body'] == body, 'reconfigure 2 keep-alive 1'

    client.load('empty')

    assert client.get()['status'] == 200, 'init'

    (resp, sock) = client.post(start=True, sock=sock, body=body)

    assert resp['status'] == 200, 'reconfigure 2 keep-alive 2'
    assert resp['body'] == '', 'reconfigure 2 keep-alive 2 body'

    assert 'success' in client.conf(
        {"listeners": {}, "applications": {}}
    ), 'reconfigure 2 clear configuration'

    resp = client.get(sock=sock)

    assert resp == {}, 'reconfigure 2 keep-alive 3'


def test_asgi_keepalive_reconfigure_3():
    client.load('empty')

    assert client.get()['status'] == 200, 'init'

    sock = client.http(
        b"""GET / HTTP/1.1
""",
        raw=True,
        no_recv=True,
    )

    assert client.get()['status'] == 200

    assert 'success' in client.conf(
        {"listeners": {}, "applications": {}}
    ), 'reconfigure 3 clear configuration'

    resp = client.http(
        b"""Host: localhost
Connection: close

""",
        sock=sock,
        raw=True,
    )

    assert resp['status'] == 200, 'reconfigure 3'


def test_asgi_process_switch():
    client.load('delayed', processes=2)

    client.get(
        headers={
            'Host': 'localhost',
            'Content-Length': '0',
            'X-Delay': '5',
            'Connection': 'close',
        },
        no_recv=True,
    )

    headers_delay_1 = {
        'Connection': 'close',
        'Host': 'localhost',
        'Content-Length': '0',
        'X-Delay': '1',
    }

    client.get(headers=headers_delay_1, no_recv=True)

    time.sleep(0.5)

    for _ in range(10):
        client.get(headers=headers_delay_1, no_recv=True)

    client.get(headers=headers_delay_1)


def test_asgi_application_loading_error(skip_alert):
    skip_alert(r'Python failed to import module "blah"')

    client.load('empty', module="blah")

    assert client.get()['status'] == 503, 'loading error'


def test_asgi_application_threading(wait_for_record):
    """wait_for_record() timeouts after 5s while every thread works at
    least 3s.  So without releasing GIL test should fail.
    """

    client.load('threading')

    for _ in range(10):
        client.get(no_recv=True)

    assert (
        wait_for_record(r'\(5\) Thread: 100', wait=50) is not None
    ), 'last thread finished'


def test_asgi_application_threads():
    client.load('threads', threads=2)

    socks = []

    for _ in range(2):
        sock = client.get(
            headers={
                'Host': 'localhost',
                'X-Delay': '3',
                'Connection': 'close',
            },
            no_recv=True,
        )

        socks.append(sock)

        time.sleep(1.0)  # required to avoid greedy request reading

    threads = set()

    for sock in socks:
        resp = client.recvall(sock).decode('utf-8')

        client.log_in(resp)

        resp = client._resp_to_dict(resp)

        assert resp['status'] == 200, 'status'

        threads.add(resp['headers']['x-thread'])

        sock.close()

    assert len(socks) == len(threads), 'threads differs'


def test_asgi_application_legacy():
    client.load('legacy')

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Content-Length': '0',
            'Connection': 'close',
        },
    )

    assert resp['status'] == 200, 'status'


def test_asgi_application_legacy_force():
    client.load('legacy_force', protocol='asgi')

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Content-Length': '0',
            'Connection': 'close',
        },
    )

    assert resp['status'] == 200, 'status'
