import grp
import os
import pwd
import re
import subprocess
import time
import venv

import pytest
from packaging import version

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'all'}}

client = ApplicationPython()


def test_python_application_variables(date_to_sec_epoch, sec_epoch):
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
    assert (
        headers.pop('Server-Software') == header_server
    ), 'server software header'

    date = headers.pop('Date')
    assert date[-4:] == ' GMT', 'date header timezone'
    assert abs(date_to_sec_epoch(date) - sec_epoch) < 5, 'date header'

    assert headers == {
        'Connection': 'close',
        'Content-Length': str(len(body)),
        'Content-Type': 'text/html',
        'Request-Method': 'POST',
        'Request-Uri': '/',
        'Http-Host': 'localhost',
        'Server-Protocol': 'HTTP/1.1',
        'Custom-Header': 'blah, Blah, BLAH',
        'Wsgi-Version': '(1, 0)',
        'Wsgi-Url-Scheme': 'http',
        'Wsgi-Multithread': 'False',
        'Wsgi-Multiprocess': 'True',
        'Wsgi-Run-Once': 'False',
    }, 'headers'
    assert resp['body'] == body, 'body'

    # REQUEST_URI unchanged

    path = f'{option.test_dir}/python/variables'
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "action": {
                        "rewrite": "/foo",
                        "pass": "applications/variables",
                    }
                }
            ],
            "applications": {
                "variables": {
                    "type": client.get_application_type(),
                    "processes": {'spare': 0},
                    "path": path,
                    "working_directory": path,
                    "module": "wsgi",
                }
            },
        }
    )

    resp = client.http(
        f"""POST /bar HTTP/1.1
Host: localhost
Content-Length: 1
Custom-Header: blah
Content-Type: text/html
Connection: close

a""".encode(),
        raw=True,
    )
    assert resp['headers']['Request-Uri'] == '/bar', 'REQUEST_URI unchanged'


def test_python_application_query_string():
    client.load('query_string')

    resp = client.get(url='/?var1=val1&var2=val2')

    assert (
        resp['headers']['Query-String'] == 'var1=val1&var2=val2'
    ), 'Query-String header'


def test_python_application_query_string_space():
    client.load('query_string')

    resp = client.get(url='/ ?var1=val1&var2=val2')
    assert (
        resp['headers']['Query-String'] == 'var1=val1&var2=val2'
    ), 'Query-String space'

    resp = client.get(url='/ %20?var1=val1&var2=val2')
    assert (
        resp['headers']['Query-String'] == 'var1=val1&var2=val2'
    ), 'Query-String space 2'

    resp = client.get(url='/ %20 ?var1=val1&var2=val2')
    assert (
        resp['headers']['Query-String'] == 'var1=val1&var2=val2'
    ), 'Query-String space 3'

    resp = client.get(url='/blah %20 blah? var1= val1 & var2=val2')
    assert (
        resp['headers']['Query-String'] == ' var1= val1 & var2=val2'
    ), 'Query-String space 4'


def test_python_application_prefix():
    client.load('prefix', prefix='/api/rest')

    def set_prefix(prefix):
        client.conf(f'"{prefix}"', 'applications/prefix/prefix')

    def check_prefix(url, script_name, path_info):
        resp = client.get(url=url)
        assert resp['status'] == 200
        assert resp['headers']['Script-Name'] == script_name
        assert resp['headers']['Path-Info'] == path_info

    check_prefix('/ap', 'NULL', '/ap')
    check_prefix('/api', 'NULL', '/api')
    check_prefix('/api/', 'NULL', '/api/')
    check_prefix('/api/res', 'NULL', '/api/res')
    check_prefix('/api/restful', 'NULL', '/api/restful')
    check_prefix('/api/rest', '/api/rest', '')
    check_prefix('/api/rest/', '/api/rest', '/')
    check_prefix('/api/rest/get', '/api/rest', '/get')
    check_prefix('/api/rest/get/blah', '/api/rest', '/get/blah')

    set_prefix('/api/rest/')
    check_prefix('/api/rest', '/api/rest', '')
    check_prefix('/api/restful', 'NULL', '/api/restful')
    check_prefix('/api/rest/', '/api/rest', '/')
    check_prefix('/api/rest/blah', '/api/rest', '/blah')

    set_prefix('/app')
    check_prefix('/ap', 'NULL', '/ap')
    check_prefix('/app', '/app', '')
    check_prefix('/app/', '/app', '/')
    check_prefix('/application/', 'NULL', '/application/')

    set_prefix('/')
    check_prefix('/', 'NULL', '/')
    check_prefix('/app', 'NULL', '/app')


def test_python_application_query_string_empty():
    client.load('query_string')

    resp = client.get(url='/?')

    assert resp['status'] == 200, 'query string empty status'
    assert resp['headers']['Query-String'] == '', 'query string empty'


def test_python_application_query_string_absent():
    client.load('query_string')

    resp = client.get()

    assert resp['status'] == 200, 'query string absent status'
    assert resp['headers']['Query-String'] == '', 'query string absent'


@pytest.mark.skip('not yet')
def test_python_application_server_port():
    client.load('server_port')

    assert (
        client.get()['headers']['Server-Port'] == '8080'
    ), 'Server-Port header'


@pytest.mark.skip('not yet')
def test_python_application_working_directory_invalid():
    client.load('empty')

    assert 'success' in client.conf(
        '"/blah"', 'applications/empty/working_directory'
    ), 'configure invalid working_directory'

    assert client.get()['status'] == 500, 'status'


def test_python_application_204_transfer_encoding():
    client.load('204_no_content')

    assert (
        'Transfer-Encoding' not in client.get()['headers']
    ), '204 header transfer encoding'


def test_python_application_ctx_iter_atexit(wait_for_record):
    client.load('ctx_iter_atexit')

    resp = client.post(body='0123456789')

    assert resp['status'] == 200, 'ctx iter status'
    assert resp['body'] == '0123456789', 'ctx iter body'

    assert 'success' in client.conf({"listeners": {}, "applications": {}})

    assert wait_for_record(r'RuntimeError') is not None, 'ctx iter atexit'


def test_python_keepalive_body():
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


def test_python_keepalive_reconfigure():
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


def test_python_keepalive_reconfigure_2():
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


def test_python_atexit(wait_for_record):
    client.load('atexit')

    client.get()

    assert 'success' in client.conf({"listeners": {}, "applications": {}})

    assert wait_for_record(r'At exit called\.') is not None, 'atexit'


def test_python_process_switch():
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


@pytest.mark.skip('not yet')
def test_python_application_start_response_exit():
    client.load('start_response_exit')

    assert client.get()['status'] == 500, 'start response exit'


def test_python_application_input_iter():
    client.load('input_iter')

    body = '''0123456789
next line

last line'''

    resp = client.post(body=body)
    assert resp['body'] == body, 'input iter'
    assert resp['headers']['X-Lines-Count'] == '4', 'input iter lines'


def test_python_application_input_readline():
    client.load('input_readline')

    body = '''0123456789
next line

last line'''

    resp = client.post(body=body)
    assert resp['body'] == body, 'input readline'
    assert resp['headers']['X-Lines-Count'] == '4', 'input readline lines'


def test_python_application_input_readline_size():
    client.load('input_readline_size')

    body = '''0123456789
next line

last line'''

    assert client.post(body=body)['body'] == body, 'input readline size'
    assert (
        client.post(body='0123')['body'] == '0123'
    ), 'input readline size less'


def test_python_application_input_readlines():
    client.load('input_readlines')

    body = '''0123456789
next line

last line'''

    resp = client.post(body=body)
    assert resp['body'] == body, 'input readlines'
    assert resp['headers']['X-Lines-Count'] == '4', 'input readlines lines'


def test_python_application_input_readlines_huge():
    client.load('input_readlines')

    body = (
        '''0123456789 abcdefghi
next line: 0123456789 abcdefghi

last line: 987654321
'''
        * 512
    )

    assert (
        client.post(body=body, read_buffer_size=16384)['body'] == body
    ), 'input readlines huge'


def test_python_application_input_read_length():
    client.load('input_read_length')

    body = '0123456789'

    resp = client.post(
        headers={
            'Host': 'localhost',
            'Input-Length': '5',
            'Connection': 'close',
        },
        body=body,
    )

    assert resp['body'] == body[:5], 'input read length lt body'

    resp = client.post(
        headers={
            'Host': 'localhost',
            'Input-Length': '15',
            'Connection': 'close',
        },
        body=body,
    )

    assert resp['body'] == body, 'input read length gt body'

    resp = client.post(
        headers={
            'Host': 'localhost',
            'Input-Length': '0',
            'Connection': 'close',
        },
        body=body,
    )

    assert resp['body'] == '', 'input read length zero'

    resp = client.post(
        headers={
            'Host': 'localhost',
            'Input-Length': '-1',
            'Connection': 'close',
        },
        body=body,
    )

    assert resp['body'] == body, 'input read length negative'


@pytest.mark.skip('not yet')
def test_python_application_errors_write(wait_for_record):
    client.load('errors_write')

    client.get()

    assert (
        wait_for_record(r'\[error\].+Error in application\.') is not None
    ), 'errors write'


def test_python_application_body_array():
    client.load('body_array')

    assert client.get()['body'] == '0123456789', 'body array'


def test_python_application_body_io():
    client.load('body_io')

    assert client.get()['body'] == '0123456789', 'body io'


def test_python_application_body_io_file():
    client.load('body_io_file')

    assert client.get()['body'] == 'body\n', 'body io file'


@pytest.mark.skip('not yet')
def test_python_application_syntax_error(skip_alert):
    skip_alert(r'Python failed to import module "wsgi"')
    client.load('syntax_error')

    assert client.get()['status'] == 500, 'syntax error'


def test_python_application_loading_error(skip_alert):
    skip_alert(r'Python failed to import module "blah"')

    client.load('empty', module="blah")

    assert client.get()['status'] == 503, 'loading error'


def test_python_application_close(wait_for_record):
    client.load('close')

    client.get()

    assert wait_for_record(r'Close called\.') is not None, 'close'


def test_python_application_close_error(wait_for_record):
    client.load('close_error')

    client.get()

    assert wait_for_record(r'Close called\.') is not None, 'close error'


def test_python_application_not_iterable(wait_for_record):
    client.load('not_iterable')

    client.get()

    assert (
        wait_for_record(
            r'\[error\].+the application returned not an iterable object'
        )
        is not None
    ), 'not iterable'


def test_python_application_write():
    client.load('write')

    assert client.get()['body'] == '0123456789', 'write'


def test_python_application_encoding():
    client.load('encoding')

    try:
        locales = (
            subprocess.check_output(
                ['locale', '-a'],
                stderr=subprocess.STDOUT,
            )
            .decode()
            .splitlines()
        )
    except (
        FileNotFoundError,
        UnicodeDecodeError,
        subprocess.CalledProcessError,
    ):
        pytest.skip('require locale')

    to_check = [
        re.compile(r'.*UTF[-_]?8'),
        re.compile(r'.*ISO[-_]?8859[-_]?1'),
    ]
    matches = [
        loc
        for loc in locales
        if any(pattern.match(loc.upper()) for pattern in to_check)
    ]

    if not matches:
        pytest.skip('no available locales')

    def unify(enc):
        enc.upper().replace('-', '').replace('_', '')

    for loc in matches:
        assert 'success' in client.conf(
            {"LC_CTYPE": loc, "LC_ALL": ""},
            '/config/applications/encoding/environment',
        )
        resp = client.get()
        assert resp['status'] == 200, 'status'
        assert unify(resp['headers']['X-Encoding']) == unify(loc.split('.')[-1])


def test_python_application_unicode(temp_dir):
    try:
        app_type = client.get_application_type()
        v = version.Version(app_type.split()[-1])
        if v.major != 3:
            raise version.InvalidVersion

    except version.InvalidVersion:
        pytest.skip('require python module version 3')

    venv_path = f'{temp_dir}/venv'
    venv.create(venv_path)

    client.load('unicode')
    assert 'success' in client.conf(
        f'"{venv_path}"',
        '/config/applications/unicode/home',
    )
    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Temp-dir': temp_dir,
                'Connection': 'close',
            }
        )['status']
        == 200
    )


def test_python_application_threading(wait_for_record):
    """wait_for_record() timeouts after 5s while every thread works at
    least 3s.  So without releasing GIL test should fail.
    """

    client.load('threading')

    for _ in range(10):
        client.get(no_recv=True)

    assert (
        wait_for_record(r'\(5\) Thread: 100', wait=50) is not None
    ), 'last thread finished'


def test_python_application_iter_exception(findall, wait_for_record):
    client.load('iter_exception')

    # Default request doesn't lead to the exception.

    resp = client.get(
        headers={
            'Host': 'localhost',
            'X-Skip': '9',
            'X-Chunked': '1',
            'Connection': 'close',
        }
    )
    assert resp['status'] == 200, 'status'
    assert resp['body'] == 'XXXXXXX', 'body'

    # Exception before start_response().

    assert client.get()['status'] == 503, 'error'

    assert wait_for_record(r'Traceback') is not None, 'traceback'
    assert (
        wait_for_record(r"raise Exception\('first exception'\)") is not None
    ), 'first exception raise'
    assert len(findall(r'Traceback')) == 1, 'traceback count 1'

    # Exception after start_response(), before first write().

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '1',
                'Connection': 'close',
            }
        )['status']
        == 503
    ), 'error 2'

    assert (
        wait_for_record(r"raise Exception\('second exception'\)") is not None
    ), 'exception raise second'
    assert len(findall(r'Traceback')) == 2, 'traceback count 2'

    # Exception after first write(), before first __next__().

    _, sock = client.get(
        headers={
            'Host': 'localhost',
            'X-Skip': '2',
            'Connection': 'keep-alive',
        },
        start=True,
    )

    assert (
        wait_for_record(r"raise Exception\('third exception'\)") is not None
    ), 'exception raise third'
    assert len(findall(r'Traceback')) == 3, 'traceback count 3'

    assert client.get(sock=sock) == {}, 'closed connection'

    # Exception after first write(), before first __next__(),
    # chunked (incomplete body).

    resp = client.get(
        headers={
            'Host': 'localhost',
            'X-Skip': '2',
            'X-Chunked': '1',
            'Connection': 'close',
        },
        raw_resp=True,
    )
    if resp:
        assert resp[-5:] != '0\r\n\r\n', 'incomplete body'
    assert len(findall(r'Traceback')) == 4, 'traceback count 4'

    # Exception in __next__().

    _, sock = client.get(
        headers={
            'Host': 'localhost',
            'X-Skip': '3',
            'Connection': 'keep-alive',
        },
        start=True,
    )

    assert (
        wait_for_record(r"raise Exception\('next exception'\)") is not None
    ), 'exception raise next'
    assert len(findall(r'Traceback')) == 5, 'traceback count 5'

    assert client.get(sock=sock) == {}, 'closed connection 2'

    # Exception in __next__(), chunked (incomplete body).

    resp = client.get(
        headers={
            'Host': 'localhost',
            'X-Skip': '3',
            'X-Chunked': '1',
            'Connection': 'close',
        },
        raw_resp=True,
    )
    if resp:
        assert resp[-5:] != '0\r\n\r\n', 'incomplete body 2'
    assert len(findall(r'Traceback')) == 6, 'traceback count 6'

    # Exception before start_response() and in close().

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'X-Not-Skip-Close': '1',
                'Connection': 'close',
            }
        )['status']
        == 503
    ), 'error'

    assert (
        wait_for_record(r"raise Exception\('close exception'\)") is not None
    ), 'exception raise close'
    assert len(findall(r'Traceback')) == 8, 'traceback count 8'


def test_python_user_group(require):
    require({'privileged_user': True})

    nobody_uid = pwd.getpwnam('nobody').pw_uid

    group = 'nobody'

    try:
        group_id = grp.getgrnam(group).gr_gid
    except KeyError:
        group = 'nogroup'
        group_id = grp.getgrnam(group).gr_gid

    client.load('user_group')

    obj = client.getjson()['body']
    assert obj['UID'] == nobody_uid, 'nobody uid'
    assert obj['GID'] == group_id, 'nobody gid'

    client.load('user_group', user='nobody')

    obj = client.getjson()['body']
    assert obj['UID'] == nobody_uid, 'nobody uid user=nobody'
    assert obj['GID'] == group_id, 'nobody gid user=nobody'

    client.load('user_group', user='nobody', group=group)

    obj = client.getjson()['body']
    assert obj['UID'] == nobody_uid, f'nobody uid user=nobody group={group}'
    assert obj['GID'] == group_id, f'nobody gid user=nobody group={group}'

    client.load('user_group', group=group)

    obj = client.getjson()['body']
    assert obj['UID'] == nobody_uid, f'nobody uid group={group}'
    assert obj['GID'] == group_id, f'nobody gid group={group}'

    client.load('user_group', user='root')

    obj = client.getjson()['body']
    assert obj['UID'] == 0, 'root uid user=root'
    assert obj['GID'] == 0, 'root gid user=root'

    group = 'root'

    try:
        grp.getgrnam(group)
        group = True
    except KeyError:
        group = False

    if group:
        client.load('user_group', user='root', group='root')

        obj = client.getjson()['body']
        assert obj['UID'] == 0, 'root uid user=root group=root'
        assert obj['GID'] == 0, 'root gid user=root group=root'

        client.load('user_group', group='root')

        obj = client.getjson()['body']
        assert obj['UID'] == nobody_uid, 'root uid group=root'
        assert obj['GID'] == 0, 'root gid group=root'


def test_python_application_callable(skip_alert):
    skip_alert(r'Python failed to get "blah" from module')
    client.load('callable')

    assert client.get()['status'] == 204, 'default application response'

    client.load('callable', callable="app")

    assert client.get()['status'] == 200, 'callable response'

    client.load('callable', callable="blah")

    assert client.get()['status'] not in [200, 204], 'callable response inv'


def test_python_application_path():
    client.load('path')

    def set_path(path):
        assert 'success' in client.conf(path, 'applications/path/path')

    def get_path():
        return client.get()['body'].split(os.pathsep)

    default_path = client.conf_get('/config/applications/path/path')
    assert 'success' in client.conf(
        {"PYTHONPATH": default_path},
        '/config/applications/path/environment',
    )

    client.conf_delete('/config/applications/path/path')
    sys_path = get_path()

    set_path('"/blah"')
    assert ['/blah', *sys_path] == get_path(), 'check path'

    set_path('"/new"')
    assert ['/new', *sys_path] == get_path(), 'check path update'

    set_path('["/blah1", "/blah2"]')
    assert [
        '/blah1',
        '/blah2',
        *sys_path,
    ] == get_path(), 'check path array'


def test_python_application_path_invalid():
    client.load('path')

    def check_path(path):
        assert 'error' in client.conf(path, 'applications/path/path')

    check_path('{}')
    check_path('["/blah", []]')


def test_python_application_threads():
    client.load('threads', threads=4)

    socks = []

    for _ in range(4):
        sock = client.get(
            headers={
                'Host': 'localhost',
                'X-Delay': '2',
                'Connection': 'close',
            },
            no_recv=True,
        )

        socks.append(sock)

    threads = set()

    for sock in socks:
        resp = client.recvall(sock).decode('utf-8')

        client.log_in(resp)

        resp = client._resp_to_dict(resp)

        assert resp['status'] == 200, 'status'

        threads.add(resp['headers']['X-Thread'])

        assert resp['headers']['Wsgi-Multithread'] == 'True', 'multithread'

        sock.close()

    assert len(socks) == len(threads), 'threads differs'
