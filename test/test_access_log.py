import time

import pytest

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


def load(script):
    client.load(script)

    assert 'success' in client.conf(
        f'"{option.temp_dir}/access.log"', 'access_log'
    ), 'access_log configure'


def set_format(log_format):
    assert 'success' in client.conf(
        {
            'path': f'{option.temp_dir}/access.log',
            'format': log_format,
        },
        'access_log',
    ), 'access_log format'


def set_if(condition):
    assert 'success' in client.conf(f'"{condition}"', 'access_log/if')


def test_access_log_keepalive(wait_for_record):
    load('mirror')

    assert client.get()['status'] == 200, 'init'

    (_, sock) = client.post(
        headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
        },
        start=True,
        body='01234',
        read_timeout=1,
    )

    assert (
        wait_for_record(r'"POST / HTTP/1.1" 200 5', 'access.log') is not None
    ), 'keepalive 1'

    _ = client.post(sock=sock, body='0123456789')

    assert (
        wait_for_record(r'"POST / HTTP/1.1" 200 10', 'access.log') is not None
    ), 'keepalive 2'


def test_access_log_pipeline(wait_for_record):
    load('empty')

    client.http(
        b"""GET / HTTP/1.1
Host: localhost
Referer: Referer-1

GET / HTTP/1.1
Host: localhost
Referer: Referer-2

GET / HTTP/1.1
Host: localhost
Referer: Referer-3
Connection: close

""",
        raw_resp=True,
        raw=True,
    )

    assert (
        wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-1" "-"', 'access.log')
        is not None
    ), 'pipeline 1'
    assert (
        wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-2" "-"', 'access.log')
        is not None
    ), 'pipeline 2'
    assert (
        wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-3" "-"', 'access.log')
        is not None
    ), 'pipeline 3'


def test_access_log_ipv6(wait_for_record):
    load('empty')

    assert 'success' in client.conf(
        {"[::1]:8080": {"pass": "applications/empty"}}, 'listeners'
    )

    client.get(sock_type='ipv6')

    assert (
        wait_for_record(
            r'::1 - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"', 'access.log'
        )
        is not None
    ), 'ipv6'


def test_access_log_unix(temp_dir, wait_for_record):
    load('empty')

    addr = f'{temp_dir}/sock'

    assert 'success' in client.conf(
        {f'unix:{addr}': {"pass": "applications/empty"}}, 'listeners'
    )

    client.get(sock_type='unix', addr=addr)

    assert (
        wait_for_record(
            r'unix: - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"', 'access.log'
        )
        is not None
    ), 'unix'


def test_access_log_referer(wait_for_record):
    load('empty')

    client.get(
        headers={
            'Host': 'localhost',
            'Referer': 'referer-value',
            'Connection': 'close',
        }
    )

    assert (
        wait_for_record(
            r'"GET / HTTP/1.1" 200 0 "referer-value" "-"', 'access.log'
        )
        is not None
    ), 'referer'


def test_access_log_user_agent(wait_for_record):
    load('empty')

    client.get(
        headers={
            'Host': 'localhost',
            'User-Agent': 'user-agent-value',
            'Connection': 'close',
        }
    )

    assert (
        wait_for_record(
            r'"GET / HTTP/1.1" 200 0 "-" "user-agent-value"', 'access.log'
        )
        is not None
    ), 'user agent'


def test_access_log_http10(wait_for_record):
    load('empty')

    client.get(http_10=True)

    assert (
        wait_for_record(r'"GET / HTTP/1.0" 200 0 "-" "-"', 'access.log')
        is not None
    ), 'http 1.0'


def test_access_log_partial(wait_for_record):
    load('empty')

    assert client.post()['status'] == 200, 'init'

    _ = client.http(b"""GE""", raw=True, read_timeout=1)

    time.sleep(1)

    assert (
        wait_for_record(r'"-" 400 0 "-" "-"', 'access.log') is not None
    ), 'partial'


def test_access_log_partial_2(wait_for_record):
    load('empty')

    assert client.post()['status'] == 200, 'init'

    client.http(b"""GET /\n""", raw=True)

    assert (
        wait_for_record(r'"-" 400 \d+ "-" "-"', 'access.log') is not None
    ), 'partial 2'


def test_access_log_partial_3(wait_for_record):
    load('empty')

    assert client.post()['status'] == 200, 'init'

    _ = client.http(b"""GET / HTTP/1.1""", raw=True, read_timeout=1)

    time.sleep(1)

    assert (
        wait_for_record(r'"-" 400 0 "-" "-"', 'access.log') is not None
    ), 'partial 3'


def test_access_log_partial_4(wait_for_record):
    load('empty')

    assert client.post()['status'] == 200, 'init'

    _ = client.http(b"""GET / HTTP/1.1\n""", raw=True, read_timeout=1)

    time.sleep(1)

    assert (
        wait_for_record(r'"-" 400 0 "-" "-"', 'access.log') is not None
    ), 'partial 4'


@pytest.mark.skip('not yet')
def test_access_log_partial_5(wait_for_record):
    load('empty')

    assert client.post()['status'] == 200, 'init'

    client.get(headers={'Connection': 'close'})

    assert (
        wait_for_record(r'"GET / HTTP/1.1" 400 \d+ "-" "-"', 'access.log')
        is not None
    ), 'partial 5'


def test_access_log_get_parameters(wait_for_record):
    load('empty')

    client.get(url='/?blah&var=val')

    assert (
        wait_for_record(
            r'"GET /\?blah&var=val HTTP/1.1" 200 0 "-" "-"', 'access.log'
        )
        is not None
    ), 'get parameters'


def test_access_log_delete(search_in_file):
    load('empty')

    assert 'success' in client.conf_delete('access_log')

    client.get(url='/delete')

    assert search_in_file(r'/delete', 'access.log') is None, 'delete'


def test_access_log_change(temp_dir, wait_for_record):
    load('empty')

    client.get()

    assert 'success' in client.conf(f'"{temp_dir}/new.log"', 'access_log')

    client.get()

    assert (
        wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', 'new.log')
        is not None
    ), 'change'


def test_access_log_format(wait_for_record):
    load('empty')

    def check_format(log_format, expect, url='/'):
        set_format(log_format)

        assert client.get(url=url)['status'] == 200
        assert wait_for_record(expect, 'access.log') is not None, 'found'

    log_format = 'BLAH\t0123456789'
    check_format(log_format, log_format)
    check_format('$uri $status $uri $status', '/ 200 / 200')


def test_access_log_variables(wait_for_record):
    load('mirror')

    # $body_bytes_sent

    set_format('$uri $body_bytes_sent')
    body = '0123456789' * 50
    client.post(url='/bbs', body=body, read_timeout=1)
    assert (
        wait_for_record(fr'^\/bbs {len(body)}$', 'access.log') is not None
    ), '$body_bytes_sent'


def test_access_log_if(search_in_file, wait_for_record):
    load('empty')
    set_format('$uri')

    def try_if(condition):
        set_if(condition)
        assert client.get(url=f'/{condition}')['status'] == 200

    # const

    try_if('')
    try_if('0')
    try_if('false')
    try_if('undefined')
    try_if('!')
    try_if('!null')
    try_if('1')

    # variable

    set_if('$arg_foo')
    assert client.get(url='/bar?bar')['status'] == 200
    assert client.get(url='/foo_empty?foo')['status'] == 200
    assert client.get(url='/foo?foo=1')['status'] == 200

    # check results

    assert wait_for_record(r'^/foo$', 'access.log') is not None

    assert search_in_file(r'^/$', 'access.log') is None
    assert search_in_file(r'^/0$', 'access.log') is None
    assert search_in_file(r'^/false$', 'access.log') is None
    assert search_in_file(r'^/undefined$', 'access.log') is None
    assert search_in_file(r'^/!$', 'access.log') is not None
    assert search_in_file(r'^/!null$', 'access.log') is not None
    assert search_in_file(r'^/1$', 'access.log') is not None

    assert search_in_file(r'^/bar$', 'access.log') is None
    assert search_in_file(r'^/foo_empty$', 'access.log') is None


def test_access_log_if_njs(require, search_in_file, wait_for_record):
    require({'modules': {'njs': 'any'}})

    load('empty')
    set_format('$uri')

    set_if('`${args.foo == \'1\'}`')

    assert client.get(url='/foo_2?foo=2')['status'] == 200
    assert client.get(url='/foo_1?foo=1')['status'] == 200

    assert wait_for_record(r'^/foo_1$', 'access.log') is not None
    assert search_in_file(r'^/foo_2$', 'access.log') is None


def test_access_log_incorrect(temp_dir, skip_alert):
    skip_alert(r'failed to apply new conf')

    assert 'error' in client.conf(
        f'{temp_dir}/blah/access.log',
        'access_log/path',
    ), 'access_log path incorrect'

    assert 'error' in client.conf(
        {
            'path': f'{temp_dir}/access.log',
            'format': '$remote_add',
        },
        'access_log',
    ), 'access_log format incorrect'

    assert 'error' in client.conf('$arg_', 'access_log/if')
