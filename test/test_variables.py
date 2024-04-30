import re
import time
from pathlib import Path

import pytest

from unit.applications.lang.python import ApplicationPython
from unit.applications.proto import ApplicationProto
from unit.option import option

client = ApplicationProto()
client_python = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"return": 200}}],
        },
    ), 'configure routes'


def set_format(log_format):
    assert 'success' in client.conf(
        {
            'path': f'{option.temp_dir}/access.log',
            'format': log_format,
        },
        'access_log',
    ), 'access_log format'


def test_variables_dollar():
    assert 'success' in client.conf("301", 'routes/0/action/return')

    def check_dollar(location, expect):
        assert 'success' in client.conf(
            f'"{location}"',
            'routes/0/action/location',
        )
        assert client.get()['headers']['Location'] == expect

    check_dollar(
        'https://${host}${uri}path${dollar}dollar',
        'https://localhost/path$dollar',
    )
    check_dollar('path$dollar${dollar}', 'path$$')


def test_variables_request_time(wait_for_record):
    set_format('$uri $request_time')

    sock = client.http(b'', raw=True, no_recv=True)

    time.sleep(1)

    assert client.get(url='/r_time_1', sock=sock)['status'] == 200
    assert wait_for_record(r'\/r_time_1 0\.\d{3}', 'access.log') is not None

    sock = client.http(
        b"""G""",
        no_recv=True,
        raw=True,
    )

    time.sleep(2)

    client.http(
        b"""ET /r_time_2 HTTP/1.1
Host: localhost
Connection: close

""",
        sock=sock,
        raw=True,
    )
    assert wait_for_record(r'\/r_time_2 [1-9]\.\d{3}', 'access.log') is not None


def test_variables_method(search_in_file, wait_for_record):
    set_format('$method')

    reg = r'^GET$'
    assert search_in_file(reg, 'access.log') is None
    assert client.get()['status'] == 200
    assert wait_for_record(reg, 'access.log') is not None, 'method GET'

    reg = r'^POST$'
    assert search_in_file(reg, 'access.log') is None
    assert client.post()['status'] == 200
    assert wait_for_record(reg, 'access.log') is not None, 'method POST'


def test_variables_request_uri(
    findall, search_in_file, temp_dir, wait_for_record
):
    set_format('$request_uri')

    def check_request_uri(req_uri):
        reg = fr'^{re.escape(req_uri)}$'

        assert search_in_file(reg, 'access.log') is None
        assert client.get(url=req_uri)['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None

    check_request_uri('/3')
    check_request_uri('/4*')
    check_request_uri('/4%2A')
    check_request_uri('/9?q#a')

    # $request_uri + proxy

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes/a"},
                "[::1]:8081": {"pass": "routes/b"},
            },
            "routes": {
                "a": [
                    {
                        "action": {
                            "proxy": "http://[::1]:8081",
                        }
                    }
                ],
                "b": [
                    {
                        "action": {
                            "return": 200,
                        }
                    }
                ],
            },
            "access_log": {
                "path": f'{temp_dir}/access.log',
                "format": "$remote_addr $uri $request_uri",
            },
        }
    )

    assert search_in_file(r'::1', 'access.log') is None

    assert client.get(url='/blah%25blah?a=b')['status'] == 200

    assert (
        wait_for_record(fr'^::1 /blah%blah /blah%25blah\?a=b$', 'access.log')
        is not None
    ), 'req 8081 (proxy)'
    assert (
        search_in_file(
            fr'^127\.0\.0\.1 /blah%blah /blah%25blah\?a=b$', 'access.log'
        )
        is not None
    ), 'req 8080'

    # rewrite set $request_uri before proxy

    assert 'success' in client.conf(
        {
            "a": [
                {
                    "action": {
                        "rewrite": "/foo",
                        "proxy": "http://[::1]:8081",
                    }
                }
            ],
            "b": [
                {
                    "action": {
                        "rewrite": "/bar",
                        "return": 200,
                    }
                }
            ],
        },
        'routes',
    )

    assert len(findall(r'::1', 'access.log')) == 1

    assert client.get(url='/blah%2Fblah?a=b')['status'] == 200

    assert (
        wait_for_record(fr'^::1 /bar /foo\?a=b$', 'access.log') is not None
    ), 'req 8081 (proxy) rewrite'
    assert (
        search_in_file(fr'^127\.0\.0\.1 /foo /blah%2Fblah\?a=b$', 'access.log')
        is not None
    ), 'req 8080 rewrite'

    # percent-encoded rewrite

    assert len(findall(r'::1', 'access.log')) == 2

    assert 'success' in client.conf('"/foo%2Ffoo"', 'routes/a/0/action/rewrite')
    assert client.get(url='/blah%2Fblah?a=b')['status'] == 200

    assert (
        wait_for_record(
            fr'^127\.0\.0\.1 /foo/foo /blah%2Fblah\?a=b$', 'access.log'
        )
        is not None
    ), 'req 8080 percent'
    assert len(findall(fr'^::1 /bar /foo/foo\?a=b$', 'access.log')) == 1


def test_variables_uri(search_in_file, wait_for_record):
    set_format('$uri')

    def check_uri(uri, expect=None):
        expect = uri if expect is None else expect
        reg = fr'^{re.escape(expect)}$'

        assert search_in_file(reg, 'access.log') is None
        assert client.get(url=uri)['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None

    check_uri('/3')
    check_uri('/4*')
    check_uri('/5%2A', '/5*')
    check_uri('/9?q#a', '/9')


def test_variables_uri_no_cache(temp_dir):
    Path(f'{temp_dir}/foo/bar').mkdir(parents=True)
    Path(f'{temp_dir}/foo/bar/index.html').write_text('index', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "action": {
                        "rewrite": "/foo${uri}/",
                        "share": f'{temp_dir}$uri',
                    }
                }
            ],
        }
    )

    assert client.get(url='/bar')['status'] == 200


def test_variables_host(search_in_file, wait_for_record):
    set_format('$host')

    def check_host(host, expect=None):
        expect = host if expect is None else expect
        reg = fr'^{re.escape(expect)}$'

        assert search_in_file(reg, 'access.log') is None
        assert (
            client.get(headers={'Host': host, 'Connection': 'close'})['status']
            == 200
        )
        assert wait_for_record(reg, 'access.log') is not None

    check_host('localhost')
    check_host('localhost1.', 'localhost1')
    check_host('localhost2:8080', 'localhost2')
    check_host('.localhost')
    check_host('www.localhost')


def test_variables_remote_addr(search_in_file, wait_for_record):
    set_format('$remote_addr')

    assert client.get()['status'] == 200
    assert wait_for_record(r'^127\.0\.0\.1$', 'access.log') is not None

    assert 'success' in client.conf(
        {"[::1]:8080": {"pass": "routes"}}, 'listeners'
    )

    reg = r'^::1$'
    assert search_in_file(reg, 'access.log') is None
    assert client.get(sock_type='ipv6')['status'] == 200
    assert wait_for_record(reg, 'access.log') is not None


def test_variables_time_local(
    date_to_sec_epoch, search_in_file, wait_for_record
):
    set_format('$uri $time_local $uri')

    assert search_in_file(r'/time_local', 'access.log') is None
    assert client.get(url='/time_local')['status'] == 200
    assert wait_for_record(r'/time_local', 'access.log') is not None, 'time log'
    date = search_in_file(r'^\/time_local (.*) \/time_local$', 'access.log')[1]
    assert (
        abs(
            date_to_sec_epoch(date, '%d/%b/%Y:%X %z')
            - time.mktime(time.localtime())
        )
        < 5
    ), '$time_local'


def test_variables_request_line(search_in_file, wait_for_record):
    set_format('$request_line')

    reg = r'^GET \/r_line HTTP\/1\.1$'
    assert search_in_file(reg, 'access.log') is None
    assert client.get(url='/r_line')['status'] == 200
    assert wait_for_record(reg, 'access.log') is not None


def test_variables_request_id(search_in_file, wait_for_record, findall):
    set_format('$uri $request_id $request_id')

    assert search_in_file(r'/request_id', 'access.log') is None
    assert client.get(url='/request_id_1')['status'] == 200
    assert client.get(url='/request_id_2')['status'] == 200
    assert wait_for_record(r'/request_id_2', 'access.log') is not None

    id1 = findall(
        r'^\/request_id_1 ([0-9a-f]{32}) ([0-9a-f]{32})$', 'access.log'
    )[0]
    id2 = findall(
        r'^\/request_id_2 ([0-9a-f]{32}) ([0-9a-f]{32})$', 'access.log'
    )[0]

    assert id1[0] == id1[1], 'same ids first'
    assert id2[0] == id2[1], 'same ids second'
    assert id1[0] != id2[0], 'first id != second id'


def test_variables_status(search_in_file, wait_for_record):
    set_format('$status')

    assert 'success' in client.conf("418", 'routes/0/action/return')

    reg = r'^418$'
    assert search_in_file(reg, 'access.log') is None
    assert client.get()['status'] == 418
    assert wait_for_record(reg, 'access.log') is not None


def test_variables_header_referer(search_in_file, wait_for_record):
    set_format('$method $header_referer')

    def check_referer(referer):
        reg = fr'^GET {re.escape(referer)}$'

        assert search_in_file(reg, 'access.log') is None
        assert (
            client.get(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'Referer': referer,
                }
            )['status']
            == 200
        )
        assert wait_for_record(reg, 'access.log') is not None

    check_referer('referer-value')
    check_referer('')
    check_referer('no')


def test_variables_header_user_agent(search_in_file, wait_for_record):
    set_format('$method $header_user_agent')

    def check_user_agent(user_agent):
        reg = fr'^GET {re.escape(user_agent)}$'

        assert search_in_file(reg, 'access.log') is None
        assert (
            client.get(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'User-Agent': user_agent,
                }
            )['status']
            == 200
        )
        assert wait_for_record(reg, 'access.log') is not None

    check_user_agent('MSIE')
    check_user_agent('')
    check_user_agent('no')


def test_variables_many(search_in_file, wait_for_record):
    def check_vars(uri, expect):
        reg = fr'^{re.escape(expect)}$'

        assert search_in_file(reg, 'access.log') is None
        assert client.get(url=uri)['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None

    set_format('$uri$method')
    check_vars('/1', '/1GET')

    set_format('${uri}${method}')
    check_vars('/2', '/2GET')

    set_format('${uri}$method')
    check_vars('/3', '/3GET')

    set_format('$method$method')
    check_vars('/', 'GETGET')


def test_variables_dynamic(wait_for_record):
    set_format('$header_foo$cookie_foo$arg_foo')

    assert (
        client.get(
            url='/?foo=h',
            headers={'Foo': 'b', 'Cookie': 'foo=la', 'Connection': 'close'},
        )['status']
        == 200
    )
    assert wait_for_record(r'^blah$', 'access.log') is not None


def test_variables_dynamic_arguments(search_in_file, wait_for_record):
    def check_arg(url, expect=None):
        expect = url if expect is None else expect
        reg = fr'^{re.escape(expect)}$'

        assert search_in_file(reg, 'access.log') is None
        assert client.get(url=url)['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None

    def check_no_arg(url):
        assert client.get(url=url)['status'] == 200
        assert search_in_file(r'^0$', 'access.log') is None

    set_format('$arg_foo_bar')
    check_arg('/?foo_bar=1', '1')
    check_arg('/?foo_b%61r=2', '2')
    check_arg('/?bar&foo_bar=3&foo', '3')
    check_arg('/?foo_bar=l&foo_bar=4', '4')
    check_no_arg('/')
    check_no_arg('/?foo_bar=')
    check_no_arg('/?Foo_bar=0')
    check_no_arg('/?foo-bar=0')
    check_no_arg('/?foo_bar=0&foo_bar=l')

    set_format('$arg_foo_b%61r')
    check_no_arg('/?foo_b=0')
    check_no_arg('/?foo_bar=0')

    set_format('$arg_f!~')
    check_no_arg('/?f=0')
    check_no_arg('/?f!~=0')


def test_variables_dynamic_headers(search_in_file, wait_for_record):
    def check_header(header, value):
        reg = fr'^{value}$'

        assert search_in_file(reg, 'access.log') is None
        assert (
            client.get(headers={header: value, 'Connection': 'close'})['status']
            == 200
        )
        assert wait_for_record(reg, 'access.log') is not None

    def check_no_header(header):
        assert (
            client.get(headers={header: '0', 'Connection': 'close'})['status']
            == 200
        )
        assert search_in_file(r'^0$', 'access.log') is None

    set_format('$header_foo_bar')
    check_header('foo-bar', '1')
    check_header('Foo-Bar', '2')
    check_no_header('foo_bar')
    check_no_header('foobar')

    set_format('$header_Foo_Bar')
    check_header('Foo-Bar', '4')
    check_header('foo-bar', '5')
    check_no_header('foo_bar')
    check_no_header('foobar')


def test_variables_dynamic_cookies(search_in_file, wait_for_record):
    def check_no_cookie(cookie):
        assert (
            client.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': cookie,
                    'Connection': 'close',
                },
            )['status']
            == 200
        )
        assert search_in_file(r'^0$', 'access.log') is None

    set_format('$cookie_foo_bar')

    reg = r'^1$'
    assert search_in_file(reg, 'access.log') is None
    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Cookie': 'foo_bar=1',
                'Connection': 'close',
            },
        )['status']
        == 200
    )
    assert wait_for_record(reg, 'access.log') is not None

    check_no_cookie('fOo_bar=0')
    check_no_cookie('foo_bar=')


def test_variables_response_header(temp_dir, wait_for_record):
    # If response has two headers with the same name then first value
    # will be stored in variable.
    # $response_header_transfer_encoding value can be 'chunked' or null only.

    # return

    set_format(
        'return@$response_header_server@$response_header_date@'
        '$response_header_content_length@$response_header_connection'
    )

    assert client.get()['status'] == 200
    assert (
        wait_for_record(r'return@Unit/.*@.*GMT@0@close', 'access.log')
        is not None
    )

    # share

    Path(f'{temp_dir}/foo').mkdir()
    Path(f'{temp_dir}/foo/index.html').write_text('index', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "action": {
                        "share": f'{temp_dir}$uri',
                    }
                }
            ],
        }
    )

    set_format(
        'share@$response_header_last_modified@$response_header_etag@'
        '$response_header_content_type@$response_header_server@'
        '$response_header_date@$response_header_content_length@'
        '$response_header_connection'
    )

    assert client.get(url='/foo/index.html')['status'] == 200
    assert (
        wait_for_record(
            r'share@.*GMT@".*"@text/html@Unit/.*@.*GMT@5@close', 'access.log'
        )
        is not None
    )

    # redirect

    set_format(
        'redirect@$response_header_location@$response_header_server@'
        '$response_header_date@$response_header_content_length@'
        '$response_header_connection'
    )

    assert client.get(url='/foo')['status'] == 301
    assert (
        wait_for_record(r'redirect@/foo/@Unit/.*@.*GMT@0@close', 'access.log')
        is not None
    )

    # error

    set_format(
        'error@$response_header_content_type@$response_header_server@'
        '$response_header_date@$response_header_content_length@'
        '$response_header_connection'
    )

    assert client.get(url='/blah')['status'] == 404
    assert (
        wait_for_record(r'error@text/html@Unit/.*@.*GMT@54@close', 'access.log')
        is not None
    )


def test_variables_response_header_application(require, wait_for_record):
    require({'modules': {'python': 'any'}})

    client_python.load('chunked')

    set_format('$uri@$response_header_transfer_encoding')

    assert client_python.get(url='/1')['status'] == 200
    assert wait_for_record(r'/1@chunked', 'access.log') is not None


def test_variables_invalid(temp_dir):
    def check_variables(log_format):
        assert 'error' in client.conf(
            {
                'path': f'{temp_dir}/access.log',
                'format': log_format,
            },
            'access_log',
        ), 'access_log format'

    check_variables("$")
    check_variables("${")
    check_variables("${}")
    check_variables("$ur")
    check_variables("$uri$$host")
    check_variables("$uriblah")
    check_variables("${uri")
    check_variables("${{uri}")
    check_variables("$ar")
    check_variables("$arg")
    check_variables("$arg_")
    check_variables("$cookie")
    check_variables("$cookie_")
    check_variables("$header")
    check_variables("$header_")
