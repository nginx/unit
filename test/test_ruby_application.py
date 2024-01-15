import re
import subprocess

import pytest

from unit.applications.lang.ruby import ApplicationRuby

prerequisites = {'modules': {'ruby': 'all'}}

client = ApplicationRuby()


def test_ruby_application(date_to_sec_epoch, sec_epoch):
    client.load('variables')

    body = 'Test body string.'

    resp = client.post(
        headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Custom-Header': 'blah',
            'Connection': 'close',
        },
        body=body,
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
        'Script-Name': '',
        'Server-Protocol': 'HTTP/1.1',
        'Custom-Header': 'blah',
        'Rack-Version': '13',
        'Rack-Url-Scheme': 'http',
        'Rack-Multithread': 'false',
        'Rack-Multiprocess': 'true',
        'Rack-Run-Once': 'false',
        'Rack-Hijack-Q': 'false',
        'Rack-Hijack': '',
        'Rack-Hijack-IO': '',
    }, 'headers'
    assert resp['body'] == body, 'body'


def test_ruby_application_query_string():
    client.load('query_string')

    resp = client.get(url='/?var1=val1&var2=val2')

    assert (
        resp['headers']['Query-String'] == 'var1=val1&var2=val2'
    ), 'Query-String header'


def test_ruby_application_query_string_empty():
    client.load('query_string')

    resp = client.get(url='/?')

    assert resp['status'] == 200, 'query string empty status'
    assert resp['headers']['Query-String'] == '', 'query string empty'


def test_ruby_application_query_string_absent():
    client.load('query_string')

    resp = client.get()

    assert resp['status'] == 200, 'query string absent status'
    assert resp['headers']['Query-String'] == '', 'query string absent'


@pytest.mark.skip('not yet')
def test_ruby_application_server_port():
    client.load('server_port')

    assert (
        client.get()['headers']['Server-Port'] == '8080'
    ), 'Server-Port header'


def test_ruby_application_status_int():
    client.load('status_int')

    assert client.get()['status'] == 200, 'status int'


def test_ruby_application_input_read_empty():
    client.load('input_read_empty')

    assert client.get()['body'] == '', 'read empty'


def test_ruby_application_input_read_parts():
    client.load('input_read_parts')

    assert (
        client.post(body='0123456789')['body'] == '012345678'
    ), 'input read parts'


def test_ruby_application_input_read_buffer():
    client.load('input_read_buffer')

    assert (
        client.post(body='0123456789')['body'] == '0123456789'
    ), 'input read buffer'


def test_ruby_application_input_read_buffer_not_empty():
    client.load('input_read_buffer_not_empty')

    assert (
        client.post(body='0123456789')['body'] == '0123456789'
    ), 'input read buffer not empty'


def test_ruby_application_input_gets():
    client.load('input_gets')

    body = '0123456789'

    assert client.post(body=body)['body'] == body, 'input gets'


def test_ruby_application_input_gets_2():
    client.load('input_gets')

    assert (
        client.post(body='01234\n56789\n')['body'] == '01234\n'
    ), 'input gets 2'


def test_ruby_application_input_gets_all():
    client.load('input_gets_all')

    body = '\n01234\n56789\n\n'

    assert client.post(body=body)['body'] == body, 'input gets all'


def test_ruby_application_input_each():
    client.load('input_each')

    body = '\n01234\n56789\n\n'

    assert client.post(body=body)['body'] == body, 'input each'


@pytest.mark.skip('not yet')
def test_ruby_application_syntax_error(skip_alert):
    skip_alert(
        r'Failed to parse rack script',
        r'syntax error',
        r'new_from_string',
        r'parse_file',
    )
    client.load('syntax_error')

    assert client.get()['status'] == 500, 'syntax error'


def test_ruby_application_errors_puts(wait_for_record):
    client.load('errors_puts')

    assert client.get()['status'] == 200

    assert (
        wait_for_record(r'\[error\].+Error in application') is not None
    ), 'errors puts'


def test_ruby_application_errors_puts_int(wait_for_record):
    client.load('errors_puts_int')

    assert client.get()['status'] == 200

    assert (
        wait_for_record(r'\[error\].+1234567890') is not None
    ), 'errors puts int'


def test_ruby_application_errors_write(wait_for_record):
    client.load('errors_write')

    assert client.get()['status'] == 200
    assert (
        wait_for_record(r'\[error\].+Error in application') is not None
    ), 'errors write'


def test_ruby_application_errors_write_to_s_custom():
    client.load('errors_write_to_s_custom')

    assert client.get()['status'] == 200, 'errors write to_s custom'


def test_ruby_application_errors_write_int(wait_for_record):
    client.load('errors_write_int')

    assert client.get()['status'] == 200
    assert (
        wait_for_record(r'\[error\].+1234567890') is not None
    ), 'errors write int'


def test_ruby_application_at_exit(wait_for_record):
    client.load('at_exit')

    assert client.get()['status'] == 200

    assert 'success' in client.conf({"listeners": {}, "applications": {}})

    assert (
        wait_for_record(r'\[error\].+At exit called\.') is not None
    ), 'at exit'


def test_ruby_application_encoding():
    client.load('encoding')

    try:
        locales = (
            subprocess.check_output(
                ['locale', '-a'],
                stderr=subprocess.STDOUT,
            )
            .decode()
            .split('\n')
        )

    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip('require locale')

    def get_locale(pattern):
        return next(
            (l for l in locales if re.match(pattern, l.upper()) is not None),
            None,
        )

    utf8 = get_locale(r'.*UTF[-_]?8')
    iso88591 = get_locale(r'.*ISO[-_]?8859[-_]?1')

    def check_locale(enc):
        assert 'success' in client.conf(
            {"LC_CTYPE": enc, "LC_ALL": ""},
            '/config/applications/encoding/environment',
        )

        resp = client.get()
        assert resp['status'] == 200, 'status'

        enc_default = re.sub(r'[-_]', '', resp['headers']['X-Enc']).upper()
        assert enc_default == re.sub(r'[-_]', '', enc.split('.')[-1]).upper()

    if utf8:
        check_locale(utf8)

    if iso88591:
        check_locale(iso88591)

    if not utf8 and not iso88591:
        pytest.skip('no available locales')


def test_ruby_application_header_custom():
    client.load('header_custom')

    resp = client.post(body="\ntc=one,two\ntc=three,four,\n\n")

    assert resp['headers']['Custom-Header'] == [
        '',
        'tc=one,two',
        'tc=three,four,',
        '',
        '',
    ], 'header custom'


@pytest.mark.skip('not yet')
def test_ruby_application_header_custom_non_printable():
    client.load('header_custom')

    assert (
        client.post(body='\b')['status'] == 500
    ), 'header custom non printable'


def test_ruby_application_header_status():
    client.load('header_status')

    assert client.get()['status'] == 200, 'header status'


def test_ruby_application_header_array():
    client.load('header_array')

    assert client.get()['headers']['x-array'] == 'name=value; ; value; av'


def test_ruby_application_header_array_nil():
    client.load('header_array_nil')

    assert client.get()['status'] == 503


def test_ruby_application_header_array_empty():
    client.load('header_array_empty')

    headers = client.get()['headers']
    assert 'x-array' in headers
    assert headers['x-array'] == ''


@pytest.mark.skip('not yet')
def test_ruby_application_header_rack():
    client.load('header_rack')

    assert client.get()['status'] == 500, 'header rack'


@pytest.mark.skip('not yet')
def test_ruby_application_session():
    client.load('session')

    assert client.get()['status'] == 200


@pytest.mark.skip('not yet')
def test_ruby_application_multipart():
    client.load('multipart')

    assert client.get()['status'] == 200


def test_ruby_application_body_empty():
    client.load('body_empty')

    assert client.get()['body'] == '', 'body empty'


def test_ruby_application_body_array():
    client.load('body_array')

    assert client.get()['body'] == '0123456789', 'body array'


def test_ruby_application_body_large():
    client.load('mirror')

    body = '0123456789' * 1000

    assert client.post(body=body)['body'] == body, 'body large'


@pytest.mark.skip('not yet')
def test_ruby_application_body_each_error(wait_for_record):
    client.load('body_each_error')

    assert client.get()['status'] == 500, 'body each error status'

    assert (
        wait_for_record(r'\[error\].+Failed to run ruby script') is not None
    ), 'body each error'


def test_ruby_application_body_file():
    client.load('body_file')

    assert client.get()['body'] == 'body\n', 'body file'


def test_ruby_keepalive_body():
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


def test_ruby_application_constants():
    client.load('constants')

    resp = client.get()

    assert resp['status'] == 200, 'status'

    headers = resp['headers']
    assert len(headers['X-Copyright']) > 0, 'RUBY_COPYRIGHT'
    assert len(headers['X-Description']) > 0, 'RUBY_DESCRIPTION'
    assert len(headers['X-Engine']) > 0, 'RUBY_ENGINE'
    assert len(headers['X-Engine-Version']) > 0, 'RUBY_ENGINE_VERSION'
    assert len(headers['X-Patchlevel']) > 0, 'RUBY_PATCHLEVEL'
    assert len(headers['X-Platform']) > 0, 'RUBY_PLATFORM'
    assert len(headers['X-Release-Date']) > 0, 'RUBY_RELEASE_DATE'
    assert len(headers['X-Revision']) > 0, 'RUBY_REVISION'
    assert len(headers['X-Version']) > 0, 'RUBY_VERSION'


def test_ruby_application_threads():
    client.load('threads')

    assert 'success' in client.conf(
        '4', 'applications/threads/threads'
    ), 'configure 4 threads'

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

        assert resp['headers']['Rack-Multithread'] == 'true', 'multithread'

        sock.close()

    assert len(socks) == len(threads), 'threads differs'
