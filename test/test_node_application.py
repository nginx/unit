import re

import pytest

from unit.applications.lang.node import ApplicationNode
from unit.utils import waitforfiles

prerequisites = {'modules': {'node': 'all'}}

client = ApplicationNode()


def assert_basic_application():
    resp = client.get()
    assert resp['headers']['Content-Type'] == 'text/plain', 'basic header'
    assert resp['body'] == 'Hello World\n', 'basic body'


def test_node_application_basic():
    client.load('basic')

    assert_basic_application()

def test_node_application_options(wait_for_record):
    client.load('options')

    assert_basic_application()
    assert wait_for_record(r'constructor was called with unsupported') is not None


def test_node_application_loader_unit_http():
    client.load('loader/unit_http')

    assert_basic_application()


def test_node_application_loader_transitive_dependency():
    client.load('loader/transitive_dependency')

    assert_basic_application()


def test_node_application_seq():
    client.load('basic')

    assert client.get()['status'] == 200, 'seq'
    assert client.get()['status'] == 200, 'seq 2'


def test_node_application_variables(date_to_sec_epoch, sec_epoch):
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

    date = headers.pop('Date')
    assert date[-4:] == ' GMT', 'date header timezone'
    assert abs(date_to_sec_epoch(date) - sec_epoch) < 5, 'date header'

    raw_headers = headers.pop('Request-Raw-Headers')
    assert re.search(
        r'^(?:Host|localhost|Content-Type|'
        r'text\/html|Custom-Header|blah|Content-Length|17|Connection|'
        r'close|,)+$',
        raw_headers,
    ), 'raw headers'

    assert headers == {
        'Connection': 'close',
        'Content-Length': str(len(body)),
        'Content-Type': 'text/html',
        'Request-Method': 'POST',
        'Request-Uri': '/',
        'Http-Host': 'localhost',
        'Server-Protocol': '1.1',
        'Custom-Header': 'blah',
    }, 'headers'
    assert resp['body'] == body, 'body'


def test_node_application_get_variables():
    client.load('get_variables')

    resp = client.get(url='/?var1=val1&var2=&var3')
    assert resp['headers']['X-Var-1'] == 'val1', 'GET variables'
    assert resp['headers']['X-Var-2'] == '', 'GET variables 2'
    assert resp['headers']['X-Var-3'] == '', 'GET variables 3'


def test_node_application_post_variables():
    client.load('post_variables')

    resp = client.post(
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'localhost',
            'Connection': 'close',
        },
        body='var1=val1&var2=&var3',
    )

    assert resp['headers']['X-Var-1'] == 'val1', 'POST variables'
    assert resp['headers']['X-Var-2'] == '', 'POST variables 2'
    assert resp['headers']['X-Var-3'] == '', 'POST variables 3'


def test_node_application_404():
    client.load('404')

    resp = client.get()

    assert resp['status'] == 404, '404 status'
    assert re.search(r'<title>404 Not Found</title>', resp['body']), '404 body'


def test_node_keepalive_body():
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

    assert resp['body'] == '0123456789' * 500, 'keep-alive 1'

    body = '0123456789'
    resp = client.post(sock=sock, body=body)

    assert resp['body'] == body, 'keep-alive 2'


def test_node_application_write_buffer():
    client.load('write_buffer')

    assert client.get()['body'] == 'buffer', 'write buffer'


def test_node_application_write_array():
    client.load('write_array')

    assert client.get()['body'] == 'array', 'write array'


def test_node_application_write_callback(temp_dir):
    client.load('write_callback')

    assert client.get()['body'] == 'helloworld', 'write callback order'
    assert waitforfiles(f'{temp_dir}/node/callback'), 'write callback'


def test_node_application_write_before_write_head():
    client.load('write_before_write_head')

    assert client.get()['status'] == 200, 'write before writeHead'


def test_node_application_double_end():
    client.load('double_end')

    assert client.get()['status'] == 200, 'double end'
    assert client.get()['status'] == 200, 'double end 2'


def test_node_application_write_return():
    client.load('write_return')

    assert client.get()['body'] == 'bodytrue', 'write return'


def test_node_application_remove_header():
    client.load('remove_header')

    resp = client.get(
        headers={
            'Host': 'localhost',
            'X-Remove': 'X-Header',
            'Connection': 'close',
        }
    )
    assert resp['headers']['Was-Header'] == 'true', 'was header'
    assert resp['headers']['Has-Header'] == 'false', 'has header'
    assert not ('X-Header' in resp['headers']), 'remove header'


def test_node_application_remove_header_nonexisting():
    client.load('remove_header')

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'X-Remove': 'blah',
                'Connection': 'close',
            }
        )['headers']['Has-Header']
        == 'true'
    ), 'remove header nonexisting'


def test_node_application_update_header():
    client.load('update_header')

    assert client.get()['headers']['X-Header'] == 'new', 'update header'


def test_node_application_set_header_array():
    client.load('set_header_array')

    assert client.get()['headers']['Set-Cookie'] == [
        'tc=one,two,three',
        'tc=four,five,six',
    ], 'set header array'


@pytest.mark.skip('not yet')
def test_node_application_status_message():
    client.load('status_message')

    assert re.search(r'200 blah', client.get(raw_resp=True)), 'status message'


def test_node_application_get_header_type():
    client.load('get_header_type')

    assert client.get()['headers']['X-Type'] == 'number', 'get header type'


def test_node_application_header_name_case():
    client.load('header_name_case')

    headers = client.get()['headers']

    assert headers['X-HEADER'] == '3', 'header value'
    assert 'X-Header' not in headers, 'insensitive'
    assert 'X-header' not in headers, 'insensitive 2'


def test_node_application_promise_handler_write_after_end():
    client.load('promise_handler')

    assert (
        client.post(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'X-Write-Call': '1',
                'Connection': 'close',
            },
            body='callback',
        )['status']
        == 200
    ), 'promise handler request write after end'


def test_node_application_promise_end(temp_dir):
    client.load('promise_end')

    assert (
        client.post(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Connection': 'close',
            },
            body='end',
        )['status']
        == 200
    ), 'promise end request'
    assert waitforfiles(f'{temp_dir}/node/callback'), 'promise end'


@pytest.mark.skip('not yet')
def test_node_application_header_name_valid():
    client.load('header_name_valid')

    assert 'status' not in client.get(), 'header name valid'


def test_node_application_header_value_object():
    client.load('header_value_object')

    assert 'X-Header' in client.get()['headers'], 'header value object'


def test_node_application_get_header_names():
    client.load('get_header_names')

    assert client.get()['headers']['X-Names'] == [
        'date',
        'x-header',
    ], 'get header names'


def test_node_application_flush_headers():
    client.load('flush_headers')

    assert client.get()['headers']['X-Header'] == 'blah'


def test_node_application_has_header():
    client.load('has_header')

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'X-Header': 'length',
                'Connection': 'close',
            }
        )['headers']['X-Has-Header']
        == 'false'
    ), 'has header length'

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'X-Header': 'Date',
                'Connection': 'close',
            }
        )['headers']['X-Has-Header']
        == 'false'
    ), 'has header date'


def test_node_application_write_multiple():
    client.load('write_multiple')

    assert client.get()['body'] == 'writewrite2end', 'write multiple'
