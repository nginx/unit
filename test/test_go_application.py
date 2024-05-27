import re

from unit.applications.lang.go import ApplicationGo

prerequisites = {'modules': {'go': 'all'}}

client = ApplicationGo()


def test_go_application_variables(date_to_sec_epoch, sec_epoch):
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

    assert headers == {
        'Content-Length': str(len(body)),
        'Content-Type': 'text/html',
        'Request-Method': 'POST',
        'Request-Uri': '/',
        'Http-Host': 'localhost',
        'Server-Protocol': 'HTTP/1.1',
        'Server-Protocol-Major': '1',
        'Server-Protocol-Minor': '1',
        'Custom-Header': 'blah',
        'Connection': 'close',
    }, 'headers'
    assert resp['body'] == body, 'body'


def test_go_application_get_variables():
    client.load('get_variables')

    resp = client.get(url='/?var1=val1&var2=&var3')
    assert resp['headers']['X-Var-1'] == 'val1', 'GET variables'
    assert resp['headers']['X-Var-2'] == '', 'GET variables 2'
    assert resp['headers']['X-Var-3'] == '', 'GET variables 3'


def test_go_application_post_variables():
    client.load('post_variables')

    resp = client.post(
        headers={
            'Host': 'localhost',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'close',
        },
        body='var1=val1&var2=&var3',
    )

    assert resp['headers']['X-Var-1'] == 'val1', 'POST variables'
    assert resp['headers']['X-Var-2'] == '', 'POST variables 2'
    assert resp['headers']['X-Var-3'] == '', 'POST variables 3'


def test_go_application_404():
    client.load('404')

    resp = client.get()

    assert resp['status'] == 404, '404 status'
    assert re.search(r'<title>404 Not Found</title>', resp['body']), '404 body'


def test_go_keepalive_body():
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


def test_go_application_cookies():
    client.load('cookies')

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': 'var1=val1; var2=val2',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Cookie-1'] == 'val1', 'cookie 1'
    assert resp['headers']['X-Cookie-2'] == 'val2', 'cookie 2'


def test_go_application_command_line_arguments_type():
    client.load('command_line_arguments')

    assert 'error' in client.conf(
        "a b c", 'applications/command_line_arguments/arguments'
    ), 'arguments type'


def test_go_application_command_line_arguments_0():
    client.load('command_line_arguments')

    assert client.get()['headers']['X-Arg-0'] == client.conf_get(
        'applications/command_line_arguments/executable'
    ), 'argument 0'


def test_go_application_command_line_arguments():
    client.load('command_line_arguments')

    arg1 = '--cc=gcc-7.2.0'
    arg2 = "--cc-opt='-O0 -DNXT_DEBUG_MEMORY=1 -fsanitize=address'"
    arg3 = '--debug'

    assert 'success' in client.conf(
        f'["{arg1}", "{arg2}", "{arg3}"]',
        'applications/command_line_arguments/arguments',
    )

    assert client.get()['body'] == f'{arg1},{arg2},{arg3}', 'arguments'


def test_go_application_command_line_arguments_change():
    client.load('command_line_arguments')

    args_path = 'applications/command_line_arguments/arguments'

    assert 'success' in client.conf('["0", "a", "$", ""]', args_path)

    assert client.get()['body'] == '0,a,$,', 'arguments'

    assert 'success' in client.conf('["-1", "b", "%"]', args_path)

    assert client.get()['body'] == '-1,b,%', 'arguments change'

    assert 'success' in client.conf('[]', args_path)

    assert client.get()['headers']['Content-Length'] == '0', 'arguments empty'
