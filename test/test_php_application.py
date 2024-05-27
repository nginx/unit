import getpass
import os
import re
import shutil
import signal
import time
from pathlib import Path

import pytest

from unit.applications.lang.php import ApplicationPHP
from unit.option import option

prerequisites = {'modules': {'php': 'all'}}

client = ApplicationPHP()


def before_disable_functions():
    body = client.get()['body']

    assert re.search(r'time: \d+', body), 'disable_functions before time'
    assert re.search(r'exec: \/\w+', body), 'disable_functions before exec'


def check_opcache():
    resp = client.get()
    assert resp['status'] == 200, 'status'

    headers = resp['headers']
    if 'X-OPcache' in headers and headers['X-OPcache'] == '-1':
        pytest.skip('opcache is not supported')

    return resp


def run_php_application_cwd_root_tests():
    assert 'success' in client.conf_delete('applications/cwd/working_directory')

    script_cwd = f'{option.test_dir}/php/cwd'

    resp = client.get()
    assert resp['status'] == 200, 'status ok'
    assert resp['body'] == script_cwd, 'default cwd'

    assert 'success' in client.conf(
        f'"{option.test_dir}"',
        'applications/cwd/working_directory',
    )

    resp = client.get()
    assert resp['status'] == 200, 'status ok'
    assert resp['body'] == script_cwd, 'wdir cwd'

    resp = client.get(url='/?chdir=/')
    assert resp['status'] == 200, 'status ok'
    assert resp['body'] == '/', 'cwd after chdir'

    # cwd must be restored

    resp = client.get()
    assert resp['status'] == 200, 'status ok'
    assert resp['body'] == script_cwd, 'cwd restored'

    resp = client.get(url='/subdir/')
    assert resp['body'] == f'{script_cwd}/subdir', 'cwd subdir'


def run_php_application_cwd_script_tests():
    client.load('cwd')

    script_cwd = f'{option.test_dir}/php/cwd'

    assert 'success' in client.conf_delete('applications/cwd/working_directory')

    assert 'success' in client.conf('"index.php"', 'applications/cwd/script')

    assert client.get()['body'] == script_cwd, 'default cwd'

    assert client.get(url='/?chdir=/')['body'] == '/', 'cwd after chdir'

    # cwd must be restored
    assert client.get()['body'] == script_cwd, 'cwd restored'


def set_opcache(app, val):
    assert 'success' in client.conf(
        {"admin": {"opcache.enable": val, "opcache.enable_cli": val}},
        f'applications/{app}/options',
    )

    r = check_opcache()
    assert r['headers']['X-OPcache'] == val, 'opcache value'


def set_preload(preload):
    Path(f'{option.temp_dir}/php.ini').write_text(
        f"""opcache.preload = {option.test_dir}/php/opcache/preload\
/{preload}
opcache.preload_user = {option.user or getpass.getuser()}
""",
        encoding='utf-8',
    )

    assert 'success' in client.conf(
        {"file": f"{option.temp_dir}/php.ini"},
        'applications/opcache/options',
    )


def test_php_application_variables(date_to_sec_epoch, sec_epoch):
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
        url='/index.php/blah?var=val',
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

    if 'X-Powered-By' in headers:
        headers.pop('X-Powered-By')

    headers.pop('Content-type')
    assert headers == {
        'Connection': 'close',
        'Content-Length': str(len(body)),
        'Request-Method': 'POST',
        'Path-Info': '/blah',
        'Request-Uri': '/index.php/blah?var=val',
        'Http-Host': 'localhost',
        'Server-Protocol': 'HTTP/1.1',
        'Custom-Header': 'blah',
    }, 'headers'
    assert resp['body'] == body, 'body'


def test_php_application_query_string():
    client.load('query_string')

    resp = client.get(url='/?var1=val1&var2=val2')

    assert (
        resp['headers']['Query-String'] == 'var1=val1&var2=val2'
    ), 'query string'


def test_php_application_query_string_empty():
    client.load('query_string')

    resp = client.get(url='/?')

    assert resp['status'] == 200, 'query string empty status'
    assert resp['headers']['Query-String'] == '', 'query string empty'


def test_php_application_query_string_rewrite():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "action": {
                        "rewrite": "/new",
                        "pass": "applications/query_string",
                    },
                },
            ],
            "applications": {
                "query_string": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "root": f"{option.test_dir}/php/query_string",
                    "script": "index.php",
                }
            },
        },
    )

    assert client.get(url='/old')['status'] == 200

    resp = client.get(url='/old?arg=val')
    assert resp['status'] == 200
    assert resp['headers']['Query-String'] == 'arg=val'


def test_php_application_fastcgi_finish_request(findall, unit_pid):
    client.load('fastcgi_finish_request')

    assert 'success' in client.conf(
        {"admin": {"auto_globals_jit": "1"}},
        'applications/fastcgi_finish_request/options',
    )

    assert client.get()['body'] == '0123'

    os.kill(unit_pid, signal.SIGUSR1)

    errs = findall(r'Error in fastcgi_finish_request')

    assert len(errs) == 0, 'no error'


def test_php_application_fastcgi_finish_request_2(findall, unit_pid):
    client.load('fastcgi_finish_request')

    assert 'success' in client.conf(
        {"admin": {"auto_globals_jit": "1"}},
        'applications/fastcgi_finish_request/options',
    )

    resp = client.get(url='/?skip')
    assert resp['status'] == 200
    assert resp['body'] == ''

    os.kill(unit_pid, signal.SIGUSR1)

    errs = findall(r'Error in fastcgi_finish_request')

    assert len(errs) == 0, 'no error'


def test_php_application_query_string_absent():
    client.load('query_string')

    resp = client.get()

    assert resp['status'] == 200, 'query string absent status'
    assert resp['headers']['Query-String'] == '', 'query string absent'


def test_php_application_phpinfo():
    client.load('phpinfo')

    resp = client.get()

    assert resp['status'] == 200, 'status'
    assert resp['body'] != '', 'body not empty'


def test_php_application_header_status():
    client.load('header')

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'X-Header': 'HTTP/1.1 404 Not Found',
            }
        )['status']
        == 404
    ), 'status'

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'X-Header': 'http/1.1 404 Not Found',
            }
        )['status']
        == 404
    ), 'status case insensitive'

    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'X-Header': 'HTTP/ 404 Not Found',
            }
        )['status']
        == 404
    ), 'status version empty'


def test_php_application_404():
    client.load('404')

    resp = client.get()

    assert resp['status'] == 404, '404 status'
    assert re.search(r'<title>404 Not Found</title>', resp['body']), '404 body'


def test_php_application_keepalive_body():
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


def test_php_application_conditional():
    client.load('conditional')

    assert re.search(r'True', client.get()['body']), 'conditional true'
    assert re.search(r'False', client.post()['body']), 'conditional false'


def test_php_application_get_variables():
    client.load('get_variables')

    resp = client.get(url='/?var1=val1&var2=&var3')
    assert resp['headers']['X-Var-1'] == 'val1', 'GET variables'
    assert resp['headers']['X-Var-2'] == '', 'GET variables 2'
    assert resp['headers']['X-Var-3'] == '', 'GET variables 3'
    assert resp['headers']['X-Var-4'] == 'not set', 'GET variables 4'


def test_php_application_post_variables():
    client.load('post_variables')

    resp = client.post(
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'localhost',
            'Connection': 'close',
        },
        body='var1=val1&var2=',
    )
    assert resp['headers']['X-Var-1'] == 'val1', 'POST variables'
    assert resp['headers']['X-Var-2'] == '', 'POST variables 2'
    assert resp['headers']['X-Var-3'] == 'not set', 'POST variables 3'


def test_php_application_cookies():
    client.load('cookies')

    resp = client.get(
        headers={
            'Cookie': 'var=val; var2=val2',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Cookie-1'] == 'val', 'cookie'
    assert resp['headers']['X-Cookie-2'] == 'val2', 'cookie'


def test_php_application_ini_precision():
    client.load('ini_precision')

    assert client.get()['headers']['X-Precision'] != '4', 'ini value default'

    assert 'success' in client.conf(
        {"file": "ini/php.ini"}, 'applications/ini_precision/options'
    )

    assert (
        client.get()['headers']['X-File']
        == f'{option.test_dir}/php/ini_precision/ini/php.ini'
    ), 'ini file'
    assert client.get()['headers']['X-Precision'] == '4', 'ini value'


@pytest.mark.skip('not yet')
def test_php_application_ini_admin_user():
    client.load('ini_precision')

    assert 'error' in client.conf(
        {"user": {"precision": "4"}, "admin": {"precision": "5"}},
        'applications/ini_precision/options',
    ), 'ini admin user'


def test_php_application_ini_admin():
    client.load('ini_precision')

    assert 'success' in client.conf(
        {"file": "ini/php.ini", "admin": {"precision": "5"}},
        'applications/ini_precision/options',
    )

    assert (
        client.get()['headers']['X-File']
        == f'{option.test_dir}/php/ini_precision/ini/php.ini'
    ), 'ini file'
    assert client.get()['headers']['X-Precision'] == '5', 'ini value admin'


def test_php_application_ini_user():
    client.load('ini_precision')

    assert 'success' in client.conf(
        {"file": "ini/php.ini", "user": {"precision": "5"}},
        'applications/ini_precision/options',
    )

    assert (
        client.get()['headers']['X-File']
        == f'{option.test_dir}/php/ini_precision/ini/php.ini'
    ), 'ini file'
    assert client.get()['headers']['X-Precision'] == '5', 'ini value user'


def test_php_application_ini_user_2():
    client.load('ini_precision')

    assert 'success' in client.conf(
        {"file": "ini/php.ini"}, 'applications/ini_precision/options'
    )

    assert client.get()['headers']['X-Precision'] == '4', 'ini user file'

    assert 'success' in client.conf(
        {"precision": "5"}, 'applications/ini_precision/options/user'
    )

    assert client.get()['headers']['X-Precision'] == '5', 'ini value user'


def test_php_application_ini_set_admin():
    client.load('ini_precision')

    assert 'success' in client.conf(
        {"admin": {"precision": "5"}}, 'applications/ini_precision/options'
    )

    assert (
        client.get(url='/?precision=6')['headers']['X-Precision'] == '5'
    ), 'ini set admin'


def test_php_application_ini_set_user():
    client.load('ini_precision')

    assert 'success' in client.conf(
        {"user": {"precision": "5"}}, 'applications/ini_precision/options'
    )

    assert (
        client.get(url='/?precision=6')['headers']['X-Precision'] == '6'
    ), 'ini set user'


def test_php_application_ini_repeat():
    client.load('ini_precision')

    assert 'success' in client.conf(
        {"user": {"precision": "5"}}, 'applications/ini_precision/options'
    )

    assert client.get()['headers']['X-Precision'] == '5', 'ini value'

    assert client.get()['headers']['X-Precision'] == '5', 'ini value repeat'


def test_php_application_disable_functions_exec():
    client.load('time_exec')

    before_disable_functions()

    assert 'success' in client.conf(
        {"admin": {"disable_functions": "exec"}},
        'applications/time_exec/options',
    )

    body = client.get()['body']

    assert re.search(r'time: \d+', body), 'disable_functions time'
    assert not re.search(r'exec: \/\w+', body), 'disable_functions exec'


def test_php_application_disable_functions_comma():
    client.load('time_exec')

    before_disable_functions()

    assert 'success' in client.conf(
        {"admin": {"disable_functions": "exec,time"}},
        'applications/time_exec/options',
    )

    body = client.get()['body']

    assert not re.search(r'time: \d+', body), 'disable_functions comma time'
    assert not re.search(r'exec: \/\w+', body), 'disable_functions comma exec'


def test_php_application_auth():
    client.load('auth')

    resp = client.get()
    assert resp['status'] == 200, 'status'
    assert resp['headers']['X-Digest'] == 'not set', 'digest'
    assert resp['headers']['X-User'] == 'not set', 'user'
    assert resp['headers']['X-Password'] == 'not set', 'password'

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Authorization': 'Basic dXNlcjpwYXNzd29yZA==',
            'Connection': 'close',
        }
    )
    assert resp['status'] == 200, 'basic status'
    assert resp['headers']['X-Digest'] == 'not set', 'basic digest'
    assert resp['headers']['X-User'] == 'user', 'basic user'
    assert resp['headers']['X-Password'] == 'password', 'basic password'

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Authorization': 'Digest username="blah", realm="", uri="/"',
            'Connection': 'close',
        }
    )
    assert resp['status'] == 200, 'digest status'
    assert (
        resp['headers']['X-Digest'] == 'username="blah", realm="", uri="/"'
    ), 'digest digest'
    assert resp['headers']['X-User'] == 'not set', 'digest user'
    assert resp['headers']['X-Password'] == 'not set', 'digest password'


def test_php_application_auth_invalid():
    client.load('auth')

    def check_auth(auth):
        resp = client.get(
            headers={
                'Host': 'localhost',
                'Authorization': auth,
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'status'
        assert resp['headers']['X-Digest'] == 'not set', 'Digest'
        assert resp['headers']['X-User'] == 'not set', 'User'
        assert resp['headers']['X-Password'] == 'not set', 'Password'

    check_auth('Basic dXN%cjpwYXNzd29yZA==')
    check_auth('Basic XNlcjpwYXNzd29yZA==')
    check_auth('Basic DdXNlcjpwYXNzd29yZA==')
    check_auth('Basic blah')
    check_auth('Basic')
    check_auth('Digest')
    check_auth('blah')


def test_php_application_disable_functions_space():
    client.load('time_exec')

    before_disable_functions()

    assert 'success' in client.conf(
        {"admin": {"disable_functions": "exec time"}},
        'applications/time_exec/options',
    )

    body = client.get()['body']

    assert not re.search(r'time: \d+', body), 'disable_functions space time'
    assert not re.search(r'exec: \/\w+', body), 'disable_functions space exec'


def test_php_application_disable_functions_user():
    client.load('time_exec')

    before_disable_functions()

    assert 'success' in client.conf(
        {"user": {"disable_functions": "exec"}},
        'applications/time_exec/options',
    )

    body = client.get()['body']

    assert re.search(r'time: \d+', body), 'disable_functions user time'
    assert not re.search(r'exec: \/\w+', body), 'disable_functions user exec'


def test_php_application_disable_functions_nonexistent():
    client.load('time_exec')

    before_disable_functions()

    assert 'success' in client.conf(
        {"admin": {"disable_functions": "blah"}},
        'applications/time_exec/options',
    )

    body = client.get()['body']

    assert re.search(r'time: \d+', body), 'disable_functions nonexistent time'
    assert re.search(r'exec: \/\w+', body), 'disable_functions nonexistent exec'


def test_php_application_disable_classes():
    client.load('date_time')

    assert re.search(r'012345', client.get()['body']), 'disable_classes before'

    assert 'success' in client.conf(
        {"admin": {"disable_classes": "DateTime"}},
        'applications/date_time/options',
    )

    assert not re.search(
        r'012345', client.get()['body']
    ), 'disable_classes before'


def test_php_application_disable_classes_user():
    client.load('date_time')

    assert re.search(r'012345', client.get()['body']), 'disable_classes before'

    assert 'success' in client.conf(
        {"user": {"disable_classes": "DateTime"}},
        'applications/date_time/options',
    )

    assert not re.search(
        r'012345', client.get()['body']
    ), 'disable_classes before'


def test_php_application_error_log(findall, wait_for_record):
    client.load('error_log')

    assert client.get()['status'] == 200, 'status'

    time.sleep(1)

    assert client.get()['status'] == 200, 'status 2'

    pattern = r'\d{4}\/\d\d\/\d\d\s\d\d:.+\[notice\].+Error in application'

    assert wait_for_record(pattern) is not None, 'errors print'

    errs = findall(pattern)

    assert len(errs) == 2, 'error_log count'

    date = errs[0].split('[')[0]
    date2 = errs[1].split('[')[0]
    assert date != date2, 'date diff'


def test_php_application_script():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "applications/script"}},
            "applications": {
                "script": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "root": f"{option.test_dir}/php/script",
                    "script": "phpinfo.php",
                }
            },
        }
    ), 'configure script'

    resp = client.get()

    assert resp['status'] == 200, 'status'
    assert resp['body'] != '', 'body not empty'


def test_php_application_index_default():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "applications/phpinfo"}},
            "applications": {
                "phpinfo": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "root": f"{option.test_dir}/php/phpinfo",
                }
            },
        }
    ), 'configure index default'

    resp = client.get()

    assert resp['status'] == 200, 'status'
    assert resp['body'] != '', 'body not empty'


def test_php_application_trailing_slash(temp_dir):
    new_root = f'{temp_dir}/php-root'

    Path(f'{new_root}/path').mkdir(parents=True)
    Path(f'{new_root}/path/index.php').write_text(
        '<?php echo "OK\n"; ?>', encoding='utf-8'
    )

    addr = f'{temp_dir}/sock'

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "applications/php-path"},
                f'unix:{addr}': {"pass": "applications/php-path"},
            },
            "applications": {
                "php-path": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "root": new_root,
                }
            },
        }
    ), 'configure trailing slash'

    assert client.get(url='/path/')['status'] == 200, 'uri with trailing /'

    resp = client.get(url='/path?q=a')
    assert resp['status'] == 301, 'uri without trailing /'
    assert (
        resp['headers']['Location'] == 'http://localhost:8080/path/?q=a'
    ), 'Location with query string'

    resp = client.get(
        sock_type='unix',
        addr=addr,
        url='/path',
        headers={'Host': 'foo', 'Connection': 'close'},
    )
    assert resp['status'] == 301, 'uri without trailing /'
    assert (
        resp['headers']['Location'] == 'http://foo/path/'
    ), 'Location with custom Host over UDS'


def test_php_application_forbidden(temp_dir):
    Path(f'{temp_dir}/php-root/path').mkdir(mode=0o000, parents=True)

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "applications/php-path"}},
            "applications": {
                "php-path": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "root": f'{temp_dir}/php-root',
                }
            },
        }
    ), 'forbidden directory'

    assert client.get(url='/path/')['status'] == 403, 'access forbidden'


def test_php_application_extension_check(temp_dir):
    client.load('phpinfo')

    assert client.get(url='/index.wrong')['status'] != 200, 'status'

    new_root = f'{temp_dir}/php'
    Path(new_root).mkdir(parents=True)
    shutil.copy(f'{option.test_dir}/php/phpinfo/index.wrong', new_root)

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "applications/phpinfo"}},
            "applications": {
                "phpinfo": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "root": new_root,
                    "working_directory": new_root,
                }
            },
        }
    ), 'configure new root'

    resp = client.get()
    assert f'{resp["status"]}{resp["body"]}' != '200', 'status new root'


def test_php_application_cwd_root():
    client.load('cwd')
    run_php_application_cwd_root_tests()


def test_php_application_cwd_opcache_disabled():
    client.load('cwd')
    set_opcache('cwd', '0')
    run_php_application_cwd_root_tests()


def test_php_application_cwd_opcache_enabled():
    client.load('cwd')
    set_opcache('cwd', '1')
    run_php_application_cwd_root_tests()


def test_php_application_cwd_script():
    client.load('cwd')
    run_php_application_cwd_script_tests()


def test_php_application_cwd_script_opcache_disabled():
    client.load('cwd')
    set_opcache('cwd', '0')
    run_php_application_cwd_script_tests()


def test_php_application_cwd_script_opcache_enabled():
    client.load('cwd')
    set_opcache('cwd', '1')
    run_php_application_cwd_script_tests()


def test_php_application_path_relative():
    client.load('open')

    assert client.get()['body'] == 'test', 'relative path'

    assert (
        client.get(url='/?chdir=/')['body'] != 'test'
    ), 'relative path w/ chdir'

    assert client.get()['body'] == 'test', 'relative path 2'


def test_php_application_shared_opcache():
    client.load('opcache', limits={'requests': 1})

    r = check_opcache()
    pid = r['headers']['X-Pid']
    assert r['headers']['X-Cached'] == '0', 'not cached'

    r = client.get()

    assert r['headers']['X-Pid'] != pid, 'new instance'
    assert r['headers']['X-Cached'] == '1', 'cached'


def test_php_application_opcache_preload_chdir():
    client.load('opcache')

    check_opcache()

    set_preload('chdir.php')

    assert client.get()['headers']['X-Cached'] == '0', 'not cached'
    assert client.get()['headers']['X-Cached'] == '1', 'cached'


def test_php_application_opcache_preload_ffr():
    client.load('opcache')

    check_opcache()

    set_preload('fastcgi_finish_request.php')

    assert client.get()['headers']['X-Cached'] == '0', 'not cached'
    assert client.get()['headers']['X-Cached'] == '1', 'cached'
