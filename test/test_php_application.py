import os
import re
import shutil
import time
from subprocess import call

import pytest

from unit.applications.lang.php import TestApplicationPHP
from unit.option import option


class TestPHPApplication(TestApplicationPHP):
    prerequisites = {'modules': {'php': 'all'}}

    def before_disable_functions(self):
        body = self.get()['body']

        assert re.search(r'time: \d+', body), 'disable_functions before time'
        assert re.search(r'exec: \/\w+', body), 'disable_functions before exec'

    def set_opcache(self, app, val):
        assert 'success' in self.conf(
            {"admin": {"opcache.enable": val, "opcache.enable_cli": val}},
            'applications/' + app + '/options',
        )

        opcache = self.get()['headers']['X-OPcache']

        if not opcache or opcache == '-1':
            pytest.skip('opcache is not supported')

        assert opcache == val, 'opcache value'

    def test_php_application_variables(self):
        self.load('variables')

        body = 'Test body string.'

        resp = self.post(
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
        assert (
            abs(self.date_to_sec_epoch(date) - self.sec_epoch()) < 5
        ), 'date header'

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

    def test_php_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'query string'

    def test_php_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        assert resp['status'] == 200, 'query string empty status'
        assert resp['headers']['Query-String'] == '', 'query string empty'

    def test_php_application_fastcgi_finish_request(self, temp_dir):
        self.load('fastcgi_finish_request')

        assert self.get()['body'] == '0123'

        with open(temp_dir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        with open(temp_dir + '/unit.log', 'r', errors='ignore') as f:
            errs = re.findall(r'Error in fastcgi_finish_request', f.read())

            assert len(errs) == 0, 'no error'

    def test_php_application_fastcgi_finish_request_2(self, temp_dir):
        self.load('fastcgi_finish_request')

        resp = self.get(url='/?skip')
        assert resp['status'] == 200
        assert resp['body'] == ''

        with open(temp_dir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        with open(temp_dir + '/unit.log', 'r', errors='ignore') as f:
            errs = re.findall(r'Error in fastcgi_finish_request', f.read())

            assert len(errs) == 0, 'no error'

    def test_php_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        assert resp['status'] == 200, 'query string absent status'
        assert resp['headers']['Query-String'] == '', 'query string absent'

    def test_php_application_phpinfo(self):
        self.load('phpinfo')

        resp = self.get()

        assert resp['status'] == 200, 'status'
        assert resp['body'] != '', 'body not empty'

    def test_php_application_header_status(self):
        self.load('header')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'X-Header': 'HTTP/1.1 404 Not Found',
                }
            )['status']
            == 404
        ), 'status'

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'X-Header': 'http/1.1 404 Not Found',
                }
            )['status']
            == 404
        ), 'status case insensitive'

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'X-Header': 'HTTP/ 404 Not Found',
                }
            )['status']
            == 404
        ), 'status version empty'

    def test_php_application_404(self):
        self.load('404')

        resp = self.get()

        assert resp['status'] == 404, '404 status'
        assert re.search(
            r'<title>404 Not Found</title>', resp['body']
        ), '404 body'

    def test_php_application_keepalive_body(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        body = '0123456789' * 500
        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html',
            },
            start=True,
            body=body,
            read_timeout=1,
        )

        assert resp['body'] == body, 'keep-alive 1'

        body = '0123456789'
        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            sock=sock,
            body=body,
        )

        assert resp['body'] == body, 'keep-alive 2'

    def test_php_application_conditional(self):
        self.load('conditional')

        assert re.search(r'True', self.get()['body']), 'conditional true'
        assert re.search(r'False', self.post()['body']), 'conditional false'

    def test_php_application_get_variables(self):
        self.load('get_variables')

        resp = self.get(url='/?var1=val1&var2=&var3')
        assert resp['headers']['X-Var-1'] == 'val1', 'GET variables'
        assert resp['headers']['X-Var-2'] == '', 'GET variables 2'
        assert resp['headers']['X-Var-3'] == '', 'GET variables 3'
        assert resp['headers']['X-Var-4'] == 'not set', 'GET variables 4'

    def test_php_application_post_variables(self):
        self.load('post_variables')

        resp = self.post(
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

    def test_php_application_cookies(self):
        self.load('cookies')

        resp = self.get(
            headers={
                'Cookie': 'var=val; var2=val2',
                'Host': 'localhost',
                'Connection': 'close',
            }
        )

        assert resp['headers']['X-Cookie-1'] == 'val', 'cookie'
        assert resp['headers']['X-Cookie-2'] == 'val2', 'cookie'

    def test_php_application_ini_precision(self):
        self.load('ini_precision')

        assert self.get()['headers']['X-Precision'] != '4', 'ini value default'

        assert 'success' in self.conf(
            {"file": "ini/php.ini"}, 'applications/ini_precision/options'
        )

        assert (
            self.get()['headers']['X-File']
            == option.test_dir + '/php/ini_precision/ini/php.ini'
        ), 'ini file'
        assert self.get()['headers']['X-Precision'] == '4', 'ini value'

    @pytest.mark.skip('not yet')
    def test_php_application_ini_admin_user(self):
        self.load('ini_precision')

        assert 'error' in self.conf(
            {"user": {"precision": "4"}, "admin": {"precision": "5"}},
            'applications/ini_precision/options',
        ), 'ini admin user'

    def test_php_application_ini_admin(self):
        self.load('ini_precision')

        assert 'success' in self.conf(
            {"file": "php.ini", "admin": {"precision": "5"}},
            'applications/ini_precision/options',
        )

        assert self.get()['headers']['X-Precision'] == '5', 'ini value admin'

    def test_php_application_ini_user(self):
        self.load('ini_precision')

        assert 'success' in self.conf(
            {"file": "php.ini", "user": {"precision": "5"}},
            'applications/ini_precision/options',
        )

        assert self.get()['headers']['X-Precision'] == '5', 'ini value user'

    def test_php_application_ini_user_2(self):
        self.load('ini_precision')

        assert 'success' in self.conf(
            {"file": "ini/php.ini"}, 'applications/ini_precision/options'
        )

        assert self.get()['headers']['X-Precision'] == '4', 'ini user file'

        assert 'success' in self.conf(
            {"precision": "5"}, 'applications/ini_precision/options/user'
        )

        assert self.get()['headers']['X-Precision'] == '5', 'ini value user'

    def test_php_application_ini_set_admin(self):
        self.load('ini_precision')

        assert 'success' in self.conf(
            {"admin": {"precision": "5"}}, 'applications/ini_precision/options'
        )

        assert (
            self.get(url='/?precision=6')['headers']['X-Precision'] == '5'
        ), 'ini set admin'

    def test_php_application_ini_set_user(self):
        self.load('ini_precision')

        assert 'success' in self.conf(
            {"user": {"precision": "5"}}, 'applications/ini_precision/options'
        )

        assert (
            self.get(url='/?precision=6')['headers']['X-Precision'] == '6'
        ), 'ini set user'

    def test_php_application_ini_repeat(self):
        self.load('ini_precision')

        assert 'success' in self.conf(
            {"user": {"precision": "5"}}, 'applications/ini_precision/options'
        )

        assert self.get()['headers']['X-Precision'] == '5', 'ini value'

        assert self.get()['headers']['X-Precision'] == '5', 'ini value repeat'

    def test_php_application_disable_functions_exec(self):
        self.load('time_exec')

        self.before_disable_functions()

        assert 'success' in self.conf(
            {"admin": {"disable_functions": "exec"}},
            'applications/time_exec/options',
        )

        body = self.get()['body']

        assert re.search(r'time: \d+', body), 'disable_functions time'
        assert not re.search(r'exec: \/\w+', body), 'disable_functions exec'

    def test_php_application_disable_functions_comma(self):
        self.load('time_exec')

        self.before_disable_functions()

        assert 'success' in self.conf(
            {"admin": {"disable_functions": "exec,time"}},
            'applications/time_exec/options',
        )

        body = self.get()['body']

        assert not re.search(
            r'time: \d+', body
        ), 'disable_functions comma time'
        assert not re.search(
            r'exec: \/\w+', body
        ), 'disable_functions comma exec'

    def test_php_application_auth(self):
        self.load('auth')

        resp = self.get()
        assert resp['status'] == 200, 'status'
        assert resp['headers']['X-Digest'] == 'not set', 'digest'
        assert resp['headers']['X-User'] == 'not set', 'user'
        assert resp['headers']['X-Password'] == 'not set', 'password'

        resp = self.get(
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

        resp = self.get(
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

    def test_php_application_auth_invalid(self):
        self.load('auth')

        def check_auth(auth):
            resp = self.get(
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

    def test_php_application_disable_functions_space(self):
        self.load('time_exec')

        self.before_disable_functions()

        assert 'success' in self.conf(
            {"admin": {"disable_functions": "exec time"}},
            'applications/time_exec/options',
        )

        body = self.get()['body']

        assert not re.search(
            r'time: \d+', body
        ), 'disable_functions space time'
        assert not re.search(
            r'exec: \/\w+', body
        ), 'disable_functions space exec'

    def test_php_application_disable_functions_user(self):
        self.load('time_exec')

        self.before_disable_functions()

        assert 'success' in self.conf(
            {"user": {"disable_functions": "exec"}},
            'applications/time_exec/options',
        )

        body = self.get()['body']

        assert re.search(r'time: \d+', body), 'disable_functions user time'
        assert not re.search(
            r'exec: \/\w+', body
        ), 'disable_functions user exec'

    def test_php_application_disable_functions_nonexistent(self):
        self.load('time_exec')

        self.before_disable_functions()

        assert 'success' in self.conf(
            {"admin": {"disable_functions": "blah"}},
            'applications/time_exec/options',
        )

        body = self.get()['body']

        assert re.search(
            r'time: \d+', body
        ), 'disable_functions nonexistent time'
        assert re.search(
            r'exec: \/\w+', body
        ), 'disable_functions nonexistent exec'

    def test_php_application_disable_classes(self):
        self.load('date_time')

        assert re.search(
            r'012345', self.get()['body']
        ), 'disable_classes before'

        assert 'success' in self.conf(
            {"admin": {"disable_classes": "DateTime"}},
            'applications/date_time/options',
        )

        assert not re.search(
            r'012345', self.get()['body']
        ), 'disable_classes before'

    def test_php_application_disable_classes_user(self):
        self.load('date_time')

        assert re.search(
            r'012345', self.get()['body']
        ), 'disable_classes before'

        assert 'success' in self.conf(
            {"user": {"disable_classes": "DateTime"}},
            'applications/date_time/options',
        )

        assert not re.search(
            r'012345', self.get()['body']
        ), 'disable_classes before'

    def test_php_application_error_log(self, temp_dir):
        self.load('error_log')

        assert self.get()['status'] == 200, 'status'

        time.sleep(1)

        assert self.get()['status'] == 200, 'status 2'

        pattern = r'\d{4}\/\d\d\/\d\d\s\d\d:.+\[notice\].+Error in application'

        assert self.wait_for_record(pattern) is not None, 'errors print'

        with open(temp_dir + '/unit.log', 'r', errors='ignore') as f:
            errs = re.findall(pattern, f.read())

            assert len(errs) == 2, 'error_log count'

            date = errs[0].split('[')[0]
            date2 = errs[1].split('[')[0]
            assert date != date2, 'date diff'

    def test_php_application_script(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "applications/script"}},
                "applications": {
                    "script": {
                        "type": "php",
                        "processes": {"spare": 0},
                        "root": option.test_dir + "/php/script",
                        "script": "phpinfo.php",
                    }
                },
            }
        ), 'configure script'

        resp = self.get()

        assert resp['status'] == 200, 'status'
        assert resp['body'] != '', 'body not empty'

    def test_php_application_index_default(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "applications/phpinfo"}},
                "applications": {
                    "phpinfo": {
                        "type": "php",
                        "processes": {"spare": 0},
                        "root": option.test_dir + "/php/phpinfo",
                    }
                },
            }
        ), 'configure index default'

        resp = self.get()

        assert resp['status'] == 200, 'status'
        assert resp['body'] != '', 'body not empty'

    def test_php_application_extension_check(self, temp_dir):
        self.load('phpinfo')

        assert self.get(url='/index.wrong')['status'] != 200, 'status'

        new_root = temp_dir + "/php"
        os.mkdir(new_root)
        shutil.copy(option.test_dir + '/php/phpinfo/index.wrong', new_root)

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "applications/phpinfo"}},
                "applications": {
                    "phpinfo": {
                        "type": "php",
                        "processes": {"spare": 0},
                        "root": new_root,
                        "working_directory": new_root,
                    }
                },
            }
        ), 'configure new root'

        resp = self.get()
        assert str(resp['status']) + resp['body'] != '200', 'status new root'

    def run_php_application_cwd_root_tests(self):
        assert 'success' in self.conf_delete(
            'applications/cwd/working_directory'
        )

        script_cwd = option.test_dir + '/php/cwd'

        resp = self.get()
        assert resp['status'] == 200, 'status ok'
        assert resp['body'] == script_cwd, 'default cwd'

        assert 'success' in self.conf(
            '"' + option.test_dir + '"', 'applications/cwd/working_directory',
        )

        resp = self.get()
        assert resp['status'] == 200, 'status ok'
        assert resp['body'] == script_cwd, 'wdir cwd'

        resp = self.get(url='/?chdir=/')
        assert resp['status'] == 200, 'status ok'
        assert resp['body'] == '/', 'cwd after chdir'

        # cwd must be restored

        resp = self.get()
        assert resp['status'] == 200, 'status ok'
        assert resp['body'] == script_cwd, 'cwd restored'

        resp = self.get(url='/subdir/')
        assert resp['body'] == script_cwd + '/subdir', 'cwd subdir'

    def test_php_application_cwd_root(self):
        self.load('cwd')
        self.run_php_application_cwd_root_tests()

    def test_php_application_cwd_opcache_disabled(self):
        self.load('cwd')
        self.set_opcache('cwd', '0')
        self.run_php_application_cwd_root_tests()

    def test_php_application_cwd_opcache_enabled(self):
        self.load('cwd')
        self.set_opcache('cwd', '1')
        self.run_php_application_cwd_root_tests()

    def run_php_application_cwd_script_tests(self):
        self.load('cwd')

        script_cwd = option.test_dir + '/php/cwd'

        assert 'success' in self.conf_delete(
            'applications/cwd/working_directory'
        )

        assert 'success' in self.conf('"index.php"', 'applications/cwd/script')

        assert self.get()['body'] == script_cwd, 'default cwd'

        assert self.get(url='/?chdir=/')['body'] == '/', 'cwd after chdir'

        # cwd must be restored
        assert self.get()['body'] == script_cwd, 'cwd restored'

    def test_php_application_cwd_script(self):
        self.load('cwd')
        self.run_php_application_cwd_script_tests()

    def test_php_application_cwd_script_opcache_disabled(self):
        self.load('cwd')
        self.set_opcache('cwd', '0')
        self.run_php_application_cwd_script_tests()

    def test_php_application_cwd_script_opcache_enabled(self):
        self.load('cwd')
        self.set_opcache('cwd', '1')
        self.run_php_application_cwd_script_tests()

    def test_php_application_path_relative(self):
        self.load('open')

        assert self.get()['body'] == 'test', 'relative path'

        assert (
            self.get(url='/?chdir=/')['body'] != 'test'
        ), 'relative path w/ chdir'

        assert self.get()['body'] == 'test', 'relative path 2'
