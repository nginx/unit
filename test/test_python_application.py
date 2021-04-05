import grp
import os
import pwd
import re
import time

import pytest

from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestPythonApplication(TestApplicationPython):
    prerequisites = {'modules': {'python': 'all'}}

    def findall(self, pattern):
        with open(option.temp_dir + '/unit.log', 'r', errors='ignore') as f:
            return re.findall(pattern, f.read())

    def test_python_application_variables(self):
        self.load('variables')

        body = 'Test body string.'

        resp = self.http(
            b"""POST / HTTP/1.1
Host: localhost
Content-Length: %d
Custom-Header: blah
Custom-hEader: Blah
Content-Type: text/html
Connection: close
custom-header: BLAH

%s"""
            % (len(body), body.encode()),
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
        assert (
            abs(self.date_to_sec_epoch(date) - self.sec_epoch()) < 5
        ), 'date header'

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

    def test_python_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'Query-String header'

    def test_python_application_query_string_space(self):
        self.load('query_string')

        resp = self.get(url='/ ?var1=val1&var2=val2')
        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'Query-String space'

        resp = self.get(url='/ %20?var1=val1&var2=val2')
        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'Query-String space 2'

        resp = self.get(url='/ %20 ?var1=val1&var2=val2')
        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'Query-String space 3'

        resp = self.get(url='/blah %20 blah? var1= val1 & var2=val2')
        assert (
            resp['headers']['Query-String'] == ' var1= val1 & var2=val2'
        ), 'Query-String space 4'

    def test_python_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        assert resp['status'] == 200, 'query string empty status'
        assert resp['headers']['Query-String'] == '', 'query string empty'

    def test_python_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        assert resp['status'] == 200, 'query string absent status'
        assert resp['headers']['Query-String'] == '', 'query string absent'

    @pytest.mark.skip('not yet')
    def test_python_application_server_port(self):
        self.load('server_port')

        assert (
            self.get()['headers']['Server-Port'] == '7080'
        ), 'Server-Port header'

    @pytest.mark.skip('not yet')
    def test_python_application_working_directory_invalid(self):
        self.load('empty')

        assert 'success' in self.conf(
            '"/blah"', 'applications/empty/working_directory'
        ), 'configure invalid working_directory'

        assert self.get()['status'] == 500, 'status'

    def test_python_application_204_transfer_encoding(self):
        self.load('204_no_content')

        assert (
            'Transfer-Encoding' not in self.get()['headers']
        ), '204 header transfer encoding'

    def test_python_application_ctx_iter_atexit(self):
        self.load('ctx_iter_atexit')

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            body='0123456789',
        )

        assert resp['status'] == 200, 'ctx iter status'
        assert resp['body'] == '0123456789', 'ctx iter body'

        assert 'success' in self.conf({"listeners": {}, "applications": {}})

        assert (
            self.wait_for_record(r'RuntimeError') is not None
        ), 'ctx iter atexit'

    def test_python_keepalive_body(self):
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

    def test_python_keepalive_reconfigure(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        body = '0123456789'
        conns = 3
        socks = []

        for i in range(conns):
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

            assert resp['body'] == body, 'keep-alive open'

            self.load('mirror', processes=i + 1)

            socks.append(sock)

        for i in range(conns):
            (resp, sock) = self.post(
                headers={
                    'Host': 'localhost',
                    'Connection': 'keep-alive',
                    'Content-Type': 'text/html',
                },
                start=True,
                sock=socks[i],
                body=body,
                read_timeout=1,
            )

            assert resp['body'] == body, 'keep-alive request'

            self.load('mirror', processes=i + 1)

        for i in range(conns):
            resp = self.post(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'Content-Type': 'text/html',
                },
                sock=socks[i],
                body=body,
            )

            assert resp['body'] == body, 'keep-alive close'

            self.load('mirror', processes=i + 1)

    def test_python_keepalive_reconfigure_2(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        body = '0123456789'

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

        assert resp['body'] == body, 'reconfigure 2 keep-alive 1'

        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            start=True,
            sock=sock,
            body=body,
        )

        assert resp['status'] == 200, 'reconfigure 2 keep-alive 2'
        assert resp['body'] == '', 'reconfigure 2 keep-alive 2 body'

        assert 'success' in self.conf(
            {"listeners": {}, "applications": {}}
        ), 'reconfigure 2 clear configuration'

        resp = self.get(sock=sock)

        assert resp == {}, 'reconfigure 2 keep-alive 3'

    def test_python_keepalive_reconfigure_3(self):
        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        (_, sock) = self.http(
            b"""GET / HTTP/1.1
""",
            start=True,
            raw=True,
            no_recv=True,
        )

        assert self.get()['status'] == 200

        assert 'success' in self.conf(
            {"listeners": {}, "applications": {}}
        ), 'reconfigure 3 clear configuration'

        resp = self.http(
            b"""Host: localhost
Connection: close

""",
            sock=sock,
            raw=True,
        )

        assert resp['status'] == 200, 'reconfigure 3'

    def test_python_atexit(self):
        self.load('atexit')

        self.get()

        assert 'success' in self.conf({"listeners": {}, "applications": {}})

        assert self.wait_for_record(r'At exit called\.') is not None, 'atexit'

    def test_python_process_switch(self):
        self.load('delayed', processes=2)

        self.get(
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

        self.get(headers=headers_delay_1, no_recv=True)

        time.sleep(0.5)

        for _ in range(10):
            self.get(headers=headers_delay_1, no_recv=True)

        self.get(headers=headers_delay_1)

    @pytest.mark.skip('not yet')
    def test_python_application_start_response_exit(self):
        self.load('start_response_exit')

        assert self.get()['status'] == 500, 'start response exit'

    def test_python_application_input_iter(self):
        self.load('input_iter')

        body = '''0123456789
next line

last line'''

        resp = self.post(body=body)
        assert resp['body'] == body, 'input iter'
        assert resp['headers']['X-Lines-Count'] == '4', 'input iter lines'

    def test_python_application_input_readline(self):
        self.load('input_readline')

        body = '''0123456789
next line

last line'''

        resp = self.post(body=body)
        assert resp['body'] == body, 'input readline'
        assert resp['headers']['X-Lines-Count'] == '4', 'input readline lines'

    def test_python_application_input_readline_size(self):
        self.load('input_readline_size')

        body = '''0123456789
next line

last line'''

        assert self.post(body=body)['body'] == body, 'input readline size'
        assert (
            self.post(body='0123')['body'] == '0123'
        ), 'input readline size less'

    def test_python_application_input_readlines(self):
        self.load('input_readlines')

        body = '''0123456789
next line

last line'''

        resp = self.post(body=body)
        assert resp['body'] == body, 'input readlines'
        assert resp['headers']['X-Lines-Count'] == '4', 'input readlines lines'

    def test_python_application_input_readlines_huge(self):
        self.load('input_readlines')

        body = (
            '''0123456789 abcdefghi
next line: 0123456789 abcdefghi

last line: 987654321
'''
            * 512
        )

        assert (
            self.post(body=body, read_buffer_size=16384)['body'] == body
        ), 'input readlines huge'

    def test_python_application_input_read_length(self):
        self.load('input_read_length')

        body = '0123456789'

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '5',
                'Connection': 'close',
            },
            body=body,
        )

        assert resp['body'] == body[:5], 'input read length lt body'

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '15',
                'Connection': 'close',
            },
            body=body,
        )

        assert resp['body'] == body, 'input read length gt body'

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '0',
                'Connection': 'close',
            },
            body=body,
        )

        assert resp['body'] == '', 'input read length zero'

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '-1',
                'Connection': 'close',
            },
            body=body,
        )

        assert resp['body'] == body, 'input read length negative'

    @pytest.mark.skip('not yet')
    def test_python_application_errors_write(self):
        self.load('errors_write')

        self.get()

        assert (
            self.wait_for_record(r'\[error\].+Error in application\.')
            is not None
        ), 'errors write'

    def test_python_application_body_array(self):
        self.load('body_array')

        assert self.get()['body'] == '0123456789', 'body array'

    def test_python_application_body_io(self):
        self.load('body_io')

        assert self.get()['body'] == '0123456789', 'body io'

    def test_python_application_body_io_file(self):
        self.load('body_io_file')

        assert self.get()['body'] == 'body\n', 'body io file'

    @pytest.mark.skip('not yet')
    def test_python_application_syntax_error(self, skip_alert):
        skip_alert(r'Python failed to import module "wsgi"')
        self.load('syntax_error')

        assert self.get()['status'] == 500, 'syntax error'

    def test_python_application_loading_error(self, skip_alert):
        skip_alert(r'Python failed to import module "blah"')

        self.load('empty', module="blah")

        assert self.get()['status'] == 503, 'loading error'

    def test_python_application_close(self):
        self.load('close')

        self.get()

        assert self.wait_for_record(r'Close called\.') is not None, 'close'

    def test_python_application_close_error(self):
        self.load('close_error')

        self.get()

        assert (
            self.wait_for_record(r'Close called\.') is not None
        ), 'close error'

    def test_python_application_not_iterable(self):
        self.load('not_iterable')

        self.get()

        assert (
            self.wait_for_record(
                r'\[error\].+the application returned not an iterable object'
            )
            is not None
        ), 'not iterable'

    def test_python_application_write(self):
        self.load('write')

        assert self.get()['body'] == '0123456789', 'write'

    def test_python_application_threading(self):
        """wait_for_record() timeouts after 5s while every thread works at
        least 3s.  So without releasing GIL test should fail.
        """

        self.load('threading')

        for _ in range(10):
            self.get(no_recv=True)

        assert (
            self.wait_for_record(r'\(5\) Thread: 100', wait=50) is not None
        ), 'last thread finished'

    def test_python_application_iter_exception(self):
        self.load('iter_exception')

        # Default request doesn't lead to the exception.

        resp = self.get(
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

        assert self.get()['status'] == 503, 'error'

        assert self.wait_for_record(r'Traceback') is not None, 'traceback'
        assert (
            self.wait_for_record(r'raise Exception\(\'first exception\'\)')
            is not None
        ), 'first exception raise'
        assert len(self.findall(r'Traceback')) == 1, 'traceback count 1'

        # Exception after start_response(), before first write().

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Skip': '1',
                    'Connection': 'close',
                }
            )['status']
            == 503
        ), 'error 2'

        assert (
            self.wait_for_record(r'raise Exception\(\'second exception\'\)')
            is not None
        ), 'exception raise second'
        assert len(self.findall(r'Traceback')) == 2, 'traceback count 2'

        # Exception after first write(), before first __next__().

        _, sock = self.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '2',
                'Connection': 'keep-alive',
            },
            start=True,
        )

        assert (
            self.wait_for_record(r'raise Exception\(\'third exception\'\)')
            is not None
        ), 'exception raise third'
        assert len(self.findall(r'Traceback')) == 3, 'traceback count 3'

        assert self.get(sock=sock) == {}, 'closed connection'

        # Exception after first write(), before first __next__(),
        # chunked (incomplete body).

        resp = self.get(
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
        assert len(self.findall(r'Traceback')) == 4, 'traceback count 4'

        # Exception in __next__().

        _, sock = self.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '3',
                'Connection': 'keep-alive',
            },
            start=True,
        )

        assert (
            self.wait_for_record(r'raise Exception\(\'next exception\'\)')
            is not None
        ), 'exception raise next'
        assert len(self.findall(r'Traceback')) == 5, 'traceback count 5'

        assert self.get(sock=sock) == {}, 'closed connection 2'

        # Exception in __next__(), chunked (incomplete body).

        resp = self.get(
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
        assert len(self.findall(r'Traceback')) == 6, 'traceback count 6'

        # Exception before start_response() and in close().

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Not-Skip-Close': '1',
                    'Connection': 'close',
                }
            )['status']
            == 503
        ), 'error'

        assert (
            self.wait_for_record(r'raise Exception\(\'close exception\'\)')
            is not None
        ), 'exception raise close'
        assert len(self.findall(r'Traceback')) == 8, 'traceback count 8'

    def test_python_user_group(self, is_su):
        if not is_su:
            pytest.skip('requires root')

        nobody_uid = pwd.getpwnam('nobody').pw_uid

        group = 'nobody'

        try:
            group_id = grp.getgrnam(group).gr_gid
        except KeyError:
            group = 'nogroup'
            group_id = grp.getgrnam(group).gr_gid

        self.load('user_group')

        obj = self.getjson()['body']
        assert obj['UID'] == nobody_uid, 'nobody uid'
        assert obj['GID'] == group_id, 'nobody gid'

        self.load('user_group', user='nobody')

        obj = self.getjson()['body']
        assert obj['UID'] == nobody_uid, 'nobody uid user=nobody'
        assert obj['GID'] == group_id, 'nobody gid user=nobody'

        self.load('user_group', user='nobody', group=group)

        obj = self.getjson()['body']
        assert obj['UID'] == nobody_uid, (
            'nobody uid user=nobody group=%s' % group
        )

        assert obj['GID'] == group_id, (
            'nobody gid user=nobody group=%s' % group
        )

        self.load('user_group', group=group)

        obj = self.getjson()['body']
        assert obj['UID'] == nobody_uid, 'nobody uid group=%s' % group

        assert obj['GID'] == group_id, 'nobody gid group=%s' % group

        self.load('user_group', user='root')

        obj = self.getjson()['body']
        assert obj['UID'] == 0, 'root uid user=root'
        assert obj['GID'] == 0, 'root gid user=root'

        group = 'root'

        try:
            grp.getgrnam(group)
            group = True
        except KeyError:
            group = False

        if group:
            self.load('user_group', user='root', group='root')

            obj = self.getjson()['body']
            assert obj['UID'] == 0, 'root uid user=root group=root'
            assert obj['GID'] == 0, 'root gid user=root group=root'

            self.load('user_group', group='root')

            obj = self.getjson()['body']
            assert obj['UID'] == nobody_uid, 'root uid group=root'
            assert obj['GID'] == 0, 'root gid group=root'

    def test_python_application_callable(self, skip_alert):
        skip_alert(r'Python failed to get "blah" from module')
        self.load('callable')

        assert self.get()['status'] == 204, 'default application response'

        self.load('callable', callable="app")

        assert self.get()['status'] == 200, 'callable response'

        self.load('callable', callable="blah")

        assert self.get()['status'] not in [200, 204], 'callable response inv'

    def test_python_application_path(self):
        self.load('path')

        def set_path(path):
            assert 'success' in self.conf(path, 'applications/path/path')

        def get_path():
            return self.get()['body'].split(os.pathsep)

        default_path = self.conf_get('/config/applications/path/path')
        assert 'success' in self.conf(
            {"PYTHONPATH": default_path},
            '/config/applications/path/environment',
        )

        self.conf_delete('/config/applications/path/path')
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

    def test_python_application_path_invalid(self):
        self.load('path')

        def check_path(path):
            assert 'error' in self.conf(path, 'applications/path/path')

        check_path('{}')
        check_path('["/blah", []]')

    def test_python_application_threads(self):
        self.load('threads', threads=4)

        socks = []

        for i in range(4):
            (_, sock) = self.get(
                headers={
                    'Host': 'localhost',
                    'X-Delay': '2',
                    'Connection': 'close',
                },
                no_recv=True,
                start=True,
            )

            socks.append(sock)

        threads = set()

        for sock in socks:
            resp = self.recvall(sock).decode('utf-8')

            self.log_in(resp)

            resp = self._resp_to_dict(resp)

            assert resp['status'] == 200, 'status'

            threads.add(resp['headers']['X-Thread'])

            assert resp['headers']['Wsgi-Multithread'] == 'True', 'multithread'

            sock.close()

        assert len(socks) == len(threads), 'threads differs'
