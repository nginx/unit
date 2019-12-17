import re
import os
import grp
import pwd
import time
import unittest
from unit.applications.lang.python import TestApplicationPython


class TestPythonApplication(TestApplicationPython):
    prerequisites = {'modules': ['python']}

    def findall(self, pattern):
        with open(self.testdir + '/unit.log', 'r', errors='ignore') as f:
            return re.findall(pattern, f.read())

    def test_python_application_variables(self):
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
        )

        self.assertEqual(resp['status'], 200, 'status')
        headers = resp['headers']
        header_server = headers.pop('Server')
        self.assertRegex(header_server, r'Unit/[\d\.]+', 'server header')
        self.assertEqual(
            headers.pop('Server-Software'),
            header_server,
            'server software header',
        )

        date = headers.pop('Date')
        self.assertEqual(date[-4:], ' GMT', 'date header timezone')
        self.assertLess(
            abs(self.date_to_sec_epoch(date) - self.sec_epoch()),
            5,
            'date header',
        )

        self.assertDictEqual(
            headers,
            {
                'Connection': 'close',
                'Content-Length': str(len(body)),
                'Content-Type': 'text/html',
                'Request-Method': 'POST',
                'Request-Uri': '/',
                'Http-Host': 'localhost',
                'Server-Protocol': 'HTTP/1.1',
                'Custom-Header': 'blah',
                'Wsgi-Version': '(1, 0)',
                'Wsgi-Url-Scheme': 'http',
                'Wsgi-Multithread': 'False',
                'Wsgi-Multiprocess': 'True',
                'Wsgi-Run-Once': 'False',
            },
            'headers',
        )
        self.assertEqual(resp['body'], body, 'body')

    def test_python_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        self.assertEqual(
            resp['headers']['Query-String'],
            'var1=val1&var2=val2',
            'Query-String header',
        )

    def test_python_application_query_string_space(self):
        self.load('query_string')

        resp = self.get(url='/ ?var1=val1&var2=val2')
        self.assertEqual(
            resp['headers']['Query-String'],
            'var1=val1&var2=val2',
            'Query-String space',
        )

        resp = self.get(url='/ %20?var1=val1&var2=val2')
        self.assertEqual(
            resp['headers']['Query-String'],
            'var1=val1&var2=val2',
            'Query-String space 2',
        )

        resp = self.get(url='/ %20 ?var1=val1&var2=val2')
        self.assertEqual(
            resp['headers']['Query-String'],
            'var1=val1&var2=val2',
            'Query-String space 3',
        )

        resp = self.get(url='/blah %20 blah? var1= val1 & var2=val2')
        self.assertEqual(
            resp['headers']['Query-String'],
            ' var1= val1 & var2=val2',
            'Query-String space 4',
        )

    def test_python_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        self.assertEqual(resp['status'], 200, 'query string empty status')
        self.assertEqual(
            resp['headers']['Query-String'], '', 'query string empty'
        )

    def test_python_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        self.assertEqual(resp['status'], 200, 'query string absent status')
        self.assertEqual(
            resp['headers']['Query-String'], '', 'query string absent'
        )

    @unittest.skip('not yet')
    def test_python_application_server_port(self):
        self.load('server_port')

        self.assertEqual(
            self.get()['headers']['Server-Port'], '7080', 'Server-Port header'
        )

    @unittest.skip('not yet')
    def test_python_application_working_directory_invalid(self):
        self.load('empty')

        self.assertIn(
            'success',
            self.conf('"/blah"', 'applications/empty/working_directory'),
            'configure invalid working_directory',
        )

        self.assertEqual(self.get()['status'], 500, 'status')

    def test_python_application_204_transfer_encoding(self):
        self.load('204_no_content')

        self.assertNotIn(
            'Transfer-Encoding',
            self.get()['headers'],
            '204 header transfer encoding',
        )

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

        self.assertEqual(resp['status'], 200, 'ctx iter status')
        self.assertEqual(resp['body'], '0123456789', 'ctx iter body')

        self.conf({"listeners": {}, "applications": {}})

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'RuntimeError'), 'ctx iter atexit'
        )

    def test_python_keepalive_body(self):
        self.load('mirror')

        self.assertEqual(self.get()['status'], 200, 'init')

        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html',
            },
            start=True,
            body='0123456789' * 500,
            read_timeout=1,
        )

        self.assertEqual(resp['body'], '0123456789' * 500, 'keep-alive 1')

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            sock=sock,
            body='0123456789',
        )

        self.assertEqual(resp['body'], '0123456789', 'keep-alive 2')

    def test_python_keepalive_reconfigure(self):
        self.skip_alerts.extend(
            [
                r'pthread_mutex.+failed',
                r'failed to apply',
                r'process \d+ exited on signal',
            ]
        )
        self.load('mirror')

        self.assertEqual(self.get()['status'], 200, 'init')

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

            self.assertEqual(resp['body'], body, 'keep-alive open')
            self.assertIn(
                'success',
                self.conf(str(i + 1), 'applications/mirror/processes'),
                'reconfigure',
            )

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

            self.assertEqual(resp['body'], body, 'keep-alive request')
            self.assertIn(
                'success',
                self.conf(str(i + 1), 'applications/mirror/processes'),
                'reconfigure 2',
            )

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

            self.assertEqual(resp['body'], body, 'keep-alive close')
            self.assertIn(
                'success',
                self.conf(str(i + 1), 'applications/mirror/processes'),
                'reconfigure 3',
            )

    def test_python_keepalive_reconfigure_2(self):
        self.load('mirror')

        self.assertEqual(self.get()['status'], 200, 'init')

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

        self.assertEqual(resp['body'], body, 'reconfigure 2 keep-alive 1')

        self.load('empty')

        self.assertEqual(self.get()['status'], 200, 'init')

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

        self.assertEqual(resp['status'], 200, 'reconfigure 2 keep-alive 2')
        self.assertEqual(resp['body'], '', 'reconfigure 2 keep-alive 2 body')

        self.assertIn(
            'success',
            self.conf({"listeners": {}, "applications": {}}),
            'reconfigure 2 clear configuration',
        )

        resp = self.get(sock=sock)

        self.assertEqual(resp, {}, 'reconfigure 2 keep-alive 3')

    def test_python_keepalive_reconfigure_3(self):
        self.load('empty')

        self.assertEqual(self.get()['status'], 200, 'init')

        (resp, sock) = self.http(
            b"""GET / HTTP/1.1
""",
            start=True,
            raw=True,
            read_timeout=5,
        )

        self.assertIn(
            'success',
            self.conf({"listeners": {}, "applications": {}}),
            'reconfigure 3 clear configuration',
        )

        resp = self.http(
            b"""Host: localhost
Connection: close

""",
            sock=sock,
            raw=True,
        )

        self.assertEqual(resp['status'], 200, 'reconfigure 3')

    def test_python_atexit(self):
        self.load('atexit')

        self.get()

        self.conf({"listeners": {}, "applications": {}})

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'At exit called\.'), 'atexit'
        )

    @unittest.skip('not yet')
    def test_python_application_start_response_exit(self):
        self.load('start_response_exit')

        self.assertEqual(self.get()['status'], 500, 'start response exit')

    @unittest.skip('not yet')
    def test_python_application_input_iter(self):
        self.load('input_iter')

        body = '0123456789'

        self.assertEqual(self.post(body=body)['body'], body, 'input iter')

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

        self.assertEqual(resp['body'], body[:5], 'input read length lt body')

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '15',
                'Connection': 'close',
            },
            body=body,
        )

        self.assertEqual(resp['body'], body, 'input read length gt body')

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '0',
                'Connection': 'close',
            },
            body=body,
        )

        self.assertEqual(resp['body'], '', 'input read length zero')

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Input-Length': '-1',
                'Connection': 'close',
            },
            body=body,
        )

        self.assertEqual(resp['body'], body, 'input read length negative')

    @unittest.skip('not yet')
    def test_python_application_errors_write(self):
        self.load('errors_write')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'\[error\].+Error in application\.'),
            'errors write',
        )

    def test_python_application_body_array(self):
        self.load('body_array')

        self.assertEqual(self.get()['body'], '0123456789', 'body array')

    def test_python_application_body_io(self):
        self.load('body_io')

        self.assertEqual(self.get()['body'], '0123456789', 'body io')

    def test_python_application_body_io_file(self):
        self.load('body_io_file')

        self.assertEqual(self.get()['body'], 'body\n', 'body io file')

    @unittest.skip('not yet')
    def test_python_application_syntax_error(self):
        self.skip_alerts.append(r'Python failed to import module "wsgi"')
        self.load('syntax_error')

        self.assertEqual(self.get()['status'], 500, 'syntax error')

    def test_python_application_close(self):
        self.load('close')

        self.get()

        self.stop()

        self.assertIsNotNone(self.wait_for_record(r'Close called\.'), 'close')

    def test_python_application_close_error(self):
        self.load('close_error')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'Close called\.'), 'close error'
        )

    def test_python_application_not_iterable(self):
        self.load('not_iterable')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(
                r'\[error\].+the application returned not an iterable object'
            ),
            'not iterable',
        )

    def test_python_application_write(self):
        self.load('write')

        self.assertEqual(self.get()['body'], '0123456789', 'write')

    def test_python_application_threading(self):
        """wait_for_record() timeouts after 5s while every thread works at
        least 3s.  So without releasing GIL test should fail.
        """

        self.load('threading')

        for _ in range(10):
            self.get(no_recv=True)

        self.assertIsNotNone(
            self.wait_for_record(r'\(5\) Thread: 100'), 'last thread finished'
        )

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
        self.assertEqual(resp['status'], 200, 'status')
        self.assertEqual(resp['body'], 'XXXXXXX', 'body')

        # Exception before start_response().

        self.assertEqual(self.get()['status'], 503, 'error')

        self.assertIsNotNone(self.wait_for_record(r'Traceback'), 'traceback')
        self.assertIsNotNone(
            self.wait_for_record(r'raise Exception\(\'first exception\'\)'),
            'first exception raise',
        )
        self.assertEqual(
            len(self.findall(r'Traceback')), 1, 'traceback count 1'
        )

        # Exception after start_response(), before first write().

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Skip': '1',
                    'Connection': 'close',
                }
            )['status'],
            503,
            'error 2',
        )

        self.assertIsNotNone(
            self.wait_for_record(r'raise Exception\(\'second exception\'\)'),
            'exception raise second',
        )
        self.assertEqual(
            len(self.findall(r'Traceback')), 2, 'traceback count 2'
        )

        # Exception after first write(), before first __next__().

        _, sock = self.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '2',
                'Connection': 'keep-alive',
            },
            start=True,
        )

        self.assertIsNotNone(
            self.wait_for_record(r'raise Exception\(\'third exception\'\)'),
            'exception raise third',
        )
        self.assertEqual(
            len(self.findall(r'Traceback')), 3, 'traceback count 3'
        )

        self.assertDictEqual(self.get(sock=sock), {}, 'closed connection')

        # Exception after first write(), before first __next__(),
        # chunked (incomplete body).

        resp = self.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '2',
                'X-Chunked': '1',
                'Connection': 'close',
            },
            raw_resp=True
        )
        if resp:
            self.assertNotEqual(resp[-5:], '0\r\n\r\n', 'incomplete body')
        self.assertEqual(
            len(self.findall(r'Traceback')), 4, 'traceback count 4'
        )

        # Exception in __next__().

        _, sock = self.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '3',
                'Connection': 'keep-alive',
            },
            start=True,
        )

        self.assertIsNotNone(
            self.wait_for_record(r'raise Exception\(\'next exception\'\)'),
            'exception raise next',
        )
        self.assertEqual(
            len(self.findall(r'Traceback')), 5, 'traceback count 5'
        )

        self.assertDictEqual(self.get(sock=sock), {}, 'closed connection 2')

        # Exception in __next__(), chunked (incomplete body).

        resp = self.get(
            headers={
                'Host': 'localhost',
                'X-Skip': '3',
                'X-Chunked': '1',
                'Connection': 'close',
            },
            raw_resp=True
        )
        if resp:
            self.assertNotEqual(resp[-5:], '0\r\n\r\n', 'incomplete body 2')
        self.assertEqual(
            len(self.findall(r'Traceback')), 6, 'traceback count 6'
        )

        # Exception before start_response() and in close().

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Not-Skip-Close': '1',
                    'Connection': 'close',
                }
            )['status'],
            503,
            'error',
        )

        self.assertIsNotNone(
            self.wait_for_record(r'raise Exception\(\'close exception\'\)'),
            'exception raise close',
        )
        self.assertEqual(
            len(self.findall(r'Traceback')), 8, 'traceback count 8'
        )

    def test_python_user_group(self):
        if not self.is_su:
            print("requires root")
            raise unittest.SkipTest()

        nobody_uid = pwd.getpwnam('nobody').pw_uid

        group = 'nobody'

        try:
            group_id = grp.getgrnam(group).gr_gid
        except:
            group = 'nogroup'
            group_id = grp.getgrnam(group).gr_gid

        self.load('user_group')

        obj = self.getjson()['body']
        self.assertEqual(obj['UID'], nobody_uid, 'nobody uid')
        self.assertEqual(obj['GID'], group_id, 'nobody gid')

        self.load('user_group', user='nobody')

        obj = self.getjson()['body']
        self.assertEqual(obj['UID'], nobody_uid, 'nobody uid user=nobody')
        self.assertEqual(obj['GID'], group_id, 'nobody gid user=nobody')

        self.load('user_group', user='nobody', group=group)

        obj = self.getjson()['body']
        self.assertEqual(
            obj['UID'], nobody_uid, 'nobody uid user=nobody group=%s' % group
        )

        self.assertEqual(
            obj['GID'], group_id, 'nobody gid user=nobody group=%s' % group
        )

        self.load('user_group', group=group)

        obj = self.getjson()['body']
        self.assertEqual(
            obj['UID'], nobody_uid, 'nobody uid group=%s' % group
        )

        self.assertEqual(obj['GID'], group_id, 'nobody gid group=%s' % group)

        self.load('user_group', user='root')

        obj = self.getjson()['body']
        self.assertEqual(obj['UID'], 0, 'root uid user=root')
        self.assertEqual(obj['GID'], 0, 'root gid user=root')

        group = 'root'

        try:
            grp.getgrnam(group)
            group = True
        except:
            group = False

        if group:
            self.load('user_group', user='root', group='root')

            obj = self.getjson()['body']
            self.assertEqual(obj['UID'], 0, 'root uid user=root group=root')
            self.assertEqual(obj['GID'], 0, 'root gid user=root group=root')

            self.load('user_group', group='root')

            obj = self.getjson()['body']
            self.assertEqual(obj['UID'], nobody_uid, 'root uid group=root')
            self.assertEqual(obj['GID'], 0, 'root gid group=root')

if __name__ == '__main__':
    TestPythonApplication.main()
