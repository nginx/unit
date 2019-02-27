import time
import unittest
import unit

class TestUnitPythonApplication(unit.TestUnitApplicationPython):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_python_application_variables(self):
        self.load('variables')

        body = 'Test body string.'

        resp = self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Custom-Header': 'blah',
            'Connection': 'close'
        }, body=body)

        self.assertEqual(resp['status'], 200, 'status')
        headers = resp['headers']
        header_server = headers.pop('Server')
        self.assertRegex(header_server, r'Unit/[\d\.]+', 'server header')
        self.assertEqual(headers.pop('Server-Software'), header_server,
            'server software header')

        date = headers.pop('Date')
        self.assertEqual(date[-4:], ' GMT', 'date header timezone')
        self.assertLess(abs(self.date_to_sec_epoch(date) - self.sec_epoch()), 5,
            'date header')

        self.assertDictEqual(headers, {
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
            'Wsgi-Run-Once': 'False'
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_python_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        self.assertEqual(resp['headers']['Query-String'], 'var1=val1&var2=val2',
            'Query-String header')

    def test_python_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        self.assertEqual(resp['status'], 200, 'query string empty status')
        self.assertEqual(resp['headers']['Query-String'], '',
            'query string empty')

    @unittest.expectedFailure
    def test_python_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        self.assertEqual(resp['status'], 200, 'query string absent status')
        self.assertEqual(resp['headers']['Query-String'], '',
            'query string absent')

    @unittest.expectedFailure
    def test_python_application_server_port(self):
        self.load('server_port')

        self.assertEqual(self.get()['headers']['Server-Port'], '7080',
            'Server-Port header')

    def test_python_application_204_transfer_encoding(self):
        self.load('204_no_content')

        self.assertNotIn('Transfer-Encoding', self.get()['headers'],
            '204 header transfer encoding')

    def test_python_application_ctx_iter_atexit(self):
        self.load('ctx_iter_atexit')

        resp = self.post(headers={
            'Host': 'localhost',
            'Connection': 'close',
            'Content-Type': 'text/html'
        }, body='0123456789')

        self.assertEqual(resp['status'], 200, 'ctx iter status')
        self.assertEqual(resp['body'], '0123456789', 'ctx iter body')

        self.conf({
            "listeners": {},
            "applications": {}
        })

        self.stop()

        time.sleep(0.2)

        self.assertIsNotNone(self.search_in_log(r'RuntimeError'),
            'ctx iter atexit')

    def test_python_keepalive_body(self):
        self.load('mirror')

        (resp, sock) = self.post(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
            'Content-Type': 'text/html'
        }, start=True, body='0123456789' * 500)

        self.assertEqual(resp['body'], '0123456789' * 500, 'keep-alive 1')

        resp = self.post(headers={
            'Host': 'localhost',
            'Connection': 'close',
            'Content-Type': 'text/html'
        }, sock=sock, body='0123456789')

        self.assertEqual(resp['body'], '0123456789', 'keep-alive 2')

    def test_python_keepalive_reconfigure(self):
        self.load('mirror')

        body = '0123456789'
        conns = 3
        socks = []

        for i in range(conns):
            (resp, sock) = self.post(headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html'
            }, start=True, body=body)

            self.assertEqual(resp['body'], body, 'keep-alive open')
            self.assertIn('success', self.conf({
                "spare": i % 4,
                "max": (i % 4) + 1
            }, 'applications/mirror/processes'), 'reconfigure')

            socks.append(sock)

        for i in range(conns):
            (resp, sock) = self.post(headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html'
            }, start=True, sock=socks[i], body=body)

            self.assertEqual(resp['body'], body, 'keep-alive request')
            self.assertIn('success', self.conf({
                "spare": i % 4,
                "max": (i % 4) + 1
            }, 'applications/mirror/processes'), 'reconfigure 2')

        for i in range(conns):
            resp = self.post(headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html'
            }, sock=socks[i], body=body)

            self.assertEqual(resp['body'], body, 'keep-alive close')
            self.assertIn('success', self.conf({
                "spare": i % 4,
                "max": (i % 4) + 1
            }, 'applications/mirror/processes'), 'reconfigure 3')

    def test_python_keepalive_reconfigure_2(self):
        self.load('mirror')

        body = '0123456789'

        (resp, sock) = self.post(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
            'Content-Type': 'text/html'
        }, start=True, body=body)

        self.assertEqual(resp['body'], body, 'reconfigure 2 keep-alive 1')

        self.load('empty')

        (resp, sock) = self.post(headers={
            'Host': 'localhost',
            'Connection': 'close',
            'Content-Type': 'text/html'
        }, start=True, sock=sock, body=body)

        self.assertEqual(resp['status'], 200, 'reconfigure 2 keep-alive 2')
        self.assertEqual(resp['body'], '', 'reconfigure 2 keep-alive 2 body')

        self.assertIn('success', self.conf({
            "listeners": {},
            "applications": {}
        }), 'reconfigure 2 clear configuration')

        resp = self.get(sock=sock)

        self.assertEqual(resp, {}, 'reconfigure 2 keep-alive 3')

    def test_python_keepalive_reconfigure_3(self):
        self.load('empty')

        (resp, sock) = self.http(b"""GET / HTTP/1.1
""", start=True, raw=True)

        self.assertIn('success', self.conf({
            "listeners": {},
            "applications": {}
        }), 'reconfigure 3 clear configuration')

        resp = self.http(b"""Host: localhost
Connection: close

""", sock=sock, raw=True)

        self.assertEqual(resp['status'], 200, 'reconfigure 3')

    def test_python_atexit(self):
        self.load('atexit')

        self.get()

        self.conf({
            "listeners": {},
            "applications": {}
        })

        self.stop()

        self.assertIsNotNone(self.search_in_log(r'At exit called\.'), 'atexit')

    @unittest.expectedFailure
    def test_python_application_start_response_exit(self):
        self.load('start_response_exit')

        self.assertEqual(self.get()['status'], 500, 'start response exit')

    @unittest.expectedFailure
    def test_python_application_input_iter(self):
        self.load('input_iter')

        body = '0123456789'

        self.assertEqual(self.post(body=body)['body'], body, 'input iter')

    def test_python_application_input_read_length(self):
        self.load('input_read_length')

        body = '0123456789'

        resp = self.post(headers={
            'Host': 'localhost',
            'Input-Length': '5',
            'Connection': 'close'
        }, body=body)

        self.assertEqual(resp['body'], body[:5], 'input read length lt body')

        resp = self.post(headers={
            'Host': 'localhost',
            'Input-Length': '15',
            'Connection': 'close'
        }, body=body)

        self.assertEqual(resp['body'], body, 'input read length gt body')

        resp = self.post(headers={
            'Host': 'localhost',
            'Input-Length': '0',
            'Connection': 'close'
        }, body=body)

        self.assertEqual(resp['body'], '', 'input read length zero')

        resp = self.post(headers={
            'Host': 'localhost',
            'Input-Length': '-1',
            'Connection': 'close'
        }, body=body)

        self.assertEqual(resp['body'], body, 'input read length negative')

    @unittest.expectedFailure
    def test_python_application_errors_write(self):
        self.load('errors_write')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+Error in application\.'),
            'errors write')

    def test_python_application_body_array(self):
        self.load('body_array')

        self.assertEqual(self.get()['body'], '0123456789', 'body array')

    def test_python_application_body_io(self):
        self.load('body_io')

        self.assertEqual(self.get()['body'], '0123456789', 'body io')

    def test_python_application_body_io_file(self):
        self.load('body_io_file')

        self.assertEqual(self.get()['body'], 'body\n', 'body io file')

    @unittest.expectedFailure
    def test_python_application_syntax_error(self):
        self.skip_alerts.append(r'Python failed to import module "wsgi"')
        self.load('syntax_error')

        self.assertEqual(self.get()['status'], 500, 'syntax error')

    def test_python_application_close(self):
        self.load('close')

        self.get()

        self.stop()

        self.assertIsNotNone(self.search_in_log(r'Close called\.'), 'close')

    def test_python_application_close_error(self):
        self.load('close_error')

        self.get()

        self.stop()

        self.assertIsNotNone(self.search_in_log(r'Close called\.'),
            'close error')

    def test_python_application_not_iterable(self):
        self.load('not_iterable')

        self.get()

        self.stop()

        self.assertIsNotNone(self.search_in_log(
            r'\[error\].+the application returned not an iterable object'),
            'not iterable')

    def test_python_application_write(self):
        self.load('write')

        self.assertEqual(self.get()['body'], '0123456789', 'write')

if __name__ == '__main__':
    TestUnitPythonApplication.main()
