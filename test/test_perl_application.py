import unittest
import unit

class TestUnitPerlApplication(unit.TestUnitApplicationPerl):

    def setUpClass():
        unit.TestUnit().check_modules('perl')

    def test_perl_application(self):
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
            'Psgi-Version': '11',
            'Psgi-Url-Scheme': 'http',
            'Psgi-Multithread': '',
            'Psgi-Multiprocess': '1',
            'Psgi-Run-Once': '',
            'Psgi-Nonblocking': '',
            'Psgi-Streaming': ''
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_perl_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        self.assertEqual(resp['headers']['Query-String'], 'var1=val1&var2=val2',
            'Query-String header')

    def test_perl_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        self.assertEqual(resp['status'], 200, 'query string empty status')
        self.assertEqual(resp['headers']['Query-String'], '',
            'query string empty')

    @unittest.expectedFailure
    def test_perl_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        self.assertEqual(resp['status'], 200, 'query string absent status')
        self.assertEqual(resp['headers']['Query-String'], '',
            'query string absent')

    @unittest.expectedFailure
    def test_perl_application_server_port(self):
        self.load('server_port')

        self.assertEqual(self.get()['headers']['Server-Port'], '7080',
            'Server-Port header')

    def test_perl_application_input_read_empty(self):
        self.load('input_read_empty')

        self.assertEqual(self.get()['body'], '', 'read empty')

    def test_perl_application_input_read_parts(self):
        self.load('input_read_parts')

        self.assertEqual(self.post(body='0123456789')['body'], '0123456789',
            'input read parts')

    @unittest.expectedFailure
    def test_perl_application_input_read_offset(self):
        self.load('input_read_offset')

        self.assertEqual(self.post(body='0123456789')['body'], '4567',
            'read offset')

    def test_perl_application_input_copy(self):
        self.load('input_copy')

        body = '0123456789'
        self.assertEqual(self.post(body=body)['body'], body, 'input copy')

    def test_perl_application_errors_print(self):
        self.load('errors_print')

        self.assertEqual(self.get()['body'], '1', 'errors result')

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+Error in application'),
            'errors print')

    def test_perl_application_header_equal_names(self):
        self.load('header_equal_names')

        self.assertListEqual(self.get()['headers']['Set-Cookie'],
            ['tc=one,two,three', 'tc=four,five,six'], 'header equal names')

    def test_perl_application_header_pairs(self):
        self.load('header_pairs')

        self.assertEqual(self.get()['headers']['blah'], 'blah', 'header pairs')

    def test_perl_application_body_empty(self):
        self.load('body_empty')

        self.assertEqual(self.get()['body'], '0\r\n\r\n', 'body empty')

    def test_perl_application_body_array(self):
        self.load('body_array')

        self.assertEqual(self.get()['body'], '0123456789', 'body array')

    def test_perl_application_body_large(self):
        self.load('variables')

        body = '0123456789' * 1000

        resp = self.post(body=body)['body']

        self.assertEqual(resp, body, 'body large')

    def test_perl_application_body_io_empty(self):
        self.load('body_io_empty')

        self.assertEqual(self.get()['status'], 200, 'body io empty')

    def test_perl_application_body_io_file(self):
        self.load('body_io_file')

        self.assertEqual(self.get()['body'], 'body\n', 'body io file')

    @unittest.expectedFailure
    def test_perl_application_syntax_error(self):
        self.skip_alerts.extend([
            r'PSGI: Failed to parse script',
            r'process \d+ exited on signal'
        ])
        self.load('syntax_error')

        self.assertEqual(self.get()['status'], 500, 'syntax error')

    def test_perl_keepalive_body(self):
        self.load('variables')

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

    def test_perl_body_io_fake(self):
        self.load('body_io_fake')

        self.assertEqual(self.get()['body'], '21', 'body io fake')

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+IOFake getline\(\) \$\/ is \d+'),
            'body io fake $/ value')

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+IOFake close\(\) called'),
            'body io fake close')

if __name__ == '__main__':
    TestUnitPerlApplication.main()
