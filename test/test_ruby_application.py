import unittest
import unit

class TestUnitRubyApplication(unit.TestUnitApplicationRuby):

    def setUpClass():
        unit.TestUnit().check_modules('ruby')

    def test_ruby_application(self):
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
            'Rack-Version': '13',
            'Rack-Url-Scheme': 'http',
            'Rack-Multithread': 'false',
            'Rack-Multiprocess': 'true',
            'Rack-Run-Once': 'false',
            'Rack-Hijack-Q': 'false',
            'Rack-Hijack': '',
            'Rack-Hijack-IO': ''
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_ruby_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        self.assertEqual(resp['headers']['Query-String'], 'var1=val1&var2=val2',
            'Query-String header')

    def test_ruby_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        self.assertEqual(resp['status'], 200, 'query string empty status')
        self.assertEqual(resp['headers']['Query-String'], '',
            'query string empty')

    @unittest.expectedFailure
    def test_ruby_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        self.assertEqual(resp['status'], 200, 'query string absent status')
        self.assertEqual(resp['headers']['Query-String'], '',
            'query string absent')

    @unittest.expectedFailure
    def test_ruby_application_server_port(self):
        self.load('server_port')

        self.assertEqual(self.get()['headers']['Server-Port'], '7080',
            'Server-Port header')

    def test_ruby_application_status_int(self):
        self.load('status_int')

        self.assertEqual(self.get()['status'], 200, 'status int')

    def test_ruby_application_input_read_empty(self):
        self.load('input_read_empty')

        self.assertEqual(self.get()['body'], '', 'read empty')

    def test_ruby_application_input_read_parts(self):
        self.load('input_read_parts')

        self.assertEqual(self.post(body='0123456789')['body'], '012345678',
            'input read parts')

    def test_ruby_application_input_read_buffer(self):
        self.load('input_read_buffer')

        self.assertEqual(self.post(body='0123456789')['body'], '0123456789',
            'input read buffer')

    def test_ruby_application_input_read_buffer_not_empty(self):
        self.load('input_read_buffer_not_empty')

        self.assertEqual(self.post(body='0123456789')['body'], '0123456789',
            'input read buffer not empty')

    def test_ruby_application_input_gets(self):
        self.load('input_gets')

        body = '0123456789'

        self.assertEqual(self.post(body=body)['body'], body, 'input gets')

    def test_ruby_application_input_gets_2(self):
        self.load('input_gets')

        self.assertEqual(self.post(body='01234\n56789\n')['body'], '01234\n',
            'input gets 2')

    def test_ruby_application_input_gets_all(self):
        self.load('input_gets_all')

        body = '\n01234\n56789\n\n'

        self.assertEqual(self.post(body=body)['body'], body, 'input gets all')

    def test_ruby_application_input_each(self):
        self.load('input_each')

        body = '\n01234\n56789\n\n'

        self.assertEqual(self.post(body=body)['body'], body, 'input each')

    @unittest.expectedFailure
    def test_ruby_application_input_rewind(self):
        self.load('input_rewind')

        body = '0123456789'

        self.assertEqual(self.post(body=body)['body'], body, 'input rewind')

    @unittest.expectedFailure
    def test_ruby_application_syntax_error(self):
        self.skip_alerts.extend([
            r'Failed to parse rack script',
            r'syntax error',
            r'new_from_string',
            r'parse_file'
        ])
        self.load('syntax_error')

        self.assertEqual(self.get()['status'], 500, 'syntax error')

    def test_ruby_application_errors_puts(self):
        self.load('errors_puts')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+Error in application'),
            'errors puts')

    def test_ruby_application_errors_puts_int(self):
        self.load('errors_puts_int')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+1234567890'),
            'errors puts int')

    def test_ruby_application_errors_write(self):
        self.load('errors_write')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+Error in application'),
            'errors write')

    def test_ruby_application_errors_write_to_s_custom(self):
        self.load('errors_write_to_s_custom')

        self.assertEqual(self.get()['status'], 200,
            'errors write to_s custom')

    def test_ruby_application_errors_write_int(self):
        self.load('errors_write_int')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+1234567890'),
            'errors write int')

    def test_ruby_application_at_exit(self):
        self.load('at_exit')

        self.get()

        self.conf({
            "listeners": {},
            "applications": {}
        })

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+At exit called\.'), 'at exit')

    def test_ruby_application_header_custom(self):
        self.load('header_custom')

        resp = self.post(body="\ntc=one,two\ntc=three,four,\n\n")

        self.assertEqual(resp['headers']['Custom-Header'],
            ['', 'tc=one,two', 'tc=three,four,', '', ''], 'header custom')

    @unittest.expectedFailure
    def test_ruby_application_header_custom_non_printable(self):
        self.load('header_custom')

        self.assertEqual(self.post(body='\b')['status'], 500,
            'header custom non printable')

    def test_ruby_application_header_status(self):
        self.load('header_status')

        self.assertEqual(self.get()['status'], 200, 'header status')

    @unittest.expectedFailure
    def test_ruby_application_header_rack(self):
        self.load('header_rack')

        self.assertEqual(self.get()['status'], 500, 'header rack')

    def test_ruby_application_body_empty(self):
        self.load('body_empty')

        self.assertEqual(self.get()['body'], '0\r\n\r\n', 'body empty')

    def test_ruby_application_body_array(self):
        self.load('body_array')

        self.assertEqual(self.get()['body'], '0123456789', 'body array')

    def test_ruby_application_body_large(self):
        self.load('mirror')

        body = '0123456789' * 1000

        self.assertEqual(self.post(body=body)['body'], body, 'body large')

    @unittest.expectedFailure
    def test_ruby_application_body_each_error(self):
        self.load('body_each_error')

        self.assertEqual(self.get()['status'], 500, 'body each error status')

        self.stop()

        self.assertIsNotNone(
            self.search_in_log(r'\[error\].+Failed to run ruby script'),
            'body each error')

    def test_ruby_application_body_file(self):
        self.load('body_file')

        self.assertEqual(self.get()['body'], 'body\n', 'body file')

    def test_ruby_keepalive_body(self):
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

if __name__ == '__main__':
    TestUnitRubyApplication.main()
