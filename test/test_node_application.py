import unittest
import unit

class TestUnitNodeApplication(unit.TestUnitApplicationNode):

    def setUpClass():
        u = unit.TestUnit().check_modules('node')

    def test_node_application_basic(self):
        self.load('basic')

        resp = self.get()
        self.assertEqual(resp['headers']['Content-Type'], 'text/plain',
            'basic header')
        self.assertEqual(resp['body'], 'Hello World\n', 'basic body')

    def test_node_application_seq(self):
        self.load('basic')

        self.assertEqual(self.get()['status'], 200, 'seq')
        self.assertEqual(self.get()['status'], 200, 'seq 2')

    def test_node_application_variables(self):
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

        date = headers.pop('Date')
        self.assertEqual(date[-4:], ' GMT', 'date header timezone')
        self.assertLess(abs(self.date_to_sec_epoch(date) - self.sec_epoch()), 5,
            'date header')

        raw_headers = headers.pop('Request-Raw-Headers')
        self.assertRegex(raw_headers, r'^(?:Host|localhost|Content-Type|' \
            'text\/html|Custom-Header|blah|Content-Length|17|Connection|' \
            'close|,)+$', 'raw headers')

        self.assertDictEqual(headers, {
            'Connection': 'close',
            'Content-Length': str(len(body)),
            'Content-Type': 'text/html',
            'Request-Method': 'POST',
            'Request-Uri': '/',
            'Http-Host': 'localhost',
            'Server-Protocol': 'HTTP/1.1',
            'Custom-Header': 'blah'
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_node_application_get_variables(self):
        self.load('get_variables')

        resp = self.get(url='/?var1=val1&var2=&var3')
        self.assertEqual(resp['headers']['X-Var-1'], 'val1', 'GET variables')
        self.assertEqual(resp['headers']['X-Var-2'], '', 'GET variables 2')
        self.assertEqual(resp['headers']['X-Var-3'], '', 'GET variables 3')

    def test_node_application_post_variables(self):
        self.load('post_variables')

        resp = self.post(headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'localhost',
            'Connection': 'close'
        }, body='var1=val1&var2=&var3')

        self.assertEqual(resp['headers']['X-Var-1'], 'val1', 'POST variables')
        self.assertEqual(resp['headers']['X-Var-2'], '', 'POST variables 2')
        self.assertEqual(resp['headers']['X-Var-3'], '', 'POST variables 3')

    def test_node_application_404(self):
        self.load('404')

        resp = self.get()

        self.assertEqual(resp['status'], 404, '404 status')
        self.assertRegex(resp['body'], r'<title>404 Not Found</title>',
            '404 body')

    def test_node_keepalive_body(self):
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

    def test_node_application_write_buffer(self):
        self.load('write_buffer')

        self.assertEqual(self.get()['body'], '6\r\nbuffer\r\n0\r\n\r\n',
            'write buffer')

    def test_node_application_write_callback(self):
        self.load('write_callback')

        self.assertEqual(self.get()['body'],
            '5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n', 'write callback order')
        self.assertTrue(self.waitforfiles(self.testdir + '/node/callback'),
            'write callback')

    def test_node_application_write_before_write_head(self):
        self.load('write_before_write_head')

        self.assertEqual(self.get()['status'], 200, 'write before writeHead')

    def test_node_application_double_end(self):
        self.load('double_end')

        self.assertEqual(self.get()['status'], 200, 'double end')
        self.assertEqual(self.get()['status'], 200, 'double end 2')

    def test_node_application_write_return(self):
        self.load('write_return')

        self.assertEqual(self.get()['body'],
            '4\r\nbody\r\n4\r\ntrue\r\n0\r\n\r\n', 'write return')

    def test_node_application_remove_header(self):
        self.load('remove_header')

        resp = self.get(headers={
            'Host': 'localhost',
            'X-Remove': 'X-Header',
            'Connection': 'close'
        })
        self.assertEqual(resp['headers']['Was-Header'], 'true', 'was header')
        self.assertEqual(resp['headers']['Has-Header'], 'false', 'has header')
        self.assertFalse('X-Header' in resp['headers'], 'remove header')

    def test_node_application_remove_header_nonexisting(self):
        self.load('remove_header')

        self.assertEqual(self.get(headers={
            'Host': 'localhost',
            'X-Remove': 'blah',
            'Connection': 'close'
        })['headers']['Has-Header'], 'true', 'remove header nonexisting')

    def test_node_application_update_header(self):
        self.load('update_header')

        self.assertEqual(self.get()['headers']['X-Header'], 'new',
            'update header')

    def test_node_application_set_header_array(self):
        self.load('set_header_array')

        self.assertListEqual(self.get()['headers']['Set-Cookie'],
            ['tc=one,two,three', 'tc=four,five,six'], 'set header array')

    @unittest.expectedFailure
    def test_node_application_status_message(self):
        self.load('status_message')

        self.assertRegex(self.get(raw_resp=True), r'200 blah', 'status message')

    def test_node_application_get_header_type(self):
        self.load('get_header_type')

        self.assertEqual(self.get()['headers']['X-Type'], 'number',
            'get header type')

    def test_node_application_header_name_case(self):
        self.load('header_name_case')

        headers = self.get()['headers']

        self.assertEqual(headers['X-HEADER'], '3', 'header value')
        self.assertNotIn('X-Header', headers, 'insensitive')
        self.assertNotIn('X-header', headers, 'insensitive 2')

    def test_node_application_promise_handler(self):
        self.load('promise_handler')

        self.assertEqual(self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Connection': 'close'
        }, body='callback')['status'], 200, 'promise handler request')
        self.assertTrue(self.waitforfiles(self.testdir + '/node/callback'),
            'promise handler')

    def test_node_application_promise_handler_write_after_end(self):
        self.load('promise_handler')

        self.assertEqual(self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'X-Write-Call': '1',
            'Connection': 'close'
        }, body='callback')['status'], 200,
            'promise handler request write after end')

    def test_node_application_promise_end(self):
        self.load('promise_end')

        self.assertEqual(self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Connection': 'close'
        }, body='end')['status'], 200, 'promise end request')
        self.assertTrue(self.waitforfiles(self.testdir + '/node/callback'),
            'promise end')

    def test_node_application_promise_multiple_calls(self):
        self.load('promise_handler')

        self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Connection': 'close'
        }, body='callback1')

        self.assertTrue(self.waitforfiles(self.testdir + '/node/callback1'),
            'promise first call')

        self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Connection': 'close'
        }, body='callback2')

        self.assertTrue(self.waitforfiles(self.testdir + '/node/callback2'),
            'promise second call')

    @unittest.expectedFailure
    def test_node_application_header_name_valid(self):
        self.load('header_name_valid')

        self.assertNotIn('status', self.get(), 'header name valid')

    def test_node_application_header_value_object(self):
        self.load('header_value_object')

        self.assertIn('X-Header', self.get()['headers'], 'header value object')

    def test_node_application_get_header_names(self):
        self.load('get_header_names')

        self.assertListEqual(self.get()['headers']['X-Names'],
            ['date', 'x-header'], 'get header names')

    def test_node_application_has_header(self):
        self.load('has_header')

        self.assertEqual(self.get(headers={
            'Host': 'localhost',
            'X-Header': 'length',
            'Connection': 'close'
        })['headers']['X-Has-Header'], 'false', 'has header length')

        self.assertEqual(self.get(headers={
            'Host': 'localhost',
            'X-Header': 'Date',
            'Connection': 'close'
        })['headers']['X-Has-Header'], 'false', 'has header date')

    def test_node_application_write_multiple(self):
        self.load('write_multiple')

        self.assertEqual(self.get()['body'], 'writewrite2end', 'write multiple')

if __name__ == '__main__':
    TestUnitNodeApplication.main()
