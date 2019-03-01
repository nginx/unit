import unittest
import unit

class TestUnitGoApplication(unit.TestUnitApplicationGo):

    def setUpClass():
        unit.TestUnit().check_modules('go')

    def test_go_application_variables(self):
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

        self.assertDictEqual(headers, {
            'Content-Length': str(len(body)),
            'Content-Type': 'text/html',
            'Request-Method': 'POST',
            'Request-Uri': '/',
            'Http-Host': 'localhost',
            'Server-Protocol': 'HTTP/1.1',
            'Server-Protocol-Major': '1',
            'Server-Protocol-Minor': '1',
            'Custom-Header': 'blah',
            'Connection': 'close'
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_go_application_get_variables(self):
        self.load('get_variables')

        resp = self.get(url='/?var1=val1&var2=&var3')
        self.assertEqual(resp['headers']['X-Var-1'], 'val1', 'GET variables')
        self.assertEqual(resp['headers']['X-Var-2'], '', 'GET variables 2')
        self.assertEqual(resp['headers']['X-Var-3'], '', 'GET variables 3')

    def test_go_application_post_variables(self):
        self.load('post_variables')

        resp = self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'close'
        }, body='var1=val1&var2=&var3')

        self.assertEqual(resp['headers']['X-Var-1'], 'val1', 'POST variables')
        self.assertEqual(resp['headers']['X-Var-2'], '', 'POST variables 2')
        self.assertEqual(resp['headers']['X-Var-3'], '', 'POST variables 3')

    def test_go_application_404(self):
        self.load('404')

        resp = self.get()

        self.assertEqual(resp['status'], 404, '404 status')
        self.assertRegex(resp['body'], r'<title>404 Not Found</title>',
            '404 body')

    def test_go_keepalive_body(self):
        self.load('mirror')

        (resp, sock) = self.post(headers={
            'Host': 'localhost',
            'Connection': 'keep-alive',
            'Content-Type': 'text/html'
        }, start=True, body='0123456789' * 500)

        self.assertEqual(resp['body'], '0123456789' * 500, 'keep-alive 1')

        resp = self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Connection': 'close'
        }, sock=sock, body='0123456789')

        self.assertEqual(resp['body'], '0123456789', 'keep-alive 2')

    def test_go_application_cookies(self):
        self.load('cookies')

        resp = self.get(headers={
            'Host': 'localhost',
            'Cookie': 'var1=val1; var2=val2',
            'Connection': 'close'
        })

        self.assertEqual(resp['headers']['X-Cookie-1'], 'val1', 'cookie 1')
        self.assertEqual(resp['headers']['X-Cookie-2'], 'val2', 'cookie 2')

    def test_go_application_command_line_arguments_type(self):
        self.load('command_line_arguments')

        self.assertIn('error', self.conf(''"a b c",
            'applications/command_line_arguments/arguments'), 'arguments type')

    def test_go_application_command_line_arguments_0(self):
        self.load('command_line_arguments')

        self.assertEqual(self.get()['headers']['X-Arg-0'],
            self.conf_get('applications/command_line_arguments/executable'),
            'argument 0')

    def test_go_application_command_line_arguments(self):
        self.load('command_line_arguments')

        arg1 = '--cc=gcc-7.2.0'
        arg2 = '--cc-opt=\'-O0 -DNXT_DEBUG_MEMORY=1 -fsanitize=address\''
        arg3 = '--debug'

        self.conf('["' + arg1 + '", "' + arg2 + '", "' + arg3 + '"]',
            'applications/command_line_arguments/arguments')

        self.assertEqual(self.get()['body'], arg1 + ',' + arg2 + ',' + arg3,
            'arguments')

    def test_go_application_command_line_arguments_change(self):
        self.load('command_line_arguments')

        args_path = 'applications/command_line_arguments/arguments'

        self.conf('["0", "a", "$", ""]', args_path)

        self.assertEqual(self.get()['body'], '0,a,$,', 'arguments')

        self.conf('["-1", "b", "%"]', args_path)

        self.assertEqual(self.get()['body'], '-1,b,%', 'arguments change')

        self.conf('[]', args_path)

        self.assertEqual(self.get()['headers']['Content-Length'], '0',
            'arguments empty')

if __name__ == '__main__':
    TestUnitGoApplication.main()
