import unittest
import unit

class TestUnitPHPApplication(unit.TestUnitApplicationPHP):

    def setUpClass():
        unit.TestUnit().check_modules('php')

    def test_php_application_variables(self):
        self.load('variables')

        body = 'Test body string.'

        resp = self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Custom-Header': 'blah'
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

        if 'X-Powered-By' in headers:
            headers.pop('X-Powered-By')

        headers.pop('Content-type')
        self.assertDictEqual(headers, {
            'Content-Length': str(len(body)),
            'Request-Method': 'POST',
            'Request-Uri': '/',
            'Http-Host': 'localhost',
            'Server-Protocol': 'HTTP/1.1',
            'Custom-Header': 'blah'
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_php_application_phpinfo(self):
        self.load('phpinfo')

        resp = self.get()

        self.assertEqual(resp['status'], 200, 'status')
        self.assertNotEqual(resp['body'], '', 'body not empty')

    def test_php_application_404(self):
        self.load('404')

        resp = self.get()

        self.assertEqual(resp['status'], 404, '404 status')
        self.assertRegex(resp['body'], r'<title>404 Not Found</title>',
            '404 body')

    def test_php_application_keepalive_body(self):
        self.load('mirror')

        (resp, sock) = self.post(headers={
            'Connection': 'keep-alive',
            'Content-Type': 'text/html',
            'Host': 'localhost'
        }, start=True, body='0123456789' * 500)

        self.assertEqual(resp['body'], '0123456789' * 500, 'keep-alive 1')

        resp = self.post(headers={
            'Connection': 'close',
            'Content-Type': 'text/html',
            'Host': 'localhost'
        }, sock=sock, body='0123456789')

        self.assertEqual(resp['body'], '0123456789', 'keep-alive 2')

    def test_php_application_conditional(self):
        self.load('conditional')

        self.assertRegex(self.get()['body'], r'True', 'conditional true')
        self.assertRegex(self.post()['body'], r'False', 'conditional false')

    def test_php_application_get_variables(self):
        self.load('get_variables')

        resp = self.get(url='/?var1=val1&var2=&var3')
        self.assertEqual(resp['headers']['X-Var-1'], 'val1', 'GET variables')
        self.assertEqual(resp['headers']['X-Var-2'], '1', 'GET variables 2')
        self.assertEqual(resp['headers']['X-Var-3'], '1', 'GET variables 3')
        self.assertEqual(resp['headers']['X-Var-4'], '', 'GET variables 4')

    def test_php_application_post_variables(self):
        self.load('post_variables')

        resp = self.post(headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'localhost',
            'Connection': 'close'
        }, body='var1=val1&var2=')
        self.assertEqual(resp['headers']['X-Var-1'], 'val1', 'POST variables')
        self.assertEqual(resp['headers']['X-Var-2'], '1', 'POST variables 2')
        self.assertEqual(resp['headers']['X-Var-3'], '', 'POST variables 3')

    def test_php_application_cookies(self):
        self.load('cookies')

        resp = self.get(headers={
            'Cookie': 'var=val; var2=val2',
            'Host': 'localhost',
            'Connection': 'close'
        })

        self.assertEqual(resp['headers']['X-Cookie-1'], 'val', 'cookie')
        self.assertEqual(resp['headers']['X-Cookie-2'], 'val2', 'cookie')

    def test_php_application_ini_precision(self):
        self.load('ini_precision')

        self.assertNotEqual(self.get()['headers']['X-Precision'], '4',
            'ini value default')

        self.conf({"file": "php.ini"}, 'applications/ini_precision/options')

        self.assertEqual(self.get()['headers']['X-File'],
            self.current_dir + '/php/ini_precision/php.ini', 'ini file')
        self.assertEqual(self.get()['headers']['X-Precision'], '4', 'ini value')

    @unittest.expectedFailure
    def test_php_application_ini_admin_user(self):
        self.load('ini_precision')

        self.assertIn('error', self.conf({
            "user": { "precision": "4" },
            "admin": { "precision": "5" }
        }, 'applications/ini_precision/options'), 'ini admin user')

    def test_php_application_ini_admin(self):
        self.load('ini_precision')

        self.conf({
            "file": "php.ini",
            "admin": { "precision": "5" }
        }, 'applications/ini_precision/options')

        self.assertEqual(self.get()['headers']['X-Precision'], '5',
            'ini value admin')

    def test_php_application_ini_user(self):
        self.load('ini_precision')

        self.conf({
            "file": "php.ini",
            "user": { "precision": "5" }
        }, 'applications/ini_precision/options')

        self.assertEqual(self.get()['headers']['X-Precision'], '5',
            'ini value user')

    def test_php_application_ini_user_2(self):
        self.load('ini_precision')

        self.conf({"file": "php.ini"}, 'applications/ini_precision/options')

        self.assertEqual(self.get()['headers']['X-Precision'], '4',
            'ini user file')

        self.conf({ "precision": "5" },
            'applications/ini_precision/options/user')

        self.assertEqual(self.get()['headers']['X-Precision'], '5',
            'ini value user')

    def test_php_application_ini_set_admin(self):
        self.load('ini_precision')

        self.conf({"admin": { "precision": "5" }},
            'applications/ini_precision/options')

        self.assertEqual(self.get(url='/?precision=6')['headers']['X-Precision'],
            '5', 'ini set admin')

    def test_php_application_ini_set_user(self):
        self.load('ini_precision')

        self.conf({"user": { "precision": "5" }},
            'applications/ini_precision/options')

        self.assertEqual(self.get(url='/?precision=6')['headers']['X-Precision'],
            '6', 'ini set user')

    def test_php_application_ini_repeat(self):
        self.load('ini_precision')

        self.conf({"user": { "precision": "5" }},
            'applications/ini_precision/options')

        self.assertEqual(self.get()['headers']['X-Precision'], '5', 'ini value')

        self.assertEqual(self.get()['headers']['X-Precision'], '5',
            'ini value repeat')

if __name__ == '__main__':
    TestUnitPHPApplication.main()
