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
            'Custom-Header': 'blah'
        }, body=body)

        self.assertEqual(resp['status'], 200, 'status')
        headers = resp['headers']
        self.assertRegex(headers.pop('Server'), r'Unit/[\d\.]+',
            'server header')

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
            'Custom-Header': 'blah'
        }, 'headers')
        self.assertEqual(resp['body'], body, 'body')

    def test_python_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        self.assertEqual(resp['headers']['Query-String'], 'var1=val1&var2=val2',
            'Query-String header')

    @unittest.expectedFailure
    def test_python_application_server_port(self):
        self.load('server_port')

        self.assertEqual(self.get()['headers']['Server-Port'], '7080',
            'Server-Port header')

    @unittest.expectedFailure
    def test_python_application_204_transfer_encoding(self):
        self.load('204_no_content')

        self.assertNotIn('Transfer-Encoding', self.get()['headers'],
            '204 header transfer encoding')

    def test_python_application_ctx_iter_atexit(self):
        self.skip_alerts.append(r'sendmsg.+failed')
        self.load('ctx_iter_atexit')

        resp = self.post(headers={
            'Connection': 'close',
            'Content-Type': 'text/html',
            'Host': 'localhost'
        }, body='0123456789')

        self.assertEqual(resp['status'], 200, 'ctx iter status')
        self.assertEqual(resp['body'], '0123456789', 'ctx iter body')

        self.conf({
            "listeners": {},
            "applications": {}
        })

        self.stop()

        self.assertIsNotNone(self.search_in_log(r'RuntimeError'),
            'ctx iter atexit')

if __name__ == '__main__':
    unittest.main()
