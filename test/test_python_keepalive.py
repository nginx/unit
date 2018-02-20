import unittest
import unit

class TestUnitPythonKeepalive(unit.TestUnitApplicationPython):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_python_keepalive_body(self):
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

if __name__ == '__main__':
    unittest.main()
