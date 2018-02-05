import unittest
import unit

class TestUnitApplication(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.5')

    @unittest.expectedFailure
    def test_python_keepalive_body(self):
        code, name = """

def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    start_response('200', [
        ('Content-Type', environ.get('CONTENT_TYPE')),
        ('Content-Length', str(len(body)))
    ])
    return [body]

""", 'py_app'

        self.python_application(name, code)

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": "app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

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
