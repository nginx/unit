import unittest
import unit

class TestUnitApplication(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.4')

    conf = """
        {
            "listeners": {
                "*:7080": {
                    "application": "app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "workers": 1,
                    "path": "%s",
                    "module": "wsgi"
                }
            }
        }
        """

    def test_python_application_simple(self):
        code, name = """

def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    start_response('200 OK', [
        ('Content-Type', environ.get('CONTENT_TYPE')),
        ('Content-Length', str(len(body))),
        ('Request-Method', environ.get('REQUEST_METHOD')),
        ('Request-Uri', environ.get('REQUEST_URI')),
        ('Path-Info', environ.get('PATH_INFO')),
        ('Http-Host', environ.get('HTTP_HOST')),
        ('Remote-Addr', environ.get('REMOTE_ADDR')),
        ('Server-Name', environ.get('SERVER_NAME')),
        ('Server-Protocol', environ.get('SERVER_PROTOCOL')),
        ('Custom-Header', environ.get('HTTP_CUSTOM_HEADER'))
    ])
    return [body]

""", 'py_app'

        self.python_application(name, code)
        self.put('/', self.conf % (self.testdir + '/' + name))

        body = 'Test body string.'

        r = unit.TestUnitHTTP.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Custom-Header': 'blah'
        }, data=body)

        self.assertEqual(r.status_code, 200, 'status')
        headers = dict(r.headers)
        self.assertRegex(headers.pop('Server'), r'unit/[\d\.]+',
            'server header')
        self.assertDictEqual(headers, {
            'Content-Length': str(len(body)),
            'Content-Type': 'text/html',
            'Request-Method': 'POST',
            'Request-Uri': '/',
            'Path-Info': '/',
            'Http-Host': 'localhost',
            'Server-Name': 'localhost',
            'Remote-Addr': '127.0.0.1',
            'Server-Protocol': 'HTTP/1.1',
            'Custom-Header': 'blah'
        }, 'headers')
        self.assertEqual(r.content, str.encode(body), 'body')

    @unittest.expectedFailure
    def test_python_application_server_port(self):
        code, name = """

def application(environ, start_response):

    start_response('200 OK', [
        ('Content-Type', 'text/html'),
        ('Server-Port', environ.get('SERVER_PORT'))
    ])
    return []

""", 'py_app'

        self.python_application(name, code)
        self.put('/', self.conf % (self.testdir + '/' + name))

        r = unit.TestUnitHTTP.get(headers={'Host': 'localhost'})

        self.assertEqual(r.headers.pop('Server-Port'), '7080',
            'Server-Port header')

    @unittest.expectedFailure
    def test_python_application_204_transfer_encoding(self):
        code, name = """

def application(environ, start_response):

    start_response('204 No Content', [])
    return []

""", 'py_app'

        self.python_application(name, code)
        self.put('/', self.conf % (self.testdir + '/' + name))

        r = unit.TestUnitHTTP.get(headers={'Host': 'localhost'})
        self.assertNotIn('Transfer-Encoding', r.headers,
            '204 header transfer encoding')

if __name__ == '__main__':
    unittest.main()
