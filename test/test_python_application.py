import unittest
import unit

class TestUnitApplication(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.4')

    def conf_with_name(self, name):
        self.conf({
            "listeners": {
                "*:7080": {
                    "application": "app"
                }
            },
            "applications": {
                "app": {
                    "type": "python",
                    "workers": 1,
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

    def test_python_application_simple(self):
        code, name = """

def application(environ, start_response):

    content_length = int(environ.get('CONTENT_LENGTH', 0))
    body = bytes(environ['wsgi.input'].read(content_length))

    start_response('200', [
        ('Content-Type', environ.get('CONTENT_TYPE')),
        ('Content-Length', str(len(body))),
        ('Request-Method', environ.get('REQUEST_METHOD')),
        ('Request-Uri', environ.get('REQUEST_URI')),
        ('Http-Host', environ.get('HTTP_HOST')),
        ('Server-Protocol', environ.get('SERVER_PROTOCOL')),
        ('Custom-Header', environ.get('HTTP_CUSTOM_HEADER'))
    ])
    return [body]

""", 'py_app'

        self.python_application(name, code)
        self.conf_with_name(name)

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
            'Http-Host': 'localhost',
            'Server-Protocol': 'HTTP/1.1',
            'Custom-Header': 'blah'
        }, 'headers')
        self.assertEqual(r.content, body.encode(), 'body')

    def test_python_application_query_string(self):
        code, name = """

def application(environ, start_response):

    start_response('200', [
        ('Content-Length', '0'),
        ('Query-String', environ.get('QUERY_STRING'))
    ])
    return []

""", 'py_app'

        self.python_application(name, code)
        self.conf_with_name(name)

        r = unit.TestUnitHTTP.get(uri='/?var1=val1&var2=val2', headers={
            'Host': 'localhost'
        })

        self.assertEqual(r.status_code, 200, 'status')
        headers = dict(r.headers)
        headers.pop('Server')
        self.assertDictEqual(headers, {
            'Content-Length': '0',
            'Query-String': 'var1=val1&var2=val2'
        }, 'headers')

    @unittest.expectedFailure
    def test_python_application_server_port(self):
        code, name = """

def application(environ, start_response):

    start_response('200', [
        ('Content-Length', '0'),
        ('Server-Port', environ.get('SERVER_PORT'))
    ])
    return []

""", 'py_app'

        self.python_application(name, code)
        self.conf_with_name(name)

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
        self.conf_with_name(name)

        r = unit.TestUnitHTTP.get(headers={'Host': 'localhost'})
        self.assertNotIn('Transfer-Encoding', r.headers,
            '204 header transfer encoding')

if __name__ == '__main__':
    unittest.main()
