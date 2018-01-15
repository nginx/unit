import unittest
import unit

class TestUnitApplication(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.4')

    def test_python_application(self):
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
        ('Server-Port', environ.get('SERVER_PORT')),
        ('Server-Protocol', environ.get('SERVER_PROTOCOL')),
        ('Custom-Header', environ.get('HTTP_CUSTOM_HEADER'))
    ])
    return [body]

""", 'py_app'

        self.python_application(name, code)

        self.put('/', """
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
            """ % (self.testdir + '/' + name))

        body = 'Test body string.'

        r = unit.TestUnitHTTP.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Content-Length': str(len(body)),
            'Custom-Header': 'blah'
        }, body=body)

        self.assertEqual(r.status_code, 200, 'status')
        self.assertEqual(r.headers['Content-Length'], str(len(body)),
            'header content length')
        self.assertEqual(r.headers['Content-Type'], 'text/html',
            'header content type')
        self.assertEqual(r.headers['Request-Method'], 'POST',
            'header request method')
        self.assertEqual(r.headers['Request-Uri'], '/', 'header request uri')
        self.assertEqual(r.headers['Path-Info'], '/', 'header path info')
        self.assertEqual(r.headers['Http-Host'], 'localhost',
            'header http host')
        self.assertEqual(r.headers['Remote-Addr'], '127.0.0.1',
            'header remote addr')

        self.assertTry('assertEqual', 'header server port',
            r.headers['Server-Port'], '7080')

        self.assertEqual(r.headers['Server-Protocol'], 'HTTP/1.1',
            'header server protocol')
        self.assertEqual(r.headers['Custom-Header'], 'blah',
            'header custom header')
        self.assertEqual(r.content, str.encode(body), 'body')


if __name__ == '__main__':
    unittest.main()
