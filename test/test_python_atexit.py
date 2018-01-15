import os
import time
import unittest
import unit

class TestUnitApplication(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.3')

    def test_python_application(self):
        code, name = """
import atexit

def create_file():
    open('%s', 'w')

atexit.register(create_file)

def application(env, start_response):
    start_response('200 OK', [('Content-Type','text/html')])
    return [b'body']

""" % (self.testdir + '/atexit'), 'py_app'

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

        unit.TestUnitHTTP.get()

        self.put('/', """
            {
                "listeners": {},
                "applications": {}
            }
            """)

        time.sleep(0.2)

        self.assertEqual(os.path.exists(self.testdir + '/atexit'), True,
            'python atexit')


if __name__ == '__main__':
    unittest.main()
