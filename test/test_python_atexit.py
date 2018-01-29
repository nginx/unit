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
    start_response('200', [('Content-Length', '0')])
    return []

""" % (self.testdir + '/atexit'), 'py_app'

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

        self.get()

        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)   # wait for 'atexit' file

        self.assertEqual(os.path.exists(self.testdir + '/atexit'), True,
            'python atexit')


if __name__ == '__main__':
    unittest.main()
