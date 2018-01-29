import os
import time
import unittest
import unit

class TestUnitApplication(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.3')

    def getWorkerCount(self):
        n = 0
        for f in os.listdir(self.testdir):
            if f.startswith('proctest.'):
                n += 1

        return n

    def getTestCode(self):
        return """
import atexit
import os

fname = "%s.%%d" %% os.getpid()

def remove_file():
    os.remove(fname)

atexit.register(remove_file)

open(fname, 'w')

def application(env, start_response):
    start_response('200 OK', [('Content-Type','text/html')])
    return [b'body']

""" % (self.testdir + '/proctest')


    def test_python_prefork(self):
        code, name = self.getTestCode(), 'py_app'

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
                    "processes": 2,
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

        self.assertEqual(self.getWorkerCount(), 2, 'python prefork 2 processes')

        self.get()
        self.assertEqual(self.getWorkerCount(), 2, 'python prefork, still 2')

        self.conf('4', '/applications/app/processes')

        time.sleep(0.2)

        self.assertEqual(self.getWorkerCount(), 4, 'python prefork 4 processes')

        self.get()
        self.assertEqual(self.getWorkerCount(), 4, 'python prefork, still 4')

        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 0, 'python stop all processes')

        time.sleep(2.2)


    def test_python_ondemand(self):
        code, name = self.getTestCode(), 'py_app'

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
                    "processes": {
                        "spare": 0,
                        "max": 8,
                        "idle_timeout": 2
                    },
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

        self.assertEqual(self.getWorkerCount(), 0, 'python on-demand')

        self.get()
        self.assertEqual(self.getWorkerCount(), 1, 'python start on-demand')

        self.get()
        self.assertEqual(self.getWorkerCount(), 1, 'python still 1')

        time.sleep(2.2)
        self.assertEqual(self.getWorkerCount(), 0, 'python stop idle')

        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 0, 'python stop all processes')

        time.sleep(2.2)

    def test_python_scale_updown(self):
        code, name = self.getTestCode(), 'py_app'

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
                    "processes": {
                        "spare": 2,
                        "max": 8,
                        "idle_timeout": 2
                    },
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

        self.assertEqual(self.getWorkerCount(), 2, 'python prefork 2')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 3, 'python keep 2 idle, 1 busy')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 3, 'python still 3')

        time.sleep(2.2)
        self.assertEqual(self.getWorkerCount(), 2, 'python stop idle')

        self.get()

        time.sleep(0.5)
        self.assertEqual(self.getWorkerCount(), 3, 'python keep 2 idle, 1 busy')

        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 0, 'python stop all processes')

        time.sleep(2.2)

    def test_python_reconfigure(self):
        code, name = self.getTestCode(), 'py_app'

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
                    "processes": {
                        "spare": 2,
                        "max": 6,
                        "idle_timeout": 2
                    },
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

        self.assertEqual(self.getWorkerCount(), 2, 'python prefork 2')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 3, 'python keep 2 idle, 1 busy')

        self.conf('6', '/applications/app/processes/spare')
        self.assertEqual(self.getWorkerCount(), 6, 'python prefork 6')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 6, 'python still 6')

        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)
        self.assertEqual(self.getWorkerCount(), 0, 'python stop all processes')

        time.sleep(2.2)

if __name__ == '__main__':
    unittest.main()
