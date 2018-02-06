import os
import time
import unittest
import unit

class TestUnitProcman(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.5')

    def count_processes(self):
        n = 0
        for f in os.listdir(self.testdir):
            if f.startswith('proctest.'):
                n += 1

        return n

    def app_code(self):
        return """
import atexit
import os

fname = "%s.%%d" %% os.getpid()

def remove_file():
    os.remove(fname)

atexit.register(remove_file)

open(fname, 'w')

def application(env, start_response):
    start_response('200', [('Content-Length', '0')])
    return []

""" % (self.testdir + '/proctest')


    def test_python_prefork(self):
        code, name = self.app_code(), 'py_app'

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

        self.assertEqual(self.count_processes(), 2, 'prefork 2')

        self.get()
        self.assertEqual(self.count_processes(), 2, 'prefork still 2')

        self.conf('4', '/applications/app/processes')

        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 4, 'prefork 4')

        self.get()
        self.assertEqual(self.count_processes(), 4, 'prefork still 4')

        self.stop_all()

    def test_python_ondemand(self):
        code, name = self.app_code(), 'py_app'

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

        self.assertEqual(self.count_processes(), 0, 'on-demand 0')

        self.get()
        self.assertEqual(self.count_processes(), 1, 'on-demand 1')

        self.get()
        self.assertEqual(self.count_processes(), 1, 'on-demand still 1')

        time.sleep(2.2)
        self.assertEqual(self.count_processes(), 0, 'on-demand stop idle')

        self.stop_all()

    def test_python_scale_updown(self):
        code, name = self.app_code(), 'py_app'

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

        self.assertEqual(self.count_processes(), 2, 'updown idle 2')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 3, 'updown idle 2, busy 1')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 3, 'updown still 3')

        time.sleep(2.2)
        self.assertEqual(self.count_processes(), 2, 'updown stop idle')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 3, 'updown idle 2, busy 1')

        self.stop_all()

    def test_python_reconfigure(self):
        code, name = self.app_code(), 'py_app'

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

        self.assertEqual(self.count_processes(), 2, 'reconf idle 2')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 3, 'reconf idle 2, busy 1')

        self.conf('6', '/applications/app/processes/spare')

        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 6, 'reconf idle 6')

        self.get()
        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 6, 'reconf still 6')

        self.stop_all()

    def stop_all(self):
        self.conf({
            "listeners": {},
            "applications": {}
        })

        time.sleep(0.2)
        self.assertEqual(self.count_processes(), 0, 'stop all')

if __name__ == '__main__':
    unittest.main()
