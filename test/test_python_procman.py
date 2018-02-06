import re
import time
import subprocess
import unittest
import unit

class TestUnitProcman(unit.TestUnitControl):

    def setUpClass():
        u = unit.TestUnit()

        u.check_modules('python')
        u.check_version('0.5')

    def pids_for_process(self, process=None):
        if process is None:
            process = self.app_name

        time.sleep(0.2)

        output = subprocess.check_output(['ps', 'ax'])

        pids = set()
        for m in re.findall('.*' + process, output.decode()):
            pids.add(re.search('^\s*(\d+)', m).group(1))

        return pids

    def setUp(self):
        super().setUp()

        code, name = """

def application(env, start_response):
    start_response('200', [('Content-Length', '0')])
    return []

""", 'py_app'

        self.app_name = "app-" + self.testdir.split('/')[-1]

        self.python_application(name, code)

        self.conf({
            "listeners": {
                "*:7080": {
                    "application": self.app_name
                }
            },
            "applications": {
                self.app_name: {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.testdir + '/' + name,
                    "module": "wsgi"
                }
            }
        })

    def test_python_prefork(self):
        self.conf('2', '/applications/' + self.app_name + '/processes')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'prefork 2')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'prefork still 2')

        self.conf('4', '/applications/' + self.app_name + '/processes')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 4, 'prefork 4')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'prefork still 4')

        self.stop_all()

    def test_python_ondemand(self):
        self.conf({
            "spare": 0,
            "max": 8,
            "idle_timeout": 1
        }, '/applications/' + self.app_name + '/processes')

        self.assertEqual(len(self.pids_for_process()), 0, 'on-demand 0')

        self.get()
        pids = self.pids_for_process()
        self.assertEqual(len(pids), 1, 'on-demand 1')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'on-demand still 1')

        time.sleep(1)

        self.assertEqual(len(self.pids_for_process()), 0, 'on-demand stop idle')

        self.stop_all()

    def test_python_scale_updown(self):
        self.conf({
            "spare": 2,
            "max": 8,
            "idle_timeout": 1
        }, '/applications/' + self.app_name + '/processes')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'updown 2')

        self.get()
        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 3, 'updown 3')
        self.assertTrue(pids.issubset(pids_new), 'updown 3 only 1 new')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids_new, 'updown still 3')

        time.sleep(1)

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'updown stop idle')

        self.get()
        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 3, 'updown again 3')
        self.assertTrue(pids.issubset(pids_new), 'updown again 3 only 1 new')

        self.stop_all()

    def test_python_reconfigure(self):
        self.conf({
            "spare": 2,
            "max": 6,
            "idle_timeout": 1
        }, '/applications/' + self.app_name + '/processes')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'reconf 2')

        self.get()
        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 3, 'reconf 3')
        self.assertTrue(pids.issubset(pids_new), 'reconf 3 only 1 new')

        self.conf('6', '/applications/' + self.app_name + '/processes/spare')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 6, 'reconf 6')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'reconf still 6')

        self.stop_all()

    def stop_all(self):
        self.conf({
            "listeners": {},
            "applications": {}
        })

        self.assertEqual(len(self.pids_for_process()), 0, 'stop all')

if __name__ == '__main__':
    unittest.main()
