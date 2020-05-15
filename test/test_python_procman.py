import re
import subprocess
import time
import unittest

from unit.applications.lang.python import TestApplicationPython


class TestPythonProcman(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def setUp(self):
        super().setUp()

        self.app_name = "app-" + self.testdir.split('/')[-1]
        self.app_proc = 'applications/' + self.app_name + '/processes'
        self.load('empty', self.app_name)

    def pids_for_process(self):
        time.sleep(0.2)

        output = subprocess.check_output(['ps', 'ax'])

        pids = set()
        for m in re.findall('.*' + self.app_name, output.decode()):
            pids.add(re.search('^\s*(\d+)', m).group(1))

        return pids

    def conf_proc(self, conf, path=None):
        if path is None:
            path = self.app_proc

        self.assertIn('success', self.conf(conf, path), 'configure processes')

    def test_python_processes_idle_timeout_zero(self):
        self.conf_proc({"spare": 0, "max": 2, "idle_timeout": 0})

        self.get()
        self.assertEqual(len(self.pids_for_process()), 0, 'idle timeout 0')

    def test_python_prefork(self):
        self.conf_proc('2')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'prefork 2')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'prefork still 2')

        self.conf_proc('4')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 4, 'prefork 4')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'prefork still 4')

        self.stop_all()

    @unittest.skip('not yet')
    def test_python_prefork_same_processes(self):
        self.conf_proc('2')
        pids = self.pids_for_process()

        self.conf_proc('4')
        pids_new = self.pids_for_process()

        self.assertTrue(pids.issubset(pids_new), 'prefork same processes')

    def test_python_ondemand(self):
        self.conf_proc({"spare": 0, "max": 8, "idle_timeout": 1})

        self.assertEqual(len(self.pids_for_process()), 0, 'on-demand 0')

        self.get()
        pids = self.pids_for_process()
        self.assertEqual(len(pids), 1, 'on-demand 1')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'on-demand still 1')

        time.sleep(1)

        self.assertEqual(
            len(self.pids_for_process()), 0, 'on-demand stop idle'
        )

        self.stop_all()

    def test_python_scale_updown(self):
        self.conf_proc({"spare": 2, "max": 8, "idle_timeout": 1})

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'updown 2')

        self.get()
        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 3, 'updown 3')
        self.assertTrue(pids.issubset(pids_new), 'updown 3 only 1 new')

        self.get()
        self.assertSetEqual(
            self.pids_for_process(), pids_new, 'updown still 3'
        )

        time.sleep(1)

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'updown stop idle')

        self.get()
        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 3, 'updown again 3')
        self.assertTrue(pids.issubset(pids_new), 'updown again 3 only 1 new')

        self.stop_all()

    def test_python_reconfigure(self):
        self.conf_proc({"spare": 2, "max": 6, "idle_timeout": 1})

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 2, 'reconf 2')

        self.get()
        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 3, 'reconf 3')
        self.assertTrue(pids.issubset(pids_new), 'reconf 3 only 1 new')

        self.conf_proc('6', self.app_proc + '/spare')

        pids = self.pids_for_process()
        self.assertEqual(len(pids), 6, 'reconf 6')

        self.get()
        self.assertSetEqual(self.pids_for_process(), pids, 'reconf still 6')

        self.stop_all()

    def test_python_idle_timeout(self):
        self.conf_proc({"spare": 0, "max": 6, "idle_timeout": 2})

        self.get()
        pids = self.pids_for_process()
        self.assertEqual(len(pids), 1, 'idle timeout 1')

        time.sleep(1)

        self.get()

        time.sleep(1)

        pids_new = self.pids_for_process()
        self.assertEqual(len(pids_new), 1, 'idle timeout still 1')
        self.assertSetEqual(
            self.pids_for_process(), pids, 'idle timeout still 1 same pid'
        )

        time.sleep(1)

        self.assertEqual(len(self.pids_for_process()), 0, 'idle timed out')

    def test_python_processes_connection_keepalive(self):
        self.conf_proc({"spare": 0, "max": 6, "idle_timeout": 2})

        (resp, sock) = self.get(
            headers={'Host': 'localhost', 'Connection': 'keep-alive'},
            start=True,
            read_timeout=1,
        )
        self.assertEqual(
            len(self.pids_for_process()), 1, 'keepalive connection 1'
        )

        time.sleep(2)

        self.assertEqual(
            len(self.pids_for_process()), 0, 'keepalive connection 0'
        )

        sock.close()

    def test_python_processes_access(self):
        self.conf_proc('1')

        path = '/' + self.app_proc
        self.assertIn('error', self.conf_get(path + '/max'))
        self.assertIn('error', self.conf_get(path + '/spare'))
        self.assertIn('error', self.conf_get(path + '/idle_timeout'))

    def test_python_processes_invalid(self):
        self.assertIn(
            'error', self.conf({"spare": -1}, self.app_proc), 'negative spare',
        )
        self.assertIn(
            'error', self.conf({"max": -1}, self.app_proc), 'negative max',
        )
        self.assertIn(
            'error',
            self.conf({"idle_timeout": -1}, self.app_proc),
            'negative idle_timeout',
        )
        self.assertIn(
            'error',
            self.conf({"spare": 2}, self.app_proc),
            'spare gt max default',
        )
        self.assertIn(
            'error',
            self.conf({"spare": 2, "max": 1}, self.app_proc),
            'spare gt max',
        )
        self.assertIn(
            'error',
            self.conf({"spare": 0, "max": 0}, self.app_proc),
            'max zero',
        )

    def stop_all(self):
        self.conf({"listeners": {}, "applications": {}})

        self.assertEqual(len(self.pids_for_process()), 0, 'stop all')


if __name__ == '__main__':
    TestPythonProcman.main()
