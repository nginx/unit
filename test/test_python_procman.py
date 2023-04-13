import re
import shutil
import subprocess
import time

import pytest
from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestPythonProcman(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def setup_method(self):
        self.app_name = f'app-{option.temp_dir.split("/")[-1]}'
        self.app_proc = f'applications/{self.app_name}/processes'
        self.load('empty', self.app_name)

    def pids_for_process(self):
        time.sleep(0.2)

        output = subprocess.check_output(['ps', 'ax'])

        pids = set()
        for m in re.findall(
            fr'.*unit: "{self.app_name}" application', output.decode()
        ):
            pids.add(re.search(r'^\s*(\d+)', m).group(1))

        return pids

    def conf_proc(self, conf, path=None):
        if path is None:
            path = self.app_proc

        assert 'success' in self.conf(conf, path), 'configure processes'

    @pytest.mark.skip('not yet')
    def test_python_processes_idle_timeout_zero(self):
        self.conf_proc({"spare": 0, "max": 2, "idle_timeout": 0})

        self.get()
        assert len(self.pids_for_process()) == 0, 'idle timeout 0'

    def test_python_prefork(self):
        self.conf_proc('2')

        pids = self.pids_for_process()
        assert len(pids) == 2, 'prefork 2'

        self.get()
        assert self.pids_for_process() == pids, 'prefork still 2'

        self.conf_proc('4')

        pids = self.pids_for_process()
        assert len(pids) == 4, 'prefork 4'

        self.get()
        assert self.pids_for_process() == pids, 'prefork still 4'

        self.stop_all()

    @pytest.mark.skip('not yet')
    def test_python_prefork_same_processes(self):
        self.conf_proc('2')
        pids = self.pids_for_process()

        self.conf_proc('4')
        pids_new = self.pids_for_process()

        assert pids.issubset(pids_new), 'prefork same processes'

    def test_python_ondemand(self):
        self.conf_proc({"spare": 0, "max": 8, "idle_timeout": 1})

        assert len(self.pids_for_process()) == 0, 'on-demand 0'

        self.get()
        pids = self.pids_for_process()
        assert len(pids) == 1, 'on-demand 1'

        self.get()
        assert self.pids_for_process() == pids, 'on-demand still 1'

        time.sleep(1)

        assert len(self.pids_for_process()) == 0, 'on-demand stop idle'

        self.stop_all()

    def test_python_scale_updown(self):
        self.conf_proc({"spare": 2, "max": 8, "idle_timeout": 1})

        pids = self.pids_for_process()
        assert len(pids) == 2, 'updown 2'

        self.get()
        pids_new = self.pids_for_process()
        assert len(pids_new) == 3, 'updown 3'
        assert pids.issubset(pids_new), 'updown 3 only 1 new'

        self.get()
        assert self.pids_for_process() == pids_new, 'updown still 3'

        time.sleep(1)

        pids = self.pids_for_process()
        assert len(pids) == 2, 'updown stop idle'

        self.get()
        pids_new = self.pids_for_process()
        assert len(pids_new) == 3, 'updown again 3'
        assert pids.issubset(pids_new), 'updown again 3 only 1 new'

        self.stop_all()

    def test_python_reconfigure(self):
        self.conf_proc({"spare": 2, "max": 6, "idle_timeout": 1})

        pids = self.pids_for_process()
        assert len(pids) == 2, 'reconf 2'

        self.get()
        pids_new = self.pids_for_process()
        assert len(pids_new) == 3, 'reconf 3'
        assert pids.issubset(pids_new), 'reconf 3 only 1 new'

        self.conf_proc('6', f'{self.app_proc}/spare')

        pids = self.pids_for_process()
        assert len(pids) == 6, 'reconf 6'

        self.get()
        assert self.pids_for_process() == pids, 'reconf still 6'

        self.stop_all()

    def test_python_idle_timeout(self):
        self.conf_proc({"spare": 0, "max": 6, "idle_timeout": 2})

        self.get()
        pids = self.pids_for_process()
        assert len(pids) == 1, 'idle timeout 1'

        time.sleep(1)

        self.get()

        time.sleep(1)

        pids_new = self.pids_for_process()
        assert len(pids_new) == 1, 'idle timeout still 1'
        assert self.pids_for_process() == pids, 'idle timeout still 1 same pid'

        time.sleep(1)

        assert len(self.pids_for_process()) == 0, 'idle timed out'

    def test_python_processes_connection_keepalive(self):
        self.conf_proc({"spare": 0, "max": 6, "idle_timeout": 2})

        (resp, sock) = self.get(
            headers={'Host': 'localhost', 'Connection': 'keep-alive'},
            start=True,
            read_timeout=1,
        )
        assert len(self.pids_for_process()) == 1, 'keepalive connection 1'

        time.sleep(2)

        assert len(self.pids_for_process()) == 0, 'keepalive connection 0'

        sock.close()

    def test_python_processes_access(self):
        self.conf_proc('1')

        path = f'/{self.app_proc}'
        assert 'error' in self.conf_get(f'{path}/max')
        assert 'error' in self.conf_get(f'{path}/spare')
        assert 'error' in self.conf_get(f'{path}/idle_timeout')

    def test_python_processes_invalid(self):
        assert 'error' in self.conf(
            {"spare": -1}, self.app_proc
        ), 'negative spare'
        assert 'error' in self.conf({"max": -1}, self.app_proc), 'negative max'
        assert 'error' in self.conf(
            {"idle_timeout": -1}, self.app_proc
        ), 'negative idle_timeout'
        assert 'error' in self.conf(
            {"spare": 2}, self.app_proc
        ), 'spare gt max default'
        assert 'error' in self.conf(
            {"spare": 2, "max": 1}, self.app_proc
        ), 'spare gt max'
        assert 'error' in self.conf(
            {"spare": 0, "max": 0}, self.app_proc
        ), 'max zero'

    def stop_all(self):
        assert 'success' in self.conf({"listeners": {}, "applications": {}})

        assert len(self.pids_for_process()) == 0, 'stop all'

    def test_python_restart(self, temp_dir):
        shutil.copyfile(
            f'{option.test_dir}/python/restart/v1.py', f'{temp_dir}/wsgi.py'
        )

        self.load(
            temp_dir,
            name=self.app_name,
            processes=1,
            environment={'PYTHONDONTWRITEBYTECODE': '1'},
        )

        b = self.get()['body']
        assert b == "v1", 'process started'

        shutil.copyfile(
            f'{option.test_dir}/python/restart/v2.py', f'{temp_dir}/wsgi.py'
        )

        b = self.get()['body']
        assert b == "v1", 'still old process'

        assert 'success' in self.conf_get(
            f'/control/applications/{self.app_name}/restart'
        ), 'restart processes'

        b = self.get()['body']
        assert b == "v2", 'new process started'

        assert 'error' in self.conf_get(
            '/control/applications/blah/restart'
        ), 'application incorrect'

        assert 'error' in self.conf_delete(
            f'/control/applications/{self.app_name}/restart'
        ), 'method incorrect'

    def test_python_restart_multi(self):
        self.conf_proc('2')

        pids = self.pids_for_process()
        assert len(pids) == 2, 'restart 2 started'

        assert 'success' in self.conf_get(
            f'/control/applications/{self.app_name}/restart'
        ), 'restart processes'

        new_pids = self.pids_for_process()
        assert len(new_pids) == 2, 'restart still 2'

        assert len(new_pids.intersection(pids)) == 0, 'restart all new'

    def test_python_restart_longstart(self):
        self.load(
            'restart',
            name=self.app_name,
            module="longstart",
            processes={"spare": 1, "max": 2, "idle_timeout": 5},
        )

        assert len(self.pids_for_process()) == 1, 'longstarts == 1'

        self.get()

        pids = self.pids_for_process()
        assert len(pids) == 2, 'longstarts == 2'

        assert 'success' in self.conf_get(
            f'/control/applications/{self.app_name}/restart'
        ), 'restart processes'

        # wait for longstarted app
        time.sleep(2)

        new_pids = self.pids_for_process()
        assert len(new_pids) == 1, 'restart 1'

        assert len(new_pids.intersection(pids)) == 0, 'restart all new'
