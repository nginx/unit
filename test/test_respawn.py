import re
import subprocess
import time

from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestRespawn(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    PATTERN_ROUTER = 'unit: router'
    PATTERN_CONTROLLER = 'unit: controller'

    def setup_method(self):
        self.app_name = f'app-{option.temp_dir.split("/")[-1]}'

        self.load('empty', self.app_name)

        assert 'success' in self.conf(
            '1', f'applications/{self.app_name}/processes'
        )

    def pid_by_name(self, name, ppid):
        output = subprocess.check_output(['ps', 'ax', '-O', 'ppid']).decode()
        m = re.search(fr'\s*(\d+)\s*{ppid}.*{name}', output)
        return None if m is None else m.group(1)

    def kill_pids(self, *pids):
        subprocess.call(['kill', '-9', *pids])

    def wait_for_process(self, process, unit_pid):
        for i in range(50):
            found = self.pid_by_name(process, unit_pid)

            if found is not None:
                break

            time.sleep(0.1)

        return found

    def find_proc(self, name, ppid, ps_output):
        return re.findall(fr'{ppid}.*{name}', ps_output)

    def smoke_test(self, unit_pid):
        for _ in range(10):
            r = self.conf('1', f'applications/{self.app_name}/processes')

            if 'success' in r:
                break

            time.sleep(0.1)

        assert 'success' in r
        assert self.get()['status'] == 200

        # Check if the only one router, controller,
        # and application processes running.

        out = subprocess.check_output(['ps', 'ax', '-O', 'ppid']).decode()
        assert len(self.find_proc(self.PATTERN_ROUTER, unit_pid, out)) == 1
        assert len(self.find_proc(self.PATTERN_CONTROLLER, unit_pid, out)) == 1
        assert len(self.find_proc(self.app_name, unit_pid, out)) == 1

    def test_respawn_router(self, skip_alert, unit_pid, skip_fds_check):
        skip_fds_check(router=True)
        pid = self.pid_by_name(self.PATTERN_ROUTER, unit_pid)

        self.kill_pids(pid)
        skip_alert(fr'process {pid} exited on signal 9')

        assert self.wait_for_process(self.PATTERN_ROUTER, unit_pid) is not None

        self.smoke_test(unit_pid)

    def test_respawn_controller(self, skip_alert, unit_pid, skip_fds_check):
        skip_fds_check(controller=True)
        pid = self.pid_by_name(self.PATTERN_CONTROLLER, unit_pid)

        self.kill_pids(pid)
        skip_alert(fr'process {pid} exited on signal 9')

        assert (
            self.wait_for_process(self.PATTERN_CONTROLLER, unit_pid) is not None
        )

        assert self.get()['status'] == 200

        self.smoke_test(unit_pid)

    def test_respawn_application(self, skip_alert, unit_pid):
        pid = self.pid_by_name(self.app_name, unit_pid)

        self.kill_pids(pid)
        skip_alert(fr'process {pid} exited on signal 9')

        assert self.wait_for_process(self.app_name, unit_pid) is not None

        self.smoke_test(unit_pid)
