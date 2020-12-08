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
        self.app_name = "app-" + option.temp_dir.split('/')[-1]

        self.load('empty', self.app_name)

        assert 'success' in self.conf(
            '1', 'applications/' + self.app_name + '/processes'
        )

    def pid_by_name(self, name):
        output = subprocess.check_output(['ps', 'ax']).decode()
        m = re.search(r'\s*(\d+).*' + name, output)
        return m if m is None else m.group(1)

    def kill_pids(self, *pids):
        subprocess.call(['kill', '-9'] + list(pids))

    def wait_for_process(self, process):
        for i in range(50):
            found = self.pid_by_name(process)

            if found is not None:
                break

            time.sleep(0.1)

        return found

    def smoke_test(self):
        for _ in range(5):
            assert 'success' in self.conf(
                '1', 'applications/' + self.app_name + '/processes'
            )
            assert self.get()['status'] == 200

        # Check if the only one router, controller,
        # and application processes running.

        output = subprocess.check_output(['ps', 'ax']).decode()
        assert len(re.findall(self.PATTERN_ROUTER, output)) == 1
        assert len(re.findall(self.PATTERN_CONTROLLER, output)) == 1
        assert len(re.findall(self.app_name, output)) == 1

    def test_respawn_router(self, skip_alert):
        pid = self.pid_by_name(self.PATTERN_ROUTER)

        self.kill_pids(pid)
        skip_alert(r'process %s exited on signal 9' % pid)

        assert self.wait_for_process(self.PATTERN_ROUTER) is not None

        self.smoke_test()

    def test_respawn_controller(self, skip_alert):
        pid = self.pid_by_name(self.PATTERN_CONTROLLER)

        self.kill_pids(pid)
        skip_alert(r'process %s exited on signal 9' % pid)

        assert self.wait_for_process(self.PATTERN_CONTROLLER) is not None

        assert self.get()['status'] == 200

        self.smoke_test()

    def test_respawn_application(self, skip_alert):
        pid = self.pid_by_name(self.app_name)

        self.kill_pids(pid)
        skip_alert(r'process %s exited on signal 9' % pid)

        assert self.wait_for_process(self.app_name) is not None

        self.smoke_test()
