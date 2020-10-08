import atexit
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from multiprocessing import Process

import pytest
from conftest import _check_alerts
from conftest import _print_log
from conftest import option
from conftest import public_dir
from conftest import waitforfiles


class TestUnit():
    @classmethod
    def setup_class(cls, complete_check=True):
        cls.available = option.available
        unit = TestUnit()

        unit._run()

        # read unit.log

        for i in range(50):
            with open(unit.temp_dir + '/unit.log', 'r') as f:
                log = f.read()
                m = re.search('controller started', log)

                if m is None:
                    time.sleep(0.1)
                else:
                    break

        if m is None:
            _print_log(path=unit.temp_dir + '/unit.log')
            exit("Unit is writing log too long")

        def check(available, prerequisites):
            missed = []

            # check modules

            if 'modules' in prerequisites:
                available_modules = list(available['modules'].keys())

                for module in prerequisites['modules']:
                    if module in available_modules:
                        continue

                    missed.append(module)

            if missed:
                pytest.skip('Unit has no ' + ', '.join(missed) + ' module(s)')

            # check features

            if 'features' in prerequisites:
                available_features = list(available['features'].keys())

                for feature in prerequisites['features']:
                    if feature in available_features:
                        continue

                    missed.append(feature)

            if missed:
                pytest.skip(', '.join(missed) + ' feature(s) not supported')

        def destroy():
            unit.stop()
            _check_alerts(log)
            shutil.rmtree(unit.temp_dir)

        def complete():
            destroy()
            check(cls.available, cls.prerequisites)

        if complete_check:
            complete()
        else:
            unit.complete = complete
            return unit

    def setup_method(self):
        self._run()

    def _run(self):
        build_dir = option.current_dir + '/build'
        self.unitd = build_dir + '/unitd'

        if not os.path.isfile(self.unitd):
            exit("Could not find unit")

        self.temp_dir = tempfile.mkdtemp(prefix='unit-test-')

        public_dir(self.temp_dir)

        if oct(stat.S_IMODE(os.stat(build_dir).st_mode)) != '0o777':
            public_dir(build_dir)

        os.mkdir(self.temp_dir + '/state')

        with open(self.temp_dir + '/unit.log', 'w') as log:
            self._p = subprocess.Popen(
                [
                    self.unitd,
                    '--no-daemon',
                    '--modules',  build_dir,
                    '--state',    self.temp_dir + '/state',
                    '--pid',      self.temp_dir + '/unit.pid',
                    '--log',      self.temp_dir + '/unit.log',
                    '--control',  'unix:' + self.temp_dir + '/control.unit.sock',
                    '--tmp',      self.temp_dir,
                ],
                stderr=log,
            )

        atexit.register(self.stop)

        if not waitforfiles(self.temp_dir + '/control.unit.sock'):
            _print_log(path=self.temp_dir + '/unit.log')
            exit("Could not start unit")

        self._started = True

    def teardown_method(self):
        self.stop()

        # check unit.log for alerts

        unit_log = self.temp_dir + '/unit.log'

        with open(unit_log, 'r', encoding='utf-8', errors='ignore') as f:
            _check_alerts(f.read())

        # remove unit.log

        if not option.save_log:
            shutil.rmtree(self.temp_dir)
        else:
            _print_log(path=self.temp_dir)

        assert self.stop_errors == [None, None], 'stop errors'

    def stop(self):
        if not self._started:
            return

        self.stop_errors = []

        self.stop_errors.append(self._stop())

        self.stop_errors.append(self.stop_processes())

        atexit.unregister(self.stop)

        self._started = False

    def _stop(self):
        if self._p.poll() is not None:
            return

        with self._p as p:
            p.send_signal(signal.SIGQUIT)

            try:
                retcode = p.wait(15)
                if retcode:
                    return 'Child process terminated with code ' + str(retcode)
            except:
                p.kill()
                return 'Could not terminate unit'

    def run_process(self, target, *args):
        if not hasattr(self, '_processes'):
            self._processes = []

        process = Process(target=target, args=args)
        process.start()

        self._processes.append(process)

    def stop_processes(self):
        if not hasattr(self, '_processes'):
            return

        fail = False
        for process in self._processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=15)

                if process.is_alive():
                    fail = True

        if fail:
            return 'Fail to stop process'
