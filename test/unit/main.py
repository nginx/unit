import os
import re
import sys
import time
import fcntl
import shutil
import argparse
import platform
import tempfile
import unittest
import subprocess
from multiprocessing import Process


class TestUnit(unittest.TestCase):

    current_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir)
    )
    pardir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
    )
    architecture = platform.architecture()[0]
    system = platform.system()
    maxDiff = None

    detailed = False
    save_log = False
    unsafe = False

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

        if re.match(r'.*\/run\.py$', sys.argv[0]):
            args, rest = TestUnit._parse_args()

            TestUnit._set_args(args)

    def run(self, result=None):
        if not hasattr(self, 'application_type'):
            return super().run(result)

        # rerun test for each available module version

        type = self.application_type
        for module in self.prerequisites['modules']:
            if module in self.available['modules']:
                for version in self.available['modules'][module]:
                    self.application_type = type + ' ' + version
                    super().run(result)

    @classmethod
    def main(cls):
        args, rest = TestUnit._parse_args()

        for i, arg in enumerate(rest):
            if arg[:5] == 'test_':
                rest[i] = cls.__name__ + '.' + arg

        sys.argv = sys.argv[:1] + rest

        TestUnit._set_args(args)

        unittest.main()

    @classmethod
    def setUpClass(cls, complete_check=True):
        cls.available = {'modules': {}, 'features': {}}
        unit = TestUnit()

        unit._run()

        # read unit.log

        for i in range(50):
            with open(unit.testdir + '/unit.log', 'r') as f:
                log = f.read()
                m = re.search('controller started', log)

                if m is None:
                    time.sleep(0.1)
                else:
                    break

        if m is None:
            unit.stop()
            exit("Unit is writing log too long")

        # discover available modules from unit.log

        for module in re.findall(r'module: ([a-zA-Z]+) (.*) ".*"$', log, re.M):
            if module[0] not in cls.available['modules']:
                cls.available['modules'][module[0]] = [module[1]]
            else:
                cls.available['modules'][module[0]].append(module[1])

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
                print('Unit has no ' + ', '.join(missed) + ' module(s)')
                raise unittest.SkipTest()

            # check features

            if 'features' in prerequisites:
                available_features = list(available['features'].keys())

                for feature in prerequisites['features']:
                    if feature in available_features:
                        continue

                    missed.append(feature)

            if missed:
                print(', '.join(missed) + ' feature(s) not supported')
                raise unittest.SkipTest()

        def destroy():
            unit.stop()
            unit._check_alerts(log)
            shutil.rmtree(unit.testdir)

        def complete():
            destroy()
            check(cls.available, cls.prerequisites)

        if complete_check:
            complete()
        else:
            unit.complete = complete
            return unit

    def setUp(self):
        self._run()

    def tearDown(self):
        self.stop()

        # detect errors and failures for current test

        def list2reason(exc_list):
            if exc_list and exc_list[-1][0] is self:
                return exc_list[-1][1]

        if hasattr(self, '_outcome'):
            result = self.defaultTestResult()
            self._feedErrorsToResult(result, self._outcome.errors)
        else:
            result = getattr(
                self, '_outcomeForDoCleanups', self._resultForDoCleanups
            )

        success = not list2reason(result.errors) and not list2reason(
            result.failures
        )

        # check unit.log for alerts

        unit_log = self.testdir + '/unit.log'

        with open(unit_log, 'r', encoding='utf-8', errors='ignore') as f:
            self._check_alerts(f.read())

        # remove unit.log

        if not TestUnit.save_log and success:
            shutil.rmtree(self.testdir)

        else:
            self._print_path_to_log()

    def stop(self):
        if self._started:
            self._stop()

    def _run(self):
        self.unitd = self.pardir + '/build/unitd'

        if not os.path.isfile(self.unitd):
            exit("Could not find unit")

        self.testdir = tempfile.mkdtemp(prefix='unit-test-')

        os.mkdir(self.testdir + '/state')

        print()

        def _run_unit():
            subprocess.call(
                [
                    self.unitd,
                    '--no-daemon',
                    '--modules',  self.pardir + '/build',
                    '--state',    self.testdir + '/state',
                    '--pid',      self.testdir + '/unit.pid',
                    '--log',      self.testdir + '/unit.log',
                    '--control',  'unix:' + self.testdir + '/control.unit.sock',
                ]
            )

        self._p = Process(target=_run_unit)
        self._p.start()

        if not self.waitforfiles(
            self.testdir + '/unit.pid',
            self.testdir + '/unit.log',
            self.testdir + '/control.unit.sock',
        ):
            exit("Could not start unit")

        self._started = True

        self.skip_alerts = [
            r'read signalfd\(4\) failed',
            r'sendmsg.+failed',
            r'recvmsg.+failed',
        ]
        self.skip_sanitizer = False

    def _stop(self):
        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        subprocess.call(['kill', '-s', 'QUIT', pid])

        for i in range(150):
            if not os.path.exists(self.testdir + '/unit.pid'):
                break
            time.sleep(0.1)

        self._p.join(timeout=5)

        if self._p.is_alive():
            self._p.terminate()
            self._p.join(timeout=5)

        if self._p.is_alive():
            self.fail("Could not terminate process " + str(self._p.pid))

        if os.path.exists(self.testdir + '/unit.pid'):
            self.fail("Could not terminate unit")

        self._started = False

        if self._p.exitcode:
            self.fail(
                "Child process terminated with code " + str(self._p.exitcode)
            )

    def _check_alerts(self, log):
        found = False

        alerts = re.findall('.+\[alert\].+', log)

        if alerts:
            print('All alerts/sanitizer errors found in log:')
            [print(alert) for alert in alerts]
            found = True

        if self.skip_alerts:
            for skip in self.skip_alerts:
                alerts = [al for al in alerts if re.search(skip, al) is None]

        if alerts:
            self._print_path_to_log()
            self.assertFalse(alerts, 'alert(s)')

        if not self.skip_sanitizer:
            sanitizer_errors = re.findall('.+Sanitizer.+', log)

            if sanitizer_errors:
                self._print_path_to_log()
                self.assertFalse(sanitizer_errors, 'sanitizer error(s)')

        if found:
            print('skipped.')

    def waitforfiles(self, *files):
        for i in range(50):
            wait = False
            ret = False

            for f in files:
                if not os.path.exists(f):
                    wait = True
                    break

            if wait:
                time.sleep(0.1)

            else:
                ret = True
                break

        return ret

    @staticmethod
    def _parse_args():
        parser = argparse.ArgumentParser(add_help=False)

        parser.add_argument(
            '-d',
            '--detailed',
            dest='detailed',
            action='store_true',
            help='Detailed output for tests',
        )
        parser.add_argument(
            '-l',
            '--log',
            dest='save_log',
            action='store_true',
            help='Save unit.log after the test execution',
        )
        parser.add_argument(
            '-u',
            '--unsafe',
            dest='unsafe',
            action='store_true',
            help='Run unsafe tests',
        )

        return parser.parse_known_args()

    @staticmethod
    def _set_args(args):
        TestUnit.detailed = args.detailed
        TestUnit.save_log = args.save_log
        TestUnit.unsafe = args.unsafe

        # set stdout to non-blocking

        if TestUnit.detailed:
            fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, 0)

    def _print_path_to_log(self):
        print('Path to unit.log:\n' + self.testdir + '/unit.log')
