import os
import re
import sys
import time
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
    maxDiff = None

    detailed = False
    save_log = False

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)

        if re.match(r'.*\/run\.py$', sys.argv[0]):
            args, rest = TestUnit._parse_args()

            TestUnit._set_args(args)

    @classmethod
    def main(cls):
        args, rest = TestUnit._parse_args()

        for i, arg in enumerate(rest):
            if arg[:5] == 'test_':
                rest[i] = cls.__name__ + '.' + arg

        sys.argv = sys.argv[:1] + rest

        TestUnit._set_args(args)

        unittest.main()

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

    def check_modules(self, *modules):
        self._run()

        for i in range(50):
            with open(self.testdir + '/unit.log', 'r') as f:
                log = f.read()
                m = re.search('controller started', log)

                if m is None:
                    time.sleep(0.1)
                else:
                    break

        if m is None:
            self.stop()
            exit("Unit is writing log too long")

        missed_module = ''
        for module in modules:
            if module == 'go':
                env = os.environ.copy()
                env['GOPATH'] = self.pardir + '/go'

                try:
                    process = subprocess.Popen(
                        [
                            'go',
                            'build',
                            '-o',
                            self.testdir + '/go/check_module',
                            self.current_dir + '/go/empty/app.go',
                        ],
                        env=env,
                    )
                    process.communicate()

                    m = module if process.returncode == 0 else None

                except:
                    m = None

            elif module == 'node':
                if os.path.isdir(self.pardir + '/node/node_modules'):
                    m = module
                else:
                    m = None

            elif module == 'openssl':
                try:
                    subprocess.check_output(['which', 'openssl'])

                    output = subprocess.check_output(
                        [self.pardir + '/build/unitd', '--version'],
                        stderr=subprocess.STDOUT,
                    )

                    m = re.search('--openssl', output.decode())

                except:
                    m = None

            else:
                m = re.search('module: ' + module, log)

            if m is None:
                missed_module = module
                break

        self.stop()
        self._check_alerts(log)
        shutil.rmtree(self.testdir)

        if missed_module:
            raise unittest.SkipTest('Unit has no ' + missed_module + ' module')

    def stop(self):
        if self._started:
            self._stop()

    def _run(self):
        self.testdir = tempfile.mkdtemp(prefix='unit-test-')

        os.mkdir(self.testdir + '/state')

        print()

        def _run_unit():
            subprocess.call(
                [
                    self.pardir + '/build/unitd',
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

        for i in range(50):
            if not os.path.exists(self.testdir + '/unit.pid'):
                break
            time.sleep(0.1)

        if os.path.exists(self.testdir + '/unit.pid'):
            exit("Could not terminate unit")

        self._started = False

        self._p.join(timeout=1)
        self._terminate_process(self._p)

    def _terminate_process(self, process):
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)

            if process.is_alive():
                exit("Could not terminate process " + process.pid)

        if process.exitcode:
            exit("Child process terminated with code " + str(process.exitcode))

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

        return parser.parse_known_args()

    @staticmethod
    def _set_args(args):
        TestUnit.detailed = args.detailed
        TestUnit.save_log = args.save_log

    def _print_path_to_log(self):
        print('Path to unit.log:\n' + self.testdir + '/unit.log')
