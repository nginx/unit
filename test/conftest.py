import fcntl
import os
import platform
import pytest
import shutil
import signal
import stat
import subprocess
import sys
import re
import tempfile
import time

from unit.check.go import check_go
from unit.check.node import check_node
from unit.check.tls import check_openssl


def pytest_addoption(parser):
    parser.addoption(
        "--detailed",
        default=False,
        action="store_true",
        help="Detailed output for tests",
    )
    parser.addoption(
        "--print_log",
        default=False,
        action="store_true",
        help="Print unit.log to stdout in case of errors",
    )
    parser.addoption(
        "--save_log",
        default=False,
        action="store_true",
        help="Save unit.log after the test execution",
    )
    parser.addoption(
        "--unsafe",
        default=False,
        action="store_true",
        help="Run unsafe tests",
    )


unit_instance = {}
option = None


def pytest_configure(config):
    global option
    option = config.option

    option.generated_tests = {}
    option.current_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir)
    )
    option.test_dir = option.current_dir + '/test'
    option.architecture = platform.architecture()[0]
    option.system = platform.system()

    # set stdout to non-blocking

    if option.detailed or option.print_log:
        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, 0)


def pytest_generate_tests(metafunc):
    cls = metafunc.cls
    if not hasattr(cls, 'application_type'):
        return

    type = cls.application_type

    def generate_tests(versions):
        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('tmp_ct', versions)

        for version in versions:
            option.generated_tests[
                metafunc.function.__name__ + '[{}]'.format(version)
            ] = (type + ' ' + version)

    # take available module from option and generate tests for each version

    for module, prereq_version in cls.prerequisites['modules'].items():
        if module in option.available['modules']:
            available_versions = option.available['modules'][module]

            if prereq_version == 'all':
                generate_tests(available_versions)

            elif prereq_version == 'any':
                option.generated_tests[metafunc.function.__name__] = (
                    type + ' ' + available_versions[0]
                )
            elif callable(prereq_version):
                generate_tests(
                    list(filter(prereq_version, available_versions))
                )

            else:
                raise ValueError(
                    """
Unexpected prerequisite version "%s" for module "%s" in %s.
'all', 'any' or callable expected."""
                    % (str(prereq_version), module, str(cls))
                )


def pytest_sessionstart(session):
    option.available = {'modules': {}, 'features': {}}

    unit = unit_run()

    # read unit.log

    for i in range(50):
        with open(unit['temp_dir'] + '/unit.log', 'r') as f:
            log = f.read()
            m = re.search('controller started', log)

            if m is None:
                time.sleep(0.1)
            else:
                break

    if m is None:
        _print_log()
        exit("Unit is writing log too long")

    # discover available modules from unit.log

    for module in re.findall(r'module: ([a-zA-Z]+) (.*) ".*"$', log, re.M):
        if module[0] not in option.available['modules']:
            option.available['modules'][module[0]] = [module[1]]
        else:
            option.available['modules'][module[0]].append(module[1])

    # discover modules from check

    option.available['modules']['openssl'] = check_openssl(unit['unitd'])
    option.available['modules']['go'] = check_go(
        option.current_dir, unit['temp_dir'], option.test_dir
    )
    option.available['modules']['node'] = check_node(option.current_dir)

    # remove None values

    option.available['modules'] = {
        k: v for k, v in option.available['modules'].items() if v is not None
    }

    unit_stop()


def setup_method(self):
    option.skip_alerts = [
        r'read signalfd\(4\) failed',
        r'sendmsg.+failed',
        r'recvmsg.+failed',
    ]
    option.skip_sanitizer = False

def unit_run():
    global unit_instance
    build_dir = option.current_dir + '/build'
    unitd = build_dir + '/unitd'

    if not os.path.isfile(unitd):
        exit('Could not find unit')

    temp_dir = tempfile.mkdtemp(prefix='unit-test-')
    public_dir(temp_dir)

    if oct(stat.S_IMODE(os.stat(build_dir).st_mode)) != '0o777':
        public_dir(build_dir)

    os.mkdir(temp_dir + '/state')

    with open(temp_dir + '/unit.log', 'w') as log:
        unit_instance['process'] = subprocess.Popen(
            [
                unitd,
                '--no-daemon',
                '--modules',
                build_dir,
                '--state',
                temp_dir + '/state',
                '--pid',
                temp_dir + '/unit.pid',
                '--log',
                temp_dir + '/unit.log',
                '--control',
                'unix:' + temp_dir + '/control.unit.sock',
                '--tmp',
                temp_dir,
            ],
            stderr=log,
        )

    if not waitforfiles(temp_dir + '/control.unit.sock'):
        _print_log()
        exit('Could not start unit')

    # dumb (TODO: remove)
    option.skip_alerts = [
        r'read signalfd\(4\) failed',
        r'sendmsg.+failed',
        r'recvmsg.+failed',
    ]
    option.skip_sanitizer = False

    unit_instance['temp_dir'] = temp_dir
    unit_instance['log'] = temp_dir + '/unit.log'
    unit_instance['control_sock'] = temp_dir + '/control.unit.sock'
    unit_instance['unitd'] = unitd

    return unit_instance


def unit_stop():
    p = unit_instance['process']

    if p.poll() is not None:
        return

    p.send_signal(signal.SIGQUIT)

    try:
        retcode = p.wait(15)
        if retcode:
            return 'Child process terminated with code ' + str(retcode)
    except:
        p.kill()
        return 'Could not terminate unit'

    shutil.rmtree(unit_instance['temp_dir'])

def public_dir(path):
    os.chmod(path, 0o777)

    for root, dirs, files in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o777)
        for f in files:
            os.chmod(os.path.join(root, f), 0o777)

def waitforfiles(*files):
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


def skip_alert(*alerts):
    option.skip_alerts.extend(alerts)


def _check_alerts(log):
    found = False

    alerts = re.findall(r'.+\[alert\].+', log)

    if alerts:
        print('All alerts/sanitizer errors found in log:')
        [print(alert) for alert in alerts]
        found = True

    if option.skip_alerts:
        for skip in option.skip_alerts:
            alerts = [al for al in alerts if re.search(skip, al) is None]

    if alerts:
        _print_log(data=log)
        assert not alerts, 'alert(s)'

    if not option.skip_sanitizer:
        sanitizer_errors = re.findall('.+Sanitizer.+', log)

        if sanitizer_errors:
            _print_log(data=log)
            assert not sanitizer_errors, 'sanitizer error(s)'

    if found:
        print('skipped.')


def _print_log(path=None, data=None):
    if path is None:
        path = unit_instance['log']

    print('Path to unit.log:\n' + path + '\n')

    if option.print_log:
        os.set_blocking(sys.stdout.fileno(), True)
        sys.stdout.flush()

        if data is None:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                shutil.copyfileobj(f, sys.stdout)
        else:
            sys.stdout.write(data)


@pytest.fixture
def is_unsafe(request):
    return request.config.getoption("--unsafe")

@pytest.fixture
def is_su(request):
    return os.geteuid() == 0

def pytest_sessionfinish(session):
    unit_stop()
