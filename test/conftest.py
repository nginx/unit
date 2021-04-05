import fcntl
import inspect
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from multiprocessing import Process

import pytest

from unit.check.go import check_go
from unit.check.isolation import check_isolation
from unit.check.node import check_node
from unit.check.regex import check_regex
from unit.check.tls import check_openssl
from unit.http import TestHTTP
from unit.option import option
from unit.utils import public_dir
from unit.utils import waitforfiles


def pytest_addoption(parser):
    parser.addoption(
        "--detailed",
        default=False,
        action="store_true",
        help="Detailed output for tests",
    )
    parser.addoption(
        "--print-log",
        default=False,
        action="store_true",
        help="Print unit.log to stdout in case of errors",
    )
    parser.addoption(
        "--save-log",
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
    parser.addoption(
        "--user",
        type=str,
        help="Default user for non-privileged processes of unitd",
    )
    parser.addoption(
        "--fds-threshold",
        type=int,
        default=0,
        help="File descriptors threshold",
    )
    parser.addoption(
        "--restart",
        default=False,
        action="store_true",
        help="Force Unit to restart after every test",
    )


unit_instance = {}
unit_log_copy = "unit.log.copy"
_processes = []
_fds_check = {
    'main': {'fds': 0, 'skip': False},
    'router': {'name': 'unit: router', 'pid': -1, 'fds': 0, 'skip': False},
    'controller': {
        'name': 'unit: controller',
        'pid': -1,
        'fds': 0,
        'skip': False,
    },
}
http = TestHTTP()


def pytest_configure(config):
    option.config = config.option

    option.detailed = config.option.detailed
    option.fds_threshold = config.option.fds_threshold
    option.print_log = config.option.print_log
    option.save_log = config.option.save_log
    option.unsafe = config.option.unsafe
    option.user = config.option.user
    option.restart = config.option.restart

    option.generated_tests = {}
    option.current_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), os.pardir)
    )
    option.test_dir = option.current_dir + '/test'
    option.architecture = platform.architecture()[0]
    option.system = platform.system()

    option.cache_dir = tempfile.mkdtemp(prefix='unit-test-cache-')
    public_dir(option.cache_dir)

    # set stdout to non-blocking

    if option.detailed or option.print_log:
        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, 0)


def pytest_generate_tests(metafunc):
    cls = metafunc.cls
    if (
        not hasattr(cls, 'application_type')
        or cls.application_type == None
        or cls.application_type == 'external'
    ):
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
    option.temp_dir = unit['temp_dir']

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
        _print_log(log)
        exit("Unit is writing log too long")

    # discover available modules from unit.log

    for module in re.findall(r'module: ([a-zA-Z]+) (.*) ".*"$', log, re.M):
        versions = option.available['modules'].setdefault(module[0], [])
        if module[1] not in versions:
            versions.append(module[1])

    # discover modules from check

    option.available['modules']['openssl'] = check_openssl(unit['unitd'])
    option.available['modules']['go'] = check_go(
        option.current_dir, unit['temp_dir'], option.test_dir
    )
    option.available['modules']['node'] = check_node(option.current_dir)
    option.available['modules']['regex'] = check_regex(unit['unitd'])

    # remove None values

    option.available['modules'] = {
        k: v for k, v in option.available['modules'].items() if v is not None
    }

    check_isolation()

    _clear_conf(unit['temp_dir'] + '/control.unit.sock')

    unit_stop()

    _check_alerts()

    if option.restart:
        shutil.rmtree(unit_instance['temp_dir'])

    elif option.save_log:
        open(unit_instance['temp_dir'] + '/' + unit_log_copy, 'w').close()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, "rep_" + rep.when, rep)


@pytest.fixture(scope='class', autouse=True)
def check_prerequisites(request):
    cls = request.cls
    missed = []

    # check modules

    if 'modules' in cls.prerequisites:
        available_modules = list(option.available['modules'].keys())

        for module in cls.prerequisites['modules']:
            if module in available_modules:
                continue

            missed.append(module)

    if missed:
        pytest.skip('Unit has no ' + ', '.join(missed) + ' module(s)')

    # check features

    if 'features' in cls.prerequisites:
        available_features = list(option.available['features'].keys())

        for feature in cls.prerequisites['features']:
            if feature in available_features:
                continue

            missed.append(feature)

    if missed:
        pytest.skip(', '.join(missed) + ' feature(s) not supported')


@pytest.fixture(autouse=True)
def run(request):
    unit = unit_run()
    option.temp_dir = unit['temp_dir']

    option.skip_alerts = [
        r'read signalfd\(4\) failed',
        r'sendmsg.+failed',
        r'recvmsg.+failed',
    ]
    option.skip_sanitizer = False

    _fds_check['main']['skip'] = False
    _fds_check['router']['skip'] = False
    _fds_check['router']['skip'] = False

    yield

    # stop unit

    error_stop_unit = unit_stop()
    error_stop_processes = stop_processes()

    # prepare log

    with open(
        unit_instance['log'], 'r', encoding='utf-8', errors='ignore'
    ) as f:
        log = f.read()

    if not option.restart and option.save_log:
        with open(unit_instance['temp_dir'] + '/' + unit_log_copy, 'a') as f:
            f.write(log)

    # remove unit.log

    if not option.save_log and option.restart:
        shutil.rmtree(unit['temp_dir'])

    # clean temp_dir before the next test

    if not option.restart:
        _clear_conf(unit['temp_dir'] + '/control.unit.sock', log)

        open(unit['log'], 'w').close()

        for item in os.listdir(unit['temp_dir']):
            if item not in [
                'control.unit.sock',
                'state',
                'unit.pid',
                'unit.log',
                unit_log_copy,
            ]:
                path = os.path.join(unit['temp_dir'], item)

                public_dir(path)

                if os.path.isfile(path) or stat.S_ISSOCK(
                    os.stat(path).st_mode
                ):
                    os.remove(path)
                else:
                    shutil.rmtree(path)

    # check descriptors (wait for some time before check)

    def waitforfds(diff):
        for i in range(600):
            fds_diff = diff()

            if fds_diff <= option.fds_threshold:
                break

            time.sleep(0.1)

        return fds_diff

    ps = _fds_check['main']
    if not ps['skip']:
        fds_diff = waitforfds(
            lambda: _count_fds(unit_instance['pid']) - ps['fds']
        )
        ps['fds'] += fds_diff

        assert (
            fds_diff <= option.fds_threshold
        ), 'descriptors leak main process'

    else:
        ps['fds'] = _count_fds(unit_instance['pid'])

    for name in ['controller', 'router']:
        ps = _fds_check[name]
        ps_pid = ps['pid']
        ps['pid'] = pid_by_name(ps['name'])

        if not ps['skip']:
            fds_diff = waitforfds(lambda: _count_fds(ps['pid']) - ps['fds'])
            ps['fds'] += fds_diff

            assert ps['pid'] == ps_pid, 'same pid %s' % name
            assert fds_diff <= option.fds_threshold, (
                'descriptors leak %s' % name
            )

        else:
            ps['fds'] = _count_fds(ps['pid'])

    # print unit.log in case of error

    if hasattr(request.node, 'rep_call') and request.node.rep_call.failed:
        _print_log(log)

    if error_stop_unit or error_stop_processes:
        _print_log(log)

    # check unit.log for errors

    assert error_stop_unit is None, 'stop unit'
    assert error_stop_processes is None, 'stop processes'

    _check_alerts(log=log)


def unit_run():
    global unit_instance

    if not option.restart and 'unitd' in unit_instance:
        return unit_instance

    build_dir = option.current_dir + '/build'
    unitd = build_dir + '/unitd'

    if not os.path.isfile(unitd):
        exit('Could not find unit')

    temp_dir = tempfile.mkdtemp(prefix='unit-test-')
    public_dir(temp_dir)

    if oct(stat.S_IMODE(os.stat(build_dir).st_mode)) != '0o777':
        public_dir(build_dir)

    os.mkdir(temp_dir + '/state')

    unitd_args = [
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
    ]

    if option.user:
        unitd_args.extend(['--user', option.user])

    with open(temp_dir + '/unit.log', 'w') as log:
        unit_instance['process'] = subprocess.Popen(unitd_args, stderr=log)

    if not waitforfiles(temp_dir + '/control.unit.sock'):
        _print_log()
        exit('Could not start unit')

    unit_instance['temp_dir'] = temp_dir
    unit_instance['log'] = temp_dir + '/unit.log'
    unit_instance['control_sock'] = temp_dir + '/control.unit.sock'
    unit_instance['unitd'] = unitd

    with open(temp_dir + '/unit.pid', 'r') as f:
        unit_instance['pid'] = f.read().rstrip()

    _clear_conf(unit_instance['temp_dir'] + '/control.unit.sock')

    _fds_check['main']['fds'] = _count_fds(unit_instance['pid'])

    router = _fds_check['router']
    router['pid'] = pid_by_name(router['name'])
    router['fds'] = _count_fds(router['pid'])

    controller = _fds_check['controller']
    controller['pid'] = pid_by_name(controller['name'])
    controller['fds'] = _count_fds(controller['pid'])

    return unit_instance


def unit_stop():
    if not option.restart:
        if inspect.stack()[1].function.startswith('test_'):
            pytest.skip('no restart mode')

        return

    p = unit_instance['process']

    if p.poll() is not None:
        return

    p.send_signal(signal.SIGQUIT)

    try:
        retcode = p.wait(15)
        if retcode:
            return 'Child process terminated with code ' + str(retcode)

    except KeyboardInterrupt:
        p.kill()
        raise

    except:
        p.kill()
        return 'Could not terminate unit'


def _check_alerts(path=None, log=None):
    if path is None:
        path = unit_instance['log']

    if log is None:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            log = f.read()

    found = False

    alerts = re.findall(r'.+\[alert\].+', log)

    if alerts:
        print('\nAll alerts/sanitizer errors found in log:')
        [print(alert) for alert in alerts]
        found = True

    if option.skip_alerts:
        for skip in option.skip_alerts:
            alerts = [al for al in alerts if re.search(skip, al) is None]

    if alerts:
        _print_log(log)
        assert not alerts, 'alert(s)'

    if not option.skip_sanitizer:
        sanitizer_errors = re.findall('.+Sanitizer.+', log)

        if sanitizer_errors:
            _print_log(log)
            assert not sanitizer_errors, 'sanitizer error(s)'

    if found:
        print('skipped.')


def _print_log(data=None):
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


def _clear_conf(sock, log=None):
    def check_success(resp):
        if 'success' not in resp:
            _print_log(log)
            assert 'success' in resp

    resp = http.put(
        url='/config',
        sock_type='unix',
        addr=sock,
        body=json.dumps({"listeners": {}, "applications": {}}),
    )['body']

    check_success(resp)

    if 'openssl' not in option.available['modules']:
        return

    try:
        certs = json.loads(
            http.get(url='/certificates', sock_type='unix', addr=sock,)['body']
        ).keys()

    except json.JSONDecodeError:
        pytest.fail('Can\'t parse certificates list.')

    for cert in certs:
        resp = http.delete(
            url='/certificates/' + cert, sock_type='unix', addr=sock,
        )['body']

        check_success(resp)


def _count_fds(pid):
    procfile = '/proc/%s/fd' % pid
    if os.path.isdir(procfile):
        return len(os.listdir(procfile))

    try:
        out = subprocess.check_output(
            ['procstat', '-f', pid], stderr=subprocess.STDOUT,
        ).decode()
        return len(out.splitlines())

    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    try:
        out = subprocess.check_output(
            ['lsof', '-n', '-p', pid], stderr=subprocess.STDOUT,
        ).decode()
        return len(out.splitlines())

    except (FileNotFoundError, subprocess.CalledProcessError):
        pass

    return 0


def run_process(target, *args):
    global _processes

    process = Process(target=target, args=args)
    process.start()

    _processes.append(process)


def stop_processes():
    if not _processes:
        return

    fail = False
    for process in _processes:
        if process.is_alive():
            process.terminate()
            process.join(timeout=15)

            if process.is_alive():
                fail = True

    if fail:
        return 'Fail to stop process(es)'


def pid_by_name(name):
    output = subprocess.check_output(['ps', 'ax', '-O', 'ppid']).decode()
    m = re.search(
        r'\s*(\d+)\s*' + str(unit_instance['pid']) + r'.*' + name, output
    )
    return None if m is None else m.group(1)


def find_proc(name, ps_output):
    return re.findall(str(unit_instance['pid']) + r'.*' + name, ps_output)


@pytest.fixture()
def skip_alert():
    def _skip(*alerts):
        option.skip_alerts.extend(alerts)

    return _skip


@pytest.fixture()
def skip_fds_check():
    def _skip(main=False, router=False, controller=False):
        _fds_check['main']['skip'] = main
        _fds_check['router']['skip'] = router
        _fds_check['controller']['skip'] = controller

    return _skip


@pytest.fixture
def temp_dir(request):
    return unit_instance['temp_dir']


@pytest.fixture
def is_unsafe(request):
    return request.config.getoption("--unsafe")


@pytest.fixture
def is_su(request):
    return os.geteuid() == 0


@pytest.fixture
def unit_pid(request):
    return unit_instance['process'].pid


def pytest_sessionfinish(session):
    if not option.restart and option.save_log:
        print('Path to unit.log:\n' + unit_instance['log'] + '\n')

    option.restart = True

    unit_stop()
    shutil.rmtree(option.cache_dir)
