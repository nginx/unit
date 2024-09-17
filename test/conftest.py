import fcntl
import inspect
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from multiprocessing import Process
from pathlib import Path

import pytest

from unit.check.check_prerequisites import check_prerequisites
from unit.check.discover_available import discover_available
from unit.http import HTTP1
from unit.log import Log
from unit.log import print_log_on_assert
from unit.option import option
from unit.status import Status
from unit.utils import check_findmnt
from unit.utils import public_dir
from unit.utils import waitforfiles
from unit.utils import waitforunmount


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
_processes = []
_fds_info = {
    'main': {'fds': 0, 'skip': False},
    'router': {'name': 'unit: router', 'pid': -1, 'fds': 0, 'skip': False},
    'controller': {
        'name': 'unit: controller',
        'pid': -1,
        'fds': 0,
        'skip': False,
    },
}
http = HTTP1()
is_findmnt = check_findmnt()


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
    option.test_dir = f'{option.current_dir}/test'

    option.cache_dir = tempfile.mkdtemp(prefix='unit-test-cache-')
    public_dir(option.cache_dir)

    # set stdout to non-blocking

    if option.detailed or option.print_log:
        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, 0)


def pytest_generate_tests(metafunc):
    module = metafunc.module
    if (
        not hasattr(module, 'client')
        or not hasattr(module.client, 'application_type')
        or module.client.application_type is None
        or module.client.application_type == 'external'
    ):
        return

    app_type = module.client.application_type

    def generate_tests(versions):
        if not versions:
            pytest.skip('no available module versions')

        metafunc.fixturenames.append('tmp_ct')
        metafunc.parametrize('tmp_ct', versions)

        for version in versions:
            option.generated_tests[
                f'{metafunc.function.__name__} [{version}]'
            ] = f'{app_type} {version}'

    # take available module from option and generate tests for each version

    available_modules = option.available['modules']

    for module, version in metafunc.module.prerequisites['modules'].items():
        if module in available_modules and available_modules[module]:
            available_versions = available_modules[module]

            if version == 'all':
                generate_tests(available_versions)

            elif version == 'any':
                option.generated_tests[
                    metafunc.function.__name__
                ] = f'{app_type} {available_versions[0]}'
            elif callable(version):
                generate_tests(list(filter(version, available_versions)))

            else:
                raise ValueError(
                    f'''
Unexpected prerequisite version "{version}" for module "{module}".
'all', 'any' or callable expected.'''
                )


def pytest_sessionstart():
    unit = unit_run()

    discover_available(unit)

    _clear_conf()

    unit_stop()

    Log.check_alerts()

    if option.restart:
        shutil.rmtree(unit['temp_dir'])
    else:
        _clear_temp_dir()


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item):
    # execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # set a report attribute for each phase of a call, which can
    # be "setup", "call", "teardown"

    setattr(item, f'rep_{rep.when}', rep)


@pytest.fixture(scope='module', autouse=True)
def check_prerequisites_module(request):
    if hasattr(request.module, 'prerequisites'):
        check_prerequisites(request.module.prerequisites)


@pytest.fixture(autouse=True)
def run(request):
    unit = unit_run()

    option.skip_alerts = [
        r'read signalfd\(4\) failed',
        r'sendmsg.+failed',
        r'recvmsg.+failed',
    ]
    option.skip_sanitizer = False

    _fds_info['main']['skip'] = False
    _fds_info['router']['skip'] = False
    _fds_info['controller']['skip'] = False

    yield

    # stop unit

    error_stop_unit = unit_stop()
    error_stop_processes = stop_processes()

    # prepare log

    with Log.open() as f:
        log = f.read()
        Log.set_pos(f.tell())

    if not option.save_log and option.restart:
        shutil.rmtree(unit['temp_dir'])
        Log.set_pos(0)

    # clean temp_dir before the next test

    if not option.restart:
        _clear_conf(log=log)
        _clear_temp_dir()

    # check descriptors

    _check_fds(log=log)

    # check processes id's and amount

    _check_processes()

    # print unit.log in case of error

    if hasattr(request.node, 'rep_call') and request.node.rep_call.failed:
        Log.print_log(log)

    if error_stop_unit or error_stop_processes:
        Log.print_log(log)

    # check unit.log for errors

    assert error_stop_unit is None, 'stop unit'
    assert error_stop_processes is None, 'stop processes'

    Log.check_alerts(log=log)


def unit_run(state_dir=None):
    global unit_instance

    if not option.restart and 'unitd' in unit_instance:
        return unit_instance

    builddir = f'{option.current_dir}/build'
    libdir = f'{builddir}/lib'
    modulesdir = f'{libdir}/unit/modules'
    sbindir = f'{builddir}/sbin'
    unitd = f'{sbindir}/unitd'

    if not Path(unitd).is_file():
        sys.exit('Could not find unit')

    temporary_dir = tempfile.mkdtemp(prefix='unit-test-')
    option.temp_dir = temporary_dir
    public_dir(temporary_dir)

    if oct(stat.S_IMODE(Path(builddir).stat().st_mode)) != '0o777':
        public_dir(builddir)

    statedir = f'{temporary_dir}/state' if state_dir is None else state_dir
    Path(statedir).mkdir(exist_ok=True)

    control_sock = f'{temporary_dir}/control.unit.sock'

    unitd_args = [
        unitd,
        '--no-daemon',
        '--modulesdir',
        modulesdir,
        '--statedir',
        statedir,
        '--pid',
        f'{temporary_dir}/unit.pid',
        '--log',
        f'{temporary_dir}/unit.log',
        '--control',
        f'unix:{temporary_dir}/control.unit.sock',
        '--tmpdir',
        temporary_dir,
    ]

    if option.user:
        unitd_args.extend(['--user', option.user])

    with open(f'{temporary_dir}/unit.log', 'w', encoding='utf-8') as log:
        unit_instance['process'] = subprocess.Popen(unitd_args, stderr=log)

    if not waitforfiles(control_sock):
        Log.print_log()
        sys.exit('Could not start unit')

    unit_instance['temp_dir'] = temporary_dir
    unit_instance['control_sock'] = control_sock
    unit_instance['unitd'] = unitd

    unit_instance['pid'] = (
        Path(f'{temporary_dir}/unit.pid').read_text(encoding='utf-8').rstrip()
    )

    if state_dir is None:
        _clear_conf()

    _fds_info['main']['fds'] = _count_fds(unit_instance['pid'])

    router = _fds_info['router']
    router['pid'] = pid_by_name(router['name'])
    router['fds'] = _count_fds(router['pid'])

    controller = _fds_info['controller']
    controller['pid'] = pid_by_name(controller['name'])
    controller['fds'] = _count_fds(controller['pid'])

    Status._check_zeros()

    return unit_instance


def unit_stop():
    if not option.restart:
        if inspect.stack()[1].function.startswith('test_'):
            pytest.skip('no restart mode')

        return

    # check zombies

    out = subprocess.check_output(
        ['ps', 'ax', '-o', 'state', '-o', 'ppid']
    ).decode()
    z_ppids = re.findall(r'Z\s*(\d+)', out)
    assert unit_instance['pid'] not in z_ppids, 'no zombies'

    # terminate unit

    p = unit_instance['process']

    if p.poll() is not None:
        return

    p.send_signal(signal.SIGQUIT)

    try:
        retcode = p.wait(15)
        if retcode:
            return f'Child process terminated with code {retcode}'

    except KeyboardInterrupt:
        p.kill()
        raise

    except:
        p.kill()
        return 'Could not terminate unit'


@print_log_on_assert
def _clear_conf(*, log=None):
    sock = unit_instance['control_sock']

    resp = http.put(
        url='/config',
        sock_type='unix',
        addr=sock,
        body=json.dumps({"listeners": {}, "applications": {}}),
    )['body']

    assert 'success' in resp, 'clear conf'

    def get(url):
        return http.get(url=url, sock_type='unix', addr=sock)['body']

    def delete(url):
        return http.delete(url=url, sock_type='unix', addr=sock)['body']

    if (
        'openssl' in option.available['modules']
        and option.available['modules']['openssl']
    ):
        try:
            certs = json.loads(get('/certificates')).keys()

        except json.JSONDecodeError:
            pytest.fail("Can't parse certificates list.")

        for cert in certs:
            assert 'success' in delete(f'/certificates/{cert}'), 'delete cert'

    if (
        'njs' in option.available['modules']
        and option.available['modules']['njs']
    ):
        try:
            scripts = json.loads(get('/js_modules')).keys()

        except json.JSONDecodeError:
            pytest.fail("Can't parse njs modules list.")

        for script in scripts:
            assert 'success' in delete(f'/js_modules/{script}'), 'delete script'


def _clear_temp_dir():
    temporary_dir = unit_instance['temp_dir']

    if is_findmnt and not waitforunmount(temporary_dir, timeout=600):
        Log.print_log()
        sys.exit(f'Could not unmount filesystems in tmpdir ({temporary_dir}).')

    for item in Path(temporary_dir).iterdir():
        if item.name not in [
            'control.unit.sock',
            'state',
            'unit.pid',
            'unit.log',
        ]:

            public_dir(item)

            if item.is_file() or stat.S_ISSOCK(item.stat().st_mode):
                item.unlink()
            else:
                for _ in range(10):
                    try:
                        shutil.rmtree(item)
                        break
                    except OSError as err:
                        # OSError: [Errno 16] Device or resource busy
                        # OSError: [Errno 39] Directory not empty
                        if err.errno not in [16, 39]:
                            raise
                        time.sleep(1)


def _check_processes():
    router_pid = _fds_info['router']['pid']
    controller_pid = _fds_info['controller']['pid']
    main_pid = unit_instance['pid']

    for _ in range(600):
        out = (
            subprocess.check_output(
                ['ps', '-ax', '-o', 'pid', '-o', 'ppid', '-o', 'command']
            )
            .decode()
            .splitlines()
        )
        out = [l for l in out if main_pid in l]

        if len(out) <= 3:
            break

        time.sleep(0.1)

    if option.restart:
        assert len(out) == 0, 'all termimated'
        return

    assert len(out) == 3, 'main, router, and controller expected'

    out = [l for l in out if 'unit: main' not in l]
    assert len(out) == 2, 'one main'

    out = [
        l
        for l in out
        if re.search(fr'{router_pid}\s+{main_pid}.*unit: router', l) is None
    ]
    assert len(out) == 1, 'one router'

    out = [
        l
        for l in out
        if re.search(fr'{controller_pid}\s+{main_pid}.*unit: controller', l)
        is None
    ]
    assert len(out) == 0, 'one controller'


@print_log_on_assert
def _check_fds(*, log=None):
    def waitforfds(diff):
        for _ in range(600):
            fds_diff = diff()

            if fds_diff <= option.fds_threshold:
                break

            time.sleep(0.1)

        return fds_diff

    ps = _fds_info['main']
    if not ps['skip']:
        fds_diff = waitforfds(
            lambda: _count_fds(unit_instance['pid']) - ps['fds']
        )
        ps['fds'] += fds_diff

        assert fds_diff <= option.fds_threshold, 'descriptors leak main process'

    else:
        ps['fds'] = _count_fds(unit_instance['pid'])

    for name in ['controller', 'router']:
        ps = _fds_info[name]
        ps_pid = ps['pid']
        ps['pid'] = pid_by_name(ps['name'])

        if not ps['skip']:
            fds_diff = waitforfds(lambda: _count_fds(ps['pid']) - ps['fds'])
            ps['fds'] += fds_diff

            if not option.restart:
                assert ps['pid'] == ps_pid, f'same pid {name}'

            assert fds_diff <= option.fds_threshold, f'descriptors leak {name}'

        else:
            ps['fds'] = _count_fds(ps['pid'])


def _count_fds(pid):
    procfile = Path(f'/proc/{pid}/fd')
    if procfile.is_dir():
        return len(list(procfile.iterdir()))

    try:
        out = subprocess.check_output(
            ['procstat', '-f', pid],
            stderr=subprocess.STDOUT,
        ).decode()
        return len(out.splitlines())

    except (FileNotFoundError, TypeError, subprocess.CalledProcessError):
        pass

    try:
        out = subprocess.check_output(
            ['lsof', '-n', '-p', pid],
            stderr=subprocess.STDOUT,
        ).decode()
        return len(out.splitlines())

    except (FileNotFoundError, TypeError, subprocess.CalledProcessError):
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
    m = re.search(fr'\s*(\d+)\s*{unit_instance["pid"]}.*{name}', output)
    return None if m is None else m.group(1)


def find_proc(name, ps_output):
    return re.findall(f'{unit_instance["pid"]}.*{name}', ps_output)


def pytest_sessionfinish():
    if not option.restart and option.save_log:
        Log.print_path()

    option.restart = True

    unit_stop()

    public_dir(option.cache_dir)
    shutil.rmtree(option.cache_dir)

    if not option.save_log and Path(option.temp_dir).is_dir():
        public_dir(option.temp_dir)
        shutil.rmtree(option.temp_dir)


@pytest.fixture
def date_to_sec_epoch():
    def _date_to_sec_epoch(date, template='%a, %d %b %Y %X %Z'):
        return time.mktime(time.strptime(date, template))

    return _date_to_sec_epoch


@pytest.fixture
def findall():
    def _findall(*args, **kwargs):
        return Log.findall(*args, **kwargs)

    return _findall


@pytest.fixture
def is_su():
    return option.is_privileged


@pytest.fixture
def is_unsafe(request):
    return request.config.getoption("--unsafe")


@pytest.fixture
def require():
    return check_prerequisites


@pytest.fixture
def search_in_file():
    def _search_in_file(pattern, name='unit.log', flags=re.M):
        return re.search(pattern, Log.read(name), flags)

    return _search_in_file


@pytest.fixture
def sec_epoch():
    return time.mktime(time.gmtime())


@pytest.fixture()
def skip_alert():
    def _skip(*alerts):
        option.skip_alerts.extend(alerts)

    return _skip


@pytest.fixture()
def skip_fds_check():
    def _skip(main=False, router=False, controller=False):
        _fds_info['main']['skip'] = main
        _fds_info['router']['skip'] = router
        _fds_info['controller']['skip'] = controller

    return _skip


@pytest.fixture()
def system():
    return option.system


@pytest.fixture
def temp_dir():
    return unit_instance['temp_dir']


@pytest.fixture
def unit_pid():
    return unit_instance['process'].pid


@pytest.fixture
def wait_for_record():
    def _wait_for_record(*args, **kwargs):
        return Log.wait_for_record(*args, **kwargs)

    return _wait_for_record
