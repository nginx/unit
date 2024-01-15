import re
import shutil
import subprocess
import time

import pytest

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    client.app_name = f'app-{temp_dir.split("/")[-1]}'
    client.app_proc = f'applications/{client.app_name}/processes'
    client.load('empty', client.app_name)


def pids_for_process():
    time.sleep(0.2)

    output = subprocess.check_output(['ps', 'ax'])

    pids = set()
    for m in re.findall(
        fr'.*unit: "{client.app_name}" application', output.decode()
    ):
        pids.add(re.search(r'^\s*(\d+)', m).group(1))

    return pids


def conf_proc(conf, path=None):
    if path is None:
        path = client.app_proc

    assert 'success' in client.conf(conf, path), 'configure processes'


def stop_all():
    assert 'success' in client.conf({"listeners": {}, "applications": {}})

    assert len(pids_for_process()) == 0, 'stop all'


@pytest.mark.skip('not yet')
def test_python_processes_idle_timeout_zero():
    conf_proc({"spare": 0, "max": 2, "idle_timeout": 0})

    client.get()
    assert len(pids_for_process()) == 0, 'idle timeout 0'


def test_python_prefork():
    conf_proc('2')

    pids = pids_for_process()
    assert len(pids) == 2, 'prefork 2'

    client.get()
    assert pids_for_process() == pids, 'prefork still 2'

    conf_proc('4')

    pids = pids_for_process()
    assert len(pids) == 4, 'prefork 4'

    client.get()
    assert pids_for_process() == pids, 'prefork still 4'

    stop_all()


@pytest.mark.skip('not yet')
def test_python_prefork_same_processes():
    conf_proc('2')
    pids = pids_for_process()

    conf_proc('4')
    pids_new = pids_for_process()

    assert pids.issubset(pids_new), 'prefork same processes'


def test_python_ondemand():
    conf_proc({"spare": 0, "max": 8, "idle_timeout": 1})

    assert len(pids_for_process()) == 0, 'on-demand 0'

    client.get()
    pids = pids_for_process()
    assert len(pids) == 1, 'on-demand 1'

    client.get()
    assert pids_for_process() == pids, 'on-demand still 1'

    time.sleep(1)

    assert len(pids_for_process()) == 0, 'on-demand stop idle'

    stop_all()


def test_python_scale_updown():
    conf_proc({"spare": 2, "max": 8, "idle_timeout": 1})

    pids = pids_for_process()
    assert len(pids) == 2, 'updown 2'

    client.get()
    pids_new = pids_for_process()
    assert len(pids_new) == 3, 'updown 3'
    assert pids.issubset(pids_new), 'updown 3 only 1 new'

    client.get()
    assert pids_for_process() == pids_new, 'updown still 3'

    time.sleep(1)

    pids = pids_for_process()
    assert len(pids) == 2, 'updown stop idle'

    client.get()
    pids_new = pids_for_process()
    assert len(pids_new) == 3, 'updown again 3'
    assert pids.issubset(pids_new), 'updown again 3 only 1 new'

    stop_all()


def test_python_reconfigure():
    conf_proc({"spare": 2, "max": 6, "idle_timeout": 1})

    pids = pids_for_process()
    assert len(pids) == 2, 'reconf 2'

    client.get()
    pids_new = pids_for_process()
    assert len(pids_new) == 3, 'reconf 3'
    assert pids.issubset(pids_new), 'reconf 3 only 1 new'

    conf_proc('6', f'{client.app_proc}/spare')

    pids = pids_for_process()
    assert len(pids) == 6, 'reconf 6'

    client.get()
    assert pids_for_process() == pids, 'reconf still 6'

    stop_all()


def test_python_idle_timeout():
    conf_proc({"spare": 0, "max": 6, "idle_timeout": 2})

    client.get()
    pids = pids_for_process()
    assert len(pids) == 1, 'idle timeout 1'

    time.sleep(1)

    client.get()

    time.sleep(1)

    pids_new = pids_for_process()
    assert len(pids_new) == 1, 'idle timeout still 1'
    assert pids_for_process() == pids, 'idle timeout still 1 same pid'

    time.sleep(1)

    assert len(pids_for_process()) == 0, 'idle timed out'


def test_python_processes_connection_keepalive():
    conf_proc({"spare": 0, "max": 6, "idle_timeout": 2})

    (_, sock) = client.get(
        headers={'Host': 'localhost', 'Connection': 'keep-alive'},
        start=True,
        read_timeout=1,
    )
    assert len(pids_for_process()) == 1, 'keepalive connection 1'

    time.sleep(2)

    assert len(pids_for_process()) == 0, 'keepalive connection 0'

    sock.close()


def test_python_processes_access():
    conf_proc('1')

    path = f'/{client.app_proc}'
    assert 'error' in client.conf_get(f'{path}/max')
    assert 'error' in client.conf_get(f'{path}/spare')
    assert 'error' in client.conf_get(f'{path}/idle_timeout')


def test_python_processes_invalid():
    assert 'error' in client.conf(
        {"spare": -1}, client.app_proc
    ), 'negative spare'
    assert 'error' in client.conf({"max": -1}, client.app_proc), 'negative max'
    assert 'error' in client.conf(
        {"idle_timeout": -1}, client.app_proc
    ), 'negative idle_timeout'
    assert 'error' in client.conf(
        {"spare": 2}, client.app_proc
    ), 'spare gt max default'
    assert 'error' in client.conf(
        {"spare": 2, "max": 1}, client.app_proc
    ), 'spare gt max'
    assert 'error' in client.conf(
        {"spare": 0, "max": 0}, client.app_proc
    ), 'max zero'


def test_python_restart(temp_dir):
    shutil.copyfile(
        f'{option.test_dir}/python/restart/v1.py', f'{temp_dir}/wsgi.py'
    )

    client.load(
        temp_dir,
        name=client.app_name,
        processes=1,
        environment={'PYTHONDONTWRITEBYTECODE': '1'},
    )

    b = client.get()['body']
    assert b == "v1", 'process started'

    shutil.copyfile(
        f'{option.test_dir}/python/restart/v2.py', f'{temp_dir}/wsgi.py'
    )

    b = client.get()['body']
    assert b == "v1", 'still old process'

    assert 'success' in client.conf_get(
        f'/control/applications/{client.app_name}/restart'
    ), 'restart processes'

    b = client.get()['body']
    assert b == "v2", 'new process started'

    assert 'error' in client.conf_get(
        '/control/applications/blah/restart'
    ), 'application incorrect'

    assert 'error' in client.conf_delete(
        f'/control/applications/{client.app_name}/restart'
    ), 'method incorrect'


def test_python_restart_multi():
    conf_proc('2')

    pids = pids_for_process()
    assert len(pids) == 2, 'restart 2 started'

    assert 'success' in client.conf_get(
        f'/control/applications/{client.app_name}/restart'
    ), 'restart processes'

    new_pids = pids_for_process()
    assert len(new_pids) == 2, 'restart still 2'

    assert len(new_pids.intersection(pids)) == 0, 'restart all new'


def test_python_restart_longstart():
    client.load(
        'restart',
        name=client.app_name,
        module="longstart",
        processes={"spare": 1, "max": 2, "idle_timeout": 5},
    )

    assert len(pids_for_process()) == 1, 'longstarts == 1'

    client.get()

    pids = pids_for_process()
    assert len(pids) == 2, 'longstarts == 2'

    assert 'success' in client.conf_get(
        f'/control/applications/{client.app_name}/restart'
    ), 'restart processes'

    # wait for longstarted app
    time.sleep(2)

    new_pids = pids_for_process()
    assert len(new_pids) == 1, 'restart 1'

    assert len(new_pids.intersection(pids)) == 0, 'restart all new'
