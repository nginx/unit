import re
import subprocess
from pathlib import Path

import pytest

from unit.applications.lang.python import ApplicationPython
from unit.option import option
from unit.utils import findmnt
from unit.utils import waitformount
from unit.utils import waitforunmount

prerequisites = {'modules': {'python': 'any'}, 'features': {'isolation': True}}

client = ApplicationPython()


def get_cgroup(app_name):
    output = subprocess.check_output(
        ['ps', 'ax', '-o', 'pid', '-o', 'cmd']
    ).decode()

    pid = re.search(fr'(\d+)\s*unit: "{app_name}" application', output).group(1)

    cgroup = f'/proc/{pid}/cgroup'

    if not Path(cgroup).is_file():
        pytest.skip(f'no cgroup at {cgroup}')

    with open(cgroup, 'r', encoding='utf-8') as f:
        return f.read().rstrip()


def test_python_isolation_rootfs(is_su, require, temp_dir):
    isolation = {'rootfs': temp_dir}

    if not is_su:
        require(
            {
                'features': {
                    'isolation': [
                        'unprivileged_userns_clone',
                        'user',
                        'mnt',
                        'pid',
                    ]
                }
            }
        )

        isolation['namespaces'] = {
            'mount': True,
            'credential': True,
            'pid': True,
        }

    client.load('ns_inspect', isolation=isolation)

    assert not (
        client.getjson(url=f'/?path={temp_dir}')['body']['FileExists']
    ), 'temp_dir does not exists in rootfs'

    assert client.getjson(url='/?path=/proc/self')['body'][
        'FileExists'
    ], 'no /proc/self'

    assert not (
        client.getjson(url='/?path=/dev/pts')['body']['FileExists']
    ), 'no /dev/pts'

    assert not (
        client.getjson(url='/?path=/sys/kernel')['body']['FileExists']
    ), 'no /sys/kernel'

    ret = client.getjson(url='/?path=/app/python/ns_inspect')

    assert ret['body']['FileExists'], 'application exists in rootfs'


def test_python_isolation_rootfs_no_language_deps(require, temp_dir):
    require({'privileged_user': True})

    isolation = {'rootfs': temp_dir, 'automount': {'language_deps': False}}
    client.load('empty', isolation=isolation)

    python_path = f'{temp_dir}/usr'

    assert findmnt().find(python_path) == -1
    assert client.get()['status'] != 200, 'disabled language_deps'
    assert findmnt().find(python_path) == -1

    isolation['automount']['language_deps'] = True

    client.load('empty', isolation=isolation)

    assert findmnt().find(python_path) == -1
    assert client.get()['status'] == 200, 'enabled language_deps'
    assert waitformount(python_path), 'language_deps mount'

    client.conf({"listeners": {}, "applications": {}})

    assert waitforunmount(python_path), 'language_deps unmount'


def test_python_isolation_procfs(require, temp_dir):
    require({'privileged_user': True})

    isolation = {'rootfs': temp_dir, 'automount': {'procfs': False}}

    client.load('ns_inspect', isolation=isolation)

    assert not (
        client.getjson(url='/?path=/proc/self')['body']['FileExists']
    ), 'no /proc/self'

    isolation['automount']['procfs'] = True

    client.load('ns_inspect', isolation=isolation)

    assert client.getjson(url='/?path=/proc/self')['body'][
        'FileExists'
    ], '/proc/self'


def test_python_isolation_cgroup(require):
    require({'privileged_user': True, 'features': {'isolation': ['cgroup']}})

    def set_cgroup_path(path):
        isolation = {'cgroup': {'path': path}}
        client.load('empty', processes=1, isolation=isolation)

    set_cgroup_path('scope/python')

    cgroup_rel = Path(get_cgroup('empty'))
    assert cgroup_rel.parts[-2:] == ('scope', 'python'), 'cgroup rel'

    set_cgroup_path('/scope2/python')

    cgroup_abs = Path(get_cgroup('empty'))
    assert cgroup_abs.parts[-2:] == ('scope2', 'python'), 'cgroup abs'

    assert len(cgroup_rel.parts) >= len(cgroup_abs.parts)


def test_python_isolation_cgroup_two(require):
    require({'privileged_user': True, 'features': {'isolation': ['cgroup']}})

    def set_two_cgroup_path(path, path2):
        script_path = f'{option.test_dir}/python/empty'

        assert 'success' in client.conf(
            {
                "listeners": {
                    "*:8080": {"pass": "applications/one"},
                    "*:8081": {"pass": "applications/two"},
                },
                "applications": {
                    "one": {
                        "type": "python",
                        "processes": 1,
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                        "isolation": {
                            'cgroup': {'path': path},
                        },
                    },
                    "two": {
                        "type": "python",
                        "processes": 1,
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                        "isolation": {
                            'cgroup': {'path': path2},
                        },
                    },
                },
            }
        )

    set_two_cgroup_path('/scope/python', '/scope/python')
    assert get_cgroup('one') == get_cgroup('two')

    set_two_cgroup_path('/scope/python', '/scope2/python')
    assert get_cgroup('one') != get_cgroup('two')


def test_python_isolation_cgroup_invalid(require):
    require({'privileged_user': True, 'features': {'isolation': ['cgroup']}})

    def check_invalid(path):
        script_path = f'{option.test_dir}/python/empty'
        assert 'error' in client.conf(
            {
                "listeners": {"*:8080": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                        "isolation": {
                            'cgroup': {'path': path},
                        },
                    }
                },
            }
        )

    check_invalid('')
    check_invalid('../scope')
    check_invalid('scope/../python')
