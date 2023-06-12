import os
import re
import subprocess
from pathlib import Path

import pytest
from unit.applications.lang.python import TestApplicationPython
from unit.option import option
from unit.utils import findmnt
from unit.utils import waitformount
from unit.utils import waitforunmount

prerequisites = {'modules': {'python': 'any'}, 'features': {'isolation': True}}


class TestPythonIsolation(TestApplicationPython):
    def get_cgroup(self, app_name):
        output = subprocess.check_output(
            ['ps', 'ax', '-o', 'pid', '-o', 'cmd']
        ).decode()

        pid = re.search(
            fr'(\d+)\s*unit: "{app_name}" application', output
        ).group(1)

        cgroup = f'/proc/{pid}/cgroup'

        if not os.path.isfile(cgroup):
            pytest.skip(f'no cgroup at {cgroup}')

        with open(cgroup, 'r') as f:
            return f.read().rstrip()

    def test_python_isolation_rootfs(self, is_su, require, temp_dir):
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

        self.load('ns_inspect', isolation=isolation)

        assert not (
            self.getjson(url=f'/?path={temp_dir}')['body']['FileExists']
        ), 'temp_dir does not exists in rootfs'

        assert self.getjson(url='/?path=/proc/self')['body'][
            'FileExists'
        ], 'no /proc/self'

        assert not (
            self.getjson(url='/?path=/dev/pts')['body']['FileExists']
        ), 'no /dev/pts'

        assert not (
            self.getjson(url='/?path=/sys/kernel')['body']['FileExists']
        ), 'no /sys/kernel'

        ret = self.getjson(url='/?path=/app/python/ns_inspect')

        assert ret['body']['FileExists'], 'application exists in rootfs'

    def test_python_isolation_rootfs_no_language_deps(self, require, temp_dir):
        require({'privileged_user': True})

        isolation = {'rootfs': temp_dir, 'automount': {'language_deps': False}}
        self.load('empty', isolation=isolation)

        python_path = f'{temp_dir}/usr'

        assert findmnt().find(python_path) == -1
        assert self.get()['status'] != 200, 'disabled language_deps'
        assert findmnt().find(python_path) == -1

        isolation['automount']['language_deps'] = True

        self.load('empty', isolation=isolation)

        assert findmnt().find(python_path) == -1
        assert self.get()['status'] == 200, 'enabled language_deps'
        assert waitformount(python_path), 'language_deps mount'

        self.conf({"listeners": {}, "applications": {}})

        assert waitforunmount(python_path), 'language_deps unmount'

    def test_python_isolation_procfs(self, require, temp_dir):
        require({'privileged_user': True})

        isolation = {'rootfs': temp_dir, 'automount': {'procfs': False}}

        self.load('ns_inspect', isolation=isolation)

        assert not (
            self.getjson(url='/?path=/proc/self')['body']['FileExists']
        ), 'no /proc/self'

        isolation['automount']['procfs'] = True

        self.load('ns_inspect', isolation=isolation)

        assert self.getjson(url='/?path=/proc/self')['body'][
            'FileExists'
        ], '/proc/self'

    def test_python_isolation_cgroup(self, require):
        require(
            {'privileged_user': True, 'features': {'isolation': ['cgroup']}}
        )

        def set_cgroup_path(path):
            isolation = {'cgroup': {'path': path}}
            self.load('empty', processes=1, isolation=isolation)

        set_cgroup_path('scope/python')

        cgroup_rel = Path(self.get_cgroup('empty'))
        assert cgroup_rel.parts[-2:] == ('scope', 'python'), 'cgroup rel'

        set_cgroup_path('/scope2/python')

        cgroup_abs = Path(self.get_cgroup('empty'))
        assert cgroup_abs.parts[-2:] == ('scope2', 'python'), 'cgroup abs'

        assert len(cgroup_rel.parts) >= len(cgroup_abs.parts)

    def test_python_isolation_cgroup_two(self, require):
        require(
            {'privileged_user': True, 'features': {'isolation': ['cgroup']}}
        )

        def set_two_cgroup_path(path, path2):
            script_path = f'{option.test_dir}/python/empty'

            assert 'success' in self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "applications/one"},
                        "*:7081": {"pass": "applications/two"},
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
        assert self.get_cgroup('one') == self.get_cgroup('two')

        set_two_cgroup_path('/scope/python', '/scope2/python')
        assert self.get_cgroup('one') != self.get_cgroup('two')

    def test_python_isolation_cgroup_invalid(self, require):
        require(
            {'privileged_user': True, 'features': {'isolation': ['cgroup']}}
        )

        def check_invalid(path):
            script_path = f'{option.test_dir}/python/empty'
            assert 'error' in self.conf(
                {
                    "listeners": {"*:7080": {"pass": "applications/empty"}},
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
