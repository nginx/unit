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


class TestPythonIsolation(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}, 'features': ['isolation']}

    def get_cgroup(self, app_name):
        output = subprocess.check_output(
            ['ps', 'ax', '-o', 'pid', '-o', 'cmd']
        ).decode()

        pid = re.search(
            r'(\d+)\s*unit: "' + app_name + '" application', output
        ).group(1)

        cgroup = '/proc/' + pid + '/cgroup'

        if not os.path.isfile(cgroup):
            pytest.skip('no cgroup at ' + cgroup)

        with open(cgroup, 'r') as f:
            return f.read().rstrip()

    def test_python_isolation_rootfs(self, is_su, temp_dir):
        isolation_features = option.available['features']['isolation'].keys()

        if not is_su:
            if not 'unprivileged_userns_clone' in isolation_features:
                pytest.skip('requires unprivileged userns or root')

            if 'user' not in isolation_features:
                pytest.skip('user namespace is not supported')

            if 'mnt' not in isolation_features:
                pytest.skip('mnt namespace is not supported')

            if 'pid' not in isolation_features:
                pytest.skip('pid namespace is not supported')

        isolation = {'rootfs': temp_dir}

        if not is_su:
            isolation['namespaces'] = {
                'mount': True,
                'credential': True,
                'pid': True,
            }

        self.load('ns_inspect', isolation=isolation)

        assert (
            self.getjson(url='/?path=' + temp_dir)['body']['FileExists']
            == False
        ), 'temp_dir does not exists in rootfs'

        assert (
            self.getjson(url='/?path=/proc/self')['body']['FileExists'] == True
        ), 'no /proc/self'

        assert (
            self.getjson(url='/?path=/dev/pts')['body']['FileExists'] == False
        ), 'no /dev/pts'

        assert (
            self.getjson(url='/?path=/sys/kernel')['body']['FileExists']
            == False
        ), 'no /sys/kernel'

        ret = self.getjson(url='/?path=/app/python/ns_inspect')

        assert ret['body']['FileExists'] == True, 'application exists in rootfs'

    def test_python_isolation_rootfs_no_language_deps(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        isolation = {'rootfs': temp_dir, 'automount': {'language_deps': False}}
        self.load('empty', isolation=isolation)

        python_path = temp_dir + '/usr'

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

    def test_python_isolation_procfs(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        isolation = {'rootfs': temp_dir, 'automount': {'procfs': False}}

        self.load('ns_inspect', isolation=isolation)

        assert (
            self.getjson(url='/?path=/proc/self')['body']['FileExists'] == False
        ), 'no /proc/self'

        isolation['automount']['procfs'] = True

        self.load('ns_inspect', isolation=isolation)

        assert (
            self.getjson(url='/?path=/proc/self')['body']['FileExists'] == True
        ), '/proc/self'

    def test_python_isolation_cgroup(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        if not 'cgroup' in option.available['features']['isolation']:
            pytest.skip('cgroup is not supported')

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

    def test_python_isolation_cgroup_two(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        if not 'cgroup' in option.available['features']['isolation']:
            pytest.skip('cgroup is not supported')

        def set_two_cgroup_path(path, path2):
            script_path = option.test_dir + '/python/empty'

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

    def test_python_isolation_cgroup_invalid(self, is_su):
        if not is_su:
            pytest.skip('requires root')

        if not 'cgroup' in option.available['features']['isolation']:
            pytest.skip('cgroup is not supported')

        def check_invalid(path):
            script_path = option.test_dir + '/python/empty'
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
