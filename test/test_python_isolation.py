import pytest

from unit.applications.lang.python import TestApplicationPython
from unit.option import option
from unit.utils import findmnt
from unit.utils import waitformount
from unit.utils import waitforunmount


class TestPythonIsolation(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}, 'features': ['isolation']}

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

        assert (
            ret['body']['FileExists'] == True
        ), 'application exists in rootfs'

    def test_python_isolation_rootfs_no_language_deps(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        isolation = {'rootfs': temp_dir, 'automount': {'language_deps': False}}

        self.load('empty', isolation=isolation)

        assert findmnt().find(temp_dir) == -1
        assert self.get()['status'] != 200, 'disabled language_deps'
        assert findmnt().find(temp_dir) == -1

        isolation['automount']['language_deps'] = True

        self.load('empty', isolation=isolation)

        assert findmnt().find(temp_dir) == -1
        assert self.get()['status'] == 200, 'enabled language_deps'
        assert waitformount(temp_dir), 'language_deps mount'

        self.conf({"listeners": {}, "applications": {}})

        assert waitforunmount(temp_dir), 'language_deps unmount'

    def test_python_isolation_procfs(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        isolation = {'rootfs': temp_dir, 'automount': {'procfs': False}}

        self.load('ns_inspect', isolation=isolation)

        assert (
            self.getjson(url='/?path=/proc/self')['body']['FileExists']
            == False
        ), 'no /proc/self'

        isolation['automount']['procfs'] = True

        self.load('ns_inspect', isolation=isolation)

        assert (
            self.getjson(url='/?path=/proc/self')['body']['FileExists'] == True
        ), '/proc/self'
