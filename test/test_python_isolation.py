import unittest

from unit.applications.lang.python import TestApplicationPython
from unit.feature.isolation import TestFeatureIsolation


class TestPythonIsolation(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}, 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.testdir)

        return unit if not complete_check else unit.complete()

    def test_python_isolation_rootfs(self):
        isolation_features = self.available['features']['isolation'].keys()

        if 'mnt' not in isolation_features:
            print('requires mnt ns')
            raise unittest.SkipTest()

        if not self.is_su:
            if 'user' not in isolation_features:
                print('requires unprivileged userns or root')
                raise unittest.SkipTest()

            if not 'unprivileged_userns_clone' in isolation_features:
                print('requires unprivileged userns or root')
                raise unittest.SkipTest()

        isolation = {
            'namespaces': {'credential': not self.is_su, 'mount': True},
            'rootfs': self.testdir,
        }

        self.load('empty', isolation=isolation)

        self.assertEqual(self.get()['status'], 200, 'python rootfs')

        self.load('ns_inspect', isolation=isolation)

        self.assertEqual(
            self.getjson(url='/?path=' + self.testdir)['body']['FileExists'],
            False,
            'testdir does not exists in rootfs',
        )

        self.assertEqual(
            self.getjson(url='/?path=/proc/self')['body']['FileExists'],
            False,
            'no /proc/self',
        )

        self.assertEqual(
            self.getjson(url='/?path=/dev/pts')['body']['FileExists'],
            False,
            'no /dev/pts',
        )

        self.assertEqual(
            self.getjson(url='/?path=/sys/kernel')['body']['FileExists'],
            False,
            'no /sys/kernel',
        )

        ret = self.getjson(url='/?path=/app/python/ns_inspect')

        self.assertEqual(
            ret['body']['FileExists'], True, 'application exists in rootfs',
        )


if __name__ == '__main__':
    TestPythonIsolation.main()
