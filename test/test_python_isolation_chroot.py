import unittest

from unit.applications.lang.python import TestApplicationPython
from unit.feature.isolation import TestFeatureIsolation


class TestPythonIsolation(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_python_isolation_chroot(self):
        if not self.is_su:
            print('requires root')
            raise unittest.SkipTest()

        isolation = {
            'rootfs': self.testdir,
        }

        self.load('empty', isolation=isolation)

        self.assertEqual(self.get()['status'], 200, 'python chroot')

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
