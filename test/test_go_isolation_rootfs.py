import os
import unittest

from unit.applications.lang.go import TestApplicationGo


class TestGoIsolationRootfs(TestApplicationGo):
    prerequisites = {'modules': {'go': 'all'}}

    def test_go_isolation_rootfs_chroot(self):
        if not self.is_su:
            print("requires root")
            raise unittest.SkipTest()

        if os.uname().sysname == 'Darwin':
            print('chroot tests not supported on OSX')
            raise unittest.SkipTest()

        isolation = {
            'rootfs': self.testdir,
        }

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson(url='/?file=/go/app')['body']

        self.assertEqual(obj['FileExists'], True, 'app relative to rootfs')

        obj = self.getjson(url='/?file=/bin/sh')['body']
        self.assertEqual(obj['FileExists'], False, 'file should not exists')


if __name__ == '__main__':
    TestGoIsolationRootfs.main()
