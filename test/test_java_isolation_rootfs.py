import os
import subprocess
import unittest

from unit.applications.lang.java import TestApplicationJava


class TestJavaIsolationRootfs(TestApplicationJava):
    prerequisites = {'modules': {'java': 'all'}}

    def setUp(self):
        if not self.is_su:
            return

        super().setUp()

        os.makedirs(self.testdir + '/jars')
        os.makedirs(self.testdir + '/tmp')
        os.chmod(self.testdir + '/tmp', 0o777)

        try:
            process = subprocess.Popen(
                [
                    "mount",
                    "--bind",
                    self.pardir + "/build",
                    self.testdir + "/jars",
                ],
                stderr=subprocess.STDOUT,
            )

            process.communicate()

        except:
            self.fail('Cann\'t run mount process.')

    def tearDown(self):
        if not self.is_su:
            return

        try:
            process = subprocess.Popen(
                ["umount", "--lazy", self.testdir + "/jars"],
                stderr=subprocess.STDOUT,
            )

            process.communicate()

        except:
            self.fail('Cann\'t run mount process.')

        # super teardown must happen after unmount to avoid deletion of /build
        super().tearDown()

    def test_java_isolation_rootfs_chroot_war(self):
        if not self.is_su:
            print('require root')
            raise unittest.SkipTest()

        isolation = {
            'rootfs': self.testdir,
        }

        self.load('empty_war', isolation=isolation)

        self.assertIn(
            'success',
            self.conf(
                '"/"', '/config/applications/empty_war/working_directory',
            ),
        )

        self.assertIn(
            'success', self.conf('"/jars"', 'applications/empty_war/unit_jars')
        )
        self.assertIn(
            'success',
            self.conf('"/java/empty.war"', 'applications/empty_war/webapp'),
        )

        self.assertEqual(self.get()['status'], 200, 'war')


if __name__ == '__main__':
    TestJavaIsolationRootfs.main()
