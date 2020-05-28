import os
import shutil
import unittest

from unit.applications.lang.ruby import TestApplicationRuby
from unit.feature.isolation import TestFeatureIsolation


class TestRubyIsolation(TestApplicationRuby):
    prerequisites = {'modules': {'ruby': 'any'}, 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.testdir)

        return unit if not complete_check else unit.complete()

    def test_ruby_isolation_rootfs(self):
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

        os.mkdir(self.testdir + '/ruby')

        shutil.copytree(
            self.current_dir + '/ruby/status_int',
            self.testdir + '/ruby/status_int',
        )
        isolation = {
            'namespaces': {'credential': not self.is_su, 'mount': True},
            'rootfs': self.testdir,
        }

        self.load('status_int', isolation=isolation)

        self.assertIn(
            'success',
            self.conf(
                '"/ruby/status_int/config.ru"',
                'applications/status_int/script',
            ),
        )

        self.assertIn(
            'success',
            self.conf(
                '"/ruby/status_int"',
                'applications/status_int/working_directory',
            ),
        )

        self.assertEqual(self.get()['status'], 200, 'status int')


if __name__ == '__main__':
    TestRubyIsolation.main()
