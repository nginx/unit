import unittest

from unit.applications.lang.php import TestApplicationPHP
from unit.feature.isolation import TestFeatureIsolation


class TestPHPIsolation(TestApplicationPHP):
    prerequisites = {'modules': {'php': 'any'}, 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.testdir)

        return unit if not complete_check else unit.complete()

    def test_php_isolation_rootfs(self):
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
            'rootfs': self.current_dir,
        }

        self.load('phpinfo', isolation=isolation)

        self.assertIn(
            'success', self.conf('"/php/phpinfo"', 'applications/phpinfo/root')
        )
        self.assertIn(
            'success',
            self.conf(
                '"/php/phpinfo"', 'applications/phpinfo/working_directory'
            ),
        )

        self.assertEqual(self.get()['status'], 200, 'empty rootfs')


if __name__ == '__main__':
    TestPHPIsolation.main()
