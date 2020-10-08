import pytest

from conftest import option
from unit.applications.lang.php import TestApplicationPHP
from unit.feature.isolation import TestFeatureIsolation


class TestPHPIsolation(TestApplicationPHP):
    prerequisites = {'modules': {'php': 'any'}, 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setup_class(cls, complete_check=True):
        unit = super().setup_class(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.temp_dir)

        return unit if not complete_check else unit.complete()

    def test_php_isolation_rootfs(self, is_su):
        isolation_features = self.available['features']['isolation'].keys()

        if 'mnt' not in isolation_features:
            pytest.skip('requires mnt ns')

        if not is_su:
            if 'user' not in isolation_features:
                pytest.skip('requires unprivileged userns or root')

            if not 'unprivileged_userns_clone' in isolation_features:
                pytest.skip('requires unprivileged userns or root')

        isolation = {
            'namespaces': {'credential': not is_su, 'mount': True},
            'rootfs': option.test_dir,
        }

        self.load('phpinfo', isolation=isolation)

        assert 'success' in self.conf(
            '"/php/phpinfo"', 'applications/phpinfo/root'
        )
        assert 'success' in self.conf(
            '"/php/phpinfo"', 'applications/phpinfo/working_directory'
        )

        assert self.get()['status'] == 200, 'empty rootfs'

    def test_php_isolation_rootfs_extensions(self, is_su):
        isolation_features = self.available['features']['isolation'].keys()

        if not is_su:
            if 'user' not in isolation_features:
                pytest.skip('requires unprivileged userns or root')

            if not 'unprivileged_userns_clone' in isolation_features:
                pytest.skip('requires unprivileged userns or root')

            if 'mnt' not in isolation_features:
                pytest.skip('requires mnt ns')

        isolation = {
            'rootfs': option.test_dir,
            'namespaces': {'credential': not is_su, 'mount': not is_su},
        }

        self.load('list-extensions', isolation=isolation)

        assert 'success' in self.conf(
            '"/php/list-extensions"', 'applications/list-extensions/root'
        )

        assert 'success' in self.conf(
            {'file': '/php/list-extensions/php.ini'},
            'applications/list-extensions/options',
        )

        assert 'success' in self.conf(
            '"/php/list-extensions"',
            'applications/list-extensions/working_directory',
        )

        extensions = self.getjson()['body']

        assert 'json' in extensions, 'json in extensions list'
        assert 'unit' in extensions, 'unit in extensions list'
