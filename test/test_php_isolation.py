import pytest

from unit.applications.lang.php import TestApplicationPHP
from unit.option import option


class TestPHPIsolation(TestApplicationPHP):
    prerequisites = {'modules': {'php': 'any'}, 'features': ['isolation']}

    def test_php_isolation_rootfs(self, is_su, temp_dir):
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

        self.load('phpinfo', isolation=isolation)

        assert 'success' in self.conf(
            '"/app/php/phpinfo"', 'applications/phpinfo/root'
        )
        assert 'success' in self.conf(
            '"/app/php/phpinfo"', 'applications/phpinfo/working_directory'
        )

        assert self.get()['status'] == 200, 'empty rootfs'

    def test_php_isolation_rootfs_extensions(self, is_su, temp_dir):
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

        self.load('list-extensions', isolation=isolation)

        assert 'success' in self.conf(
            '"/app/php/list-extensions"', 'applications/list-extensions/root'
        )

        assert 'success' in self.conf(
            {'file': '/php/list-extensions/php.ini'},
            'applications/list-extensions/options',
        )

        assert 'success' in self.conf(
            '"/app/php/list-extensions"',
            'applications/list-extensions/working_directory',
        )

        extensions = self.getjson()['body']

        assert 'json' in extensions, 'json in extensions list'
        assert 'unit' in extensions, 'unit in extensions list'
