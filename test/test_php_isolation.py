from unit.applications.lang.php import TestApplicationPHP

prerequisites = {'modules': {'php': 'any'}, 'features': {'isolation': True}}


class TestPHPIsolation(TestApplicationPHP):
    def test_php_isolation_rootfs(self, is_su, require, temp_dir):
        isolation = {'rootfs': temp_dir}

        if not is_su:
            require(
                {
                    'features': {
                        'isolation': [
                            'unprivileged_userns_clone',
                            'user',
                            'mnt',
                            'pid',
                        ]
                    }
                }
            )

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

    def test_php_isolation_rootfs_extensions(self, is_su, require, temp_dir):
        isolation = {'rootfs': temp_dir}

        if not is_su:
            require(
                {
                    'features': {
                        'isolation': [
                            'unprivileged_userns_clone',
                            'user',
                            'mnt',
                            'pid',
                        ]
                    }
                }
            )

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
