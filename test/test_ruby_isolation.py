from unit.applications.lang.ruby import TestApplicationRuby

prerequisites = {'modules': {'ruby': 'any'}, 'features': {'isolation': True}}


class TestRubyIsolation(TestApplicationRuby):
    def test_ruby_isolation_rootfs(self, is_su, require, temp_dir):
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

        self.load('status_int', isolation=isolation)

        assert 'success' in self.conf(
            '"/ruby/status_int/config.ru"',
            'applications/status_int/script',
        )

        assert 'success' in self.conf(
            '"/ruby/status_int"',
            'applications/status_int/working_directory',
        )

        assert self.get()['status'] == 200, 'status int'
