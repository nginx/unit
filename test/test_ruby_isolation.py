from unit.applications.lang.ruby import ApplicationRuby

prerequisites = {'modules': {'ruby': 'any'}, 'features': {'isolation': True}}

client = ApplicationRuby()


def test_ruby_isolation_rootfs(is_su, require, temp_dir):
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

    client.load('status_int', isolation=isolation)

    assert 'success' in client.conf(
        '"/ruby/status_int/config.ru"',
        'applications/status_int/script',
    )

    assert 'success' in client.conf(
        '"/ruby/status_int"',
        'applications/status_int/working_directory',
    )

    assert client.get()['status'] == 200, 'status int'
