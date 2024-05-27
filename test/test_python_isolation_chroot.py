from unit.applications.lang.python import ApplicationPython

prerequisites = {'modules': {'python': 'any'}, 'privileged_user': True}

client = ApplicationPython()


def test_python_isolation_chroot(temp_dir):
    client.load('ns_inspect', isolation={'rootfs': temp_dir})

    assert not (
        client.getjson(url=f'/?path={temp_dir}')['body']['FileExists']
    ), 'temp_dir does not exists in rootfs'

    assert client.getjson(url='/?path=/proc/self')['body'][
        'FileExists'
    ], 'no /proc/self'

    assert not (
        client.getjson(url='/?path=/dev/pts')['body']['FileExists']
    ), 'no /dev/pts'

    assert not (
        client.getjson(url='/?path=/sys/kernel')['body']['FileExists']
    ), 'no /sys/kernel'

    ret = client.getjson(url='/?path=/app/python/ns_inspect')

    assert ret['body']['FileExists'], 'application exists in rootfs'
