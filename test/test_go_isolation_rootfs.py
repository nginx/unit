from unit.applications.lang.go import ApplicationGo

prerequisites = {
    'modules': {'go': 'all'},
    'features': {'isolation': True},
    'privileged_user': True,
}

client = ApplicationGo()


def test_go_isolation_rootfs_chroot(temp_dir):
    client.load('ns_inspect', isolation={'rootfs': temp_dir})

    obj = client.getjson(url='/?file=/go/app')['body']
    assert obj['FileExists'], 'app relative to rootfs'

    obj = client.getjson(url='/?file=/bin/sh')['body']
    assert not obj['FileExists'], 'file should not exists'
