import grp
import os
import pwd

import pytest

from unit.applications.lang.go import ApplicationGo
from unit.option import option
from unit.utils import getns

prerequisites = {'modules': {'go': 'any'}, 'features': {'isolation': True}}

client = ApplicationGo()


def unpriv_creds():
    nobody_uid = pwd.getpwnam('nobody').pw_uid

    try:
        nogroup_gid = grp.getgrnam('nogroup').gr_gid
        nogroup = 'nogroup'
    except KeyError:
        nogroup_gid = grp.getgrnam('nobody').gr_gid
        nogroup = 'nobody'

    return (nobody_uid, nogroup_gid, nogroup)


def test_isolation_values():
    client.load('ns_inspect')

    obj = client.getjson()['body']

    for ns, ns_value in option.available['features']['isolation'].items():
        if ns.upper() in obj['NS']:
            assert obj['NS'][ns.upper()] == ns_value, f'{ns} match'


def test_isolation_unpriv_user(require):
    require(
        {
            'privileged_user': False,
            'features': {'isolation': ['unprivileged_userns_clone']},
        }
    )

    client.load('ns_inspect')
    obj = client.getjson()['body']

    assert obj['UID'] == os.geteuid(), 'uid match'
    assert obj['GID'] == os.getegid(), 'gid match'

    client.load('ns_inspect', isolation={'namespaces': {'credential': True}})

    obj = client.getjson()['body']

    nobody_uid, nogroup_gid, nogroup = unpriv_creds()

    # unprivileged unit map itself to nobody in the container by default
    assert obj['UID'] == nobody_uid, 'uid of nobody'
    assert obj['GID'] == nogroup_gid, f'gid of {nogroup}'

    client.load(
        'ns_inspect',
        user='root',
        isolation={'namespaces': {'credential': True}},
    )

    obj = client.getjson()['body']

    assert obj['UID'] == 0, 'uid match user=root'
    assert obj['GID'] == 0, 'gid match user=root'

    client.load(
        'ns_inspect',
        user='root',
        group=nogroup,
        isolation={'namespaces': {'credential': True}},
    )

    obj = client.getjson()['body']

    assert obj['UID'] == 0, 'uid match user=root group=nogroup'
    assert obj['GID'] == nogroup_gid, 'gid match user=root group=nogroup'

    client.load(
        'ns_inspect',
        user='root',
        group='root',
        isolation={
            'namespaces': {'credential': True},
            'uidmap': [{'container': 0, 'host': os.geteuid(), 'size': 1}],
            'gidmap': [{'container': 0, 'host': os.getegid(), 'size': 1}],
        },
    )

    obj = client.getjson()['body']

    assert obj['UID'] == 0, 'uid match uidmap'
    assert obj['GID'] == 0, 'gid match gidmap'


def test_isolation_priv_user(require):
    require({'privileged_user': True})

    client.load('ns_inspect')

    nobody_uid, nogroup_gid, nogroup = unpriv_creds()

    obj = client.getjson()['body']

    assert obj['UID'] == nobody_uid, 'uid match'
    assert obj['GID'] == nogroup_gid, 'gid match'

    client.load('ns_inspect', isolation={'namespaces': {'credential': True}})

    obj = client.getjson()['body']

    # privileged unit map app creds in the container by default
    assert obj['UID'] == nobody_uid, 'uid nobody'
    assert obj['GID'] == nogroup_gid, 'gid nobody'

    client.load(
        'ns_inspect',
        user='root',
        isolation={'namespaces': {'credential': True}},
    )

    obj = client.getjson()['body']

    assert obj['UID'] == 0, 'uid nobody user=root'
    assert obj['GID'] == 0, 'gid nobody user=root'

    client.load(
        'ns_inspect',
        user='root',
        group=nogroup,
        isolation={'namespaces': {'credential': True}},
    )

    obj = client.getjson()['body']

    assert obj['UID'] == 0, 'uid match user=root group=nogroup'
    assert obj['GID'] == nogroup_gid, 'gid match user=root group=nogroup'

    client.load(
        'ns_inspect',
        user='root',
        group='root',
        isolation={
            'namespaces': {'credential': True},
            'uidmap': [{'container': 0, 'host': 0, 'size': 1}],
            'gidmap': [{'container': 0, 'host': 0, 'size': 1}],
        },
    )

    obj = client.getjson()['body']

    assert obj['UID'] == 0, 'uid match uidmap user=root'
    assert obj['GID'] == 0, 'gid match gidmap user=root'

    # map 65535 uids
    client.load(
        'ns_inspect',
        user='nobody',
        isolation={
            'namespaces': {'credential': True},
            'uidmap': [{'container': 0, 'host': 0, 'size': nobody_uid + 1}],
        },
    )

    obj = client.getjson()['body']

    assert obj['UID'] == nobody_uid, 'uid match uidmap user=nobody'
    assert obj['GID'] == nogroup_gid, 'gid match uidmap user=nobody'


def test_isolation_mnt(require):
    require(
        {
            'features': {'isolation': ['unprivileged_userns_clone', 'mnt']},
        }
    )

    client.load(
        'ns_inspect',
        isolation={'namespaces': {'mount': True, 'credential': True}},
    )

    obj = client.getjson()['body']

    # all but user and mnt
    allns = list(option.available['features']['isolation'].keys())
    allns.remove('user')
    allns.remove('mnt')

    for ns in allns:
        if ns.upper() in obj['NS']:
            assert (
                obj['NS'][ns.upper()]
                == option.available['features']['isolation'][ns]
            ), f'{ns} match'

    assert obj['NS']['MNT'] != getns('mnt'), 'mnt set'
    assert obj['NS']['USER'] != getns('user'), 'user set'


def test_isolation_pid(is_su, require):
    require({'features': {'isolation': ['pid']}})

    if not is_su:
        require(
            {
                'features': {
                    'isolation': [
                        'unprivileged_userns_clone',
                        'user',
                        'mnt',
                    ]
                }
            }
        )

    isolation = {'namespaces': {'pid': True}}

    if not is_su:
        isolation['namespaces']['mount'] = True
        isolation['namespaces']['credential'] = True

    client.load('ns_inspect', isolation=isolation)

    obj = client.getjson()['body']

    assert obj['PID'] == 2, 'pid of container is 2'


def test_isolation_namespace_false():
    client.load('ns_inspect')
    allns = list(option.available['features']['isolation'].keys())

    remove_list = ['unprivileged_userns_clone', 'ipc', 'cgroup']
    allns = [ns for ns in allns if ns not in remove_list]

    namespaces = {}
    for ns in allns:
        if ns == 'user':
            namespaces['credential'] = False
        elif ns == 'mnt':
            namespaces['mount'] = False
        elif ns == 'net':
            namespaces['network'] = False
        elif ns == 'uts':
            namespaces['uname'] = False
        else:
            namespaces[ns] = False

    client.load('ns_inspect', isolation={'namespaces': namespaces})

    obj = client.getjson()['body']

    for ns in allns:
        if ns.upper() in obj['NS']:
            assert (
                obj['NS'][ns.upper()]
                == option.available['features']['isolation'][ns]
            ), f'{ns} match'


def test_go_isolation_rootfs_container(is_su, require, temp_dir):
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

    isolation = {'rootfs': temp_dir}

    if not is_su:
        isolation['namespaces'] = {
            'mount': True,
            'credential': True,
            'pid': True,
        }

    client.load('ns_inspect', isolation=isolation)

    obj = client.getjson(url='/?file=/go/app')['body']

    assert obj['FileExists'], 'app relative to rootfs'

    obj = client.getjson(url='/?file=/bin/sh')['body']
    assert not obj['FileExists'], 'file should not exists'


def test_go_isolation_rootfs_container_priv(require, temp_dir):
    require({'privileged_user': True, 'features': {'isolation': ['mnt']}})

    isolation = {
        'namespaces': {'mount': True},
        'rootfs': temp_dir,
    }

    client.load('ns_inspect', isolation=isolation)

    obj = client.getjson(url='/?file=/go/app')['body']

    assert obj['FileExists'], 'app relative to rootfs'

    obj = client.getjson(url='/?file=/bin/sh')['body']
    assert not obj['FileExists'], 'file should not exists'


def test_go_isolation_rootfs_automount_tmpfs(is_su, require, temp_dir):
    try:
        open("/proc/self/mountinfo", encoding='utf-8')
    except:
        pytest.skip('The system lacks /proc/self/mountinfo file')

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

    isolation = {'rootfs': temp_dir}

    if not is_su:
        isolation['namespaces'] = {
            'mount': True,
            'credential': True,
            'pid': True,
        }

    isolation['automount'] = {'tmpfs': False}

    client.load('ns_inspect', isolation=isolation)

    obj = client.getjson(url='/?mounts=true')['body']

    assert (
        "/ /tmp" not in obj['Mounts'] and "tmpfs" not in obj['Mounts']
    ), 'app has no /tmp mounted'

    isolation['automount'] = {'tmpfs': True}

    client.load('ns_inspect', isolation=isolation)

    obj = client.getjson(url='/?mounts=true')['body']

    assert (
        "/ /tmp" in obj['Mounts'] and "tmpfs" in obj['Mounts']
    ), 'app has /tmp mounted on /'
