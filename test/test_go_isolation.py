import grp
import os
import pwd

import pytest
from unit.applications.lang.go import TestApplicationGo
from unit.option import option
from unit.utils import getns

class TestGoIsolation(TestApplicationGo):
    prerequisites = {'modules': {'go': 'any'}, 'features': ['isolation']}

    def unpriv_creds(self):
        nobody_uid = pwd.getpwnam('nobody').pw_uid

        try:
            nogroup_gid = grp.getgrnam('nogroup').gr_gid
            nogroup = 'nogroup'
        except KeyError:
            nogroup_gid = grp.getgrnam('nobody').gr_gid
            nogroup = 'nobody'

        return (nobody_uid, nogroup_gid, nogroup)

    def isolation_key(self, key):
        return key in option.available['features']['isolation'].keys()

    def test_isolation_values(self):
        self.load('ns_inspect')

        obj = self.getjson()['body']

        for ns, ns_value in option.available['features']['isolation'].items():
            if ns.upper() in obj['NS']:
                assert obj['NS'][ns.upper()] == ns_value, '%s match' % ns

    def test_isolation_unpriv_user(self, is_su):
        if not self.isolation_key('unprivileged_userns_clone'):
            pytest.skip('unprivileged clone is not available')

        if is_su:
            pytest.skip('privileged tests, skip this')

        self.load('ns_inspect')
        obj = self.getjson()['body']

        assert obj['UID'] == os.geteuid(), 'uid match'
        assert obj['GID'] == os.getegid(), 'gid match'

        self.load('ns_inspect', isolation={'namespaces': {'credential': True}})

        obj = self.getjson()['body']

        nobody_uid, nogroup_gid, nogroup = self.unpriv_creds()

        # unprivileged unit map itself to nobody in the container by default
        assert obj['UID'] == nobody_uid, 'uid of nobody'
        assert obj['GID'] == nogroup_gid, 'gid of %s' % nogroup

        self.load(
            'ns_inspect',
            user='root',
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        assert obj['UID'] == 0, 'uid match user=root'
        assert obj['GID'] == 0, 'gid match user=root'

        self.load(
            'ns_inspect',
            user='root',
            group=nogroup,
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        assert obj['UID'] == 0, 'uid match user=root group=nogroup'
        assert obj['GID'] == nogroup_gid, 'gid match user=root group=nogroup'

        self.load(
            'ns_inspect',
            user='root',
            group='root',
            isolation={
                'namespaces': {'credential': True},
                'uidmap': [{'container': 0, 'host': os.geteuid(), 'size': 1}],
                'gidmap': [{'container': 0, 'host': os.getegid(), 'size': 1}],
            },
        )

        obj = self.getjson()['body']

        assert obj['UID'] == 0, 'uid match uidmap'
        assert obj['GID'] == 0, 'gid match gidmap'

    def test_isolation_priv_user(self, is_su):
        if not is_su:
            pytest.skip('unprivileged tests, skip this')

        self.load('ns_inspect')

        nobody_uid, nogroup_gid, nogroup = self.unpriv_creds()

        obj = self.getjson()['body']

        assert obj['UID'] == nobody_uid, 'uid match'
        assert obj['GID'] == nogroup_gid, 'gid match'

        self.load('ns_inspect', isolation={'namespaces': {'credential': True}})

        obj = self.getjson()['body']

        # privileged unit map app creds in the container by default
        assert obj['UID'] == nobody_uid, 'uid nobody'
        assert obj['GID'] == nogroup_gid, 'gid nobody'

        self.load(
            'ns_inspect',
            user='root',
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        assert obj['UID'] == 0, 'uid nobody user=root'
        assert obj['GID'] == 0, 'gid nobody user=root'

        self.load(
            'ns_inspect',
            user='root',
            group=nogroup,
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        assert obj['UID'] == 0, 'uid match user=root group=nogroup'
        assert obj['GID'] == nogroup_gid, 'gid match user=root group=nogroup'

        self.load(
            'ns_inspect',
            user='root',
            group='root',
            isolation={
                'namespaces': {'credential': True},
                'uidmap': [{'container': 0, 'host': 0, 'size': 1}],
                'gidmap': [{'container': 0, 'host': 0, 'size': 1}],
            },
        )

        obj = self.getjson()['body']

        assert obj['UID'] == 0, 'uid match uidmap user=root'
        assert obj['GID'] == 0, 'gid match gidmap user=root'

        # map 65535 uids
        self.load(
            'ns_inspect',
            user='nobody',
            isolation={
                'namespaces': {'credential': True},
                'uidmap': [
                    {'container': 0, 'host': 0, 'size': nobody_uid + 1}
                ],
            },
        )

        obj = self.getjson()['body']

        assert obj['UID'] == nobody_uid, 'uid match uidmap user=nobody'
        assert obj['GID'] == nogroup_gid, 'gid match uidmap user=nobody'

    def test_isolation_mnt(self):
        if not self.isolation_key('mnt'):
            pytest.skip('mnt namespace is not supported')

        if not self.isolation_key('unprivileged_userns_clone'):
            pytest.skip('unprivileged clone is not available')

        self.load(
            'ns_inspect',
            isolation={'namespaces': {'mount': True, 'credential': True}},
        )

        obj = self.getjson()['body']

        # all but user and mnt
        allns = list(option.available['features']['isolation'].keys())
        allns.remove('user')
        allns.remove('mnt')

        for ns in allns:
            if ns.upper() in obj['NS']:
                assert (
                    obj['NS'][ns.upper()]
                    == option.available['features']['isolation'][ns]
                ), ('%s match' % ns)

        assert obj['NS']['MNT'] != getns('mnt'), 'mnt set'
        assert obj['NS']['USER'] != getns('user'), 'user set'

    def test_isolation_pid(self, is_su):
        if not self.isolation_key('pid'):
            pytest.skip('pid namespace is not supported')

        if not is_su:
            if not self.isolation_key('unprivileged_userns_clone'):
                pytest.skip('unprivileged clone is not available')

            if not self.isolation_key('user'):
                pytest.skip('user namespace is not supported')

            if not self.isolation_key('mnt'):
                pytest.skip('mnt namespace is not supported')

        isolation = {'namespaces': {'pid': True}}

        if not is_su:
            isolation['namespaces']['mount'] = True
            isolation['namespaces']['credential'] = True

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson()['body']

        assert obj['PID'] == 1, 'pid of container is 1'

    def test_isolation_namespace_false(self):
        self.load('ns_inspect')
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

        self.load('ns_inspect', isolation={'namespaces': namespaces})

        obj = self.getjson()['body']

        for ns in allns:
            if ns.upper() in obj['NS']:
                assert (
                    obj['NS'][ns.upper()]
                    == option.available['features']['isolation'][ns]
                ), ('%s match' % ns)

    def test_go_isolation_rootfs_container(self, is_su, temp_dir):
        if not is_su:
            if not self.isolation_key('unprivileged_userns_clone'):
                pytest.skip('unprivileged clone is not available')

            if not self.isolation_key('user'):
                pytest.skip('user namespace is not supported')

            if not self.isolation_key('mnt'):
                pytest.skip('mnt namespace is not supported')

            if not self.isolation_key('pid'):
                pytest.skip('pid namespace is not supported')

        isolation = {'rootfs': temp_dir}

        if not is_su:
            isolation['namespaces'] = {
                'mount': True,
                'credential': True,
                'pid': True
            }

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson(url='/?file=/go/app')['body']

        assert obj['FileExists'] == True, 'app relative to rootfs'

        obj = self.getjson(url='/?file=/bin/sh')['body']
        assert obj['FileExists'] == False, 'file should not exists'

    def test_go_isolation_rootfs_container_priv(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        if not self.isolation_key('mnt'):
            pytest.skip('mnt namespace is not supported')

        isolation = {
            'namespaces': {'mount': True},
            'rootfs': temp_dir,
        }

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson(url='/?file=/go/app')['body']

        assert obj['FileExists'] == True, 'app relative to rootfs'

        obj = self.getjson(url='/?file=/bin/sh')['body']
        assert obj['FileExists'] == False, 'file should not exists'

    def test_go_isolation_rootfs_automount_tmpfs(self, is_su, temp_dir):
        try:
            open("/proc/self/mountinfo")
        except:
            pytest.skip('The system lacks /proc/self/mountinfo file')

        if not is_su:
            if not self.isolation_key('unprivileged_userns_clone'):
                pytest.skip('unprivileged clone is not available')

            if not self.isolation_key('user'):
                pytest.skip('user namespace is not supported')

            if not self.isolation_key('mnt'):
                pytest.skip('mnt namespace is not supported')

            if not self.isolation_key('pid'):
                pytest.skip('pid namespace is not supported')

        isolation = {'rootfs': temp_dir}

        if not is_su:
            isolation['namespaces'] = {
                'mount': True,
                'credential': True,
                'pid': True
            }

        isolation['automount'] = {
            'tmpfs': False
        }

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson(url='/?mounts=true')['body']

        assert (
            "/ /tmp" not in obj['Mounts'] and "tmpfs" not in obj['Mounts']
        ), 'app has no /tmp mounted'

        isolation['automount'] = {
            'tmpfs': True
        }

        self.load('ns_inspect', isolation=isolation)

        obj = self.getjson(url='/?mounts=true')['body']

        assert (
            "/ /tmp" in obj['Mounts'] and "tmpfs" in obj['Mounts']
        ), 'app has /tmp mounted on /'
