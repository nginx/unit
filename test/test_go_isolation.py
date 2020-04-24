import pwd
import grp
import json
import unittest
from unit.applications.lang.go import TestApplicationGo
from unit.feature.isolation import TestFeatureIsolation


class TestGoIsolation(TestApplicationGo):
    prerequisites = {'modules': {'go': 'any'}, 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.testdir)

        return unit if not complete_check else unit.complete()

    def unpriv_creds(self):
        nobody_uid = pwd.getpwnam('nobody').pw_uid

        try:
            nogroup_gid = grp.getgrnam('nogroup').gr_gid
            nogroup = 'nogroup'
        except:
            nogroup_gid = grp.getgrnam('nobody').gr_gid
            nogroup = 'nobody'

        return (nobody_uid, nogroup_gid, nogroup)

    def isolation_key(self, key):
        return key in self.available['features']['isolation'].keys()

    def test_isolation_values(self):
        self.load('ns_inspect')

        obj = self.getjson()['body']

        for ns, ns_value in self.available['features']['isolation'].items():
            if ns.upper() in obj['NS']:
                self.assertEqual(
                    obj['NS'][ns.upper()], ns_value, '%s match' % ns
                )

    def test_isolation_unpriv_user(self):
        if not self.isolation_key('unprivileged_userns_clone'):
            print('unprivileged clone is not available')
            raise unittest.SkipTest()

        if self.is_su:
            print('privileged tests, skip this')
            raise unittest.SkipTest()

        self.load('ns_inspect')
        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], self.uid, 'uid match')
        self.assertEqual(obj['GID'], self.gid, 'gid match')

        self.load('ns_inspect', isolation={'namespaces': {'credential': True}})

        obj = self.getjson()['body']

        nobody_uid, nogroup_gid, nogroup = self.unpriv_creds()

        # unprivileged unit map itself to nobody in the container by default
        self.assertEqual(obj['UID'], nobody_uid, 'uid of nobody')
        self.assertEqual(obj['GID'], nogroup_gid, 'gid of %s' % nogroup)

        self.load(
            'ns_inspect',
            user='root',
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], 0, 'uid match user=root')
        self.assertEqual(obj['GID'], 0, 'gid match user=root')

        self.load(
            'ns_inspect',
            user='root',
            group=nogroup,
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], 0, 'uid match user=root group=nogroup')
        self.assertEqual(
            obj['GID'], nogroup_gid, 'gid match user=root group=nogroup'
        )

        self.load(
            'ns_inspect',
            user='root',
            group='root',
            isolation={
                'namespaces': {'credential': True},
                'uidmap': [{'container': 0, 'host': self.uid, 'size': 1}],
                'gidmap': [{'container': 0, 'host': self.gid, 'size': 1}],
            },
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], 0, 'uid match uidmap')
        self.assertEqual(obj['GID'], 0, 'gid match gidmap')

    def test_isolation_priv_user(self):
        if not self.is_su:
            print('unprivileged tests, skip this')
            raise unittest.SkipTest()

        self.load('ns_inspect')

        nobody_uid, nogroup_gid, nogroup = self.unpriv_creds()

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], nobody_uid, 'uid match')
        self.assertEqual(obj['GID'], nogroup_gid, 'gid match')

        self.load('ns_inspect', isolation={'namespaces': {'credential': True}})

        obj = self.getjson()['body']

        # privileged unit map app creds in the container by default
        self.assertEqual(obj['UID'], nobody_uid, 'uid nobody')
        self.assertEqual(obj['GID'], nogroup_gid, 'gid nobody')

        self.load(
            'ns_inspect',
            user='root',
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], 0, 'uid nobody user=root')
        self.assertEqual(obj['GID'], 0, 'gid nobody user=root')

        self.load(
            'ns_inspect',
            user='root',
            group=nogroup,
            isolation={'namespaces': {'credential': True}},
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], 0, 'uid match user=root group=nogroup')
        self.assertEqual(
            obj['GID'], nogroup_gid, 'gid match user=root group=nogroup'
        )

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

        self.assertEqual(obj['UID'], 0, 'uid match uidmap user=root')
        self.assertEqual(obj['GID'], 0, 'gid match gidmap user=root')

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

        self.assertEqual(
            obj['UID'], nobody_uid, 'uid match uidmap user=nobody'
        )
        self.assertEqual(
            obj['GID'], nogroup_gid, 'gid match uidmap user=nobody'
        )

    def test_isolation_mnt(self):
        if not self.isolation_key('mnt'):
            print('mnt namespace is not supported')
            raise unittest.SkipTest()

        if not self.isolation_key('unprivileged_userns_clone'):
            print('unprivileged clone is not available')
            raise unittest.SkipTest()

        self.load(
            'ns_inspect',
            isolation={'namespaces': {'mount': True, 'credential': True}},
        )

        obj = self.getjson()['body']

        # all but user and mnt
        allns = list(self.available['features']['isolation'].keys())
        allns.remove('user')
        allns.remove('mnt')

        for ns in allns:
            if ns.upper() in obj['NS']:
                self.assertEqual(
                    obj['NS'][ns.upper()],
                    self.available['features']['isolation'][ns],
                    '%s match' % ns,
                )

        self.assertNotEqual(
            obj['NS']['MNT'], self.isolation.getns('mnt'), 'mnt set'
        )
        self.assertNotEqual(
            obj['NS']['USER'], self.isolation.getns('user'), 'user set'
        )

    def test_isolation_pid(self):
        if not self.isolation_key('pid'):
            print('pid namespace is not supported')
            raise unittest.SkipTest()

        if not (self.is_su or self.isolation_key('unprivileged_userns_clone')):
            print('requires root or unprivileged_userns_clone')
            raise unittest.SkipTest()

        self.load(
            'ns_inspect',
            isolation={'namespaces': {'pid': True, 'credential': True}},
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['PID'], 1, 'pid of container is 1')

    def test_isolation_namespace_false(self):
        self.load('ns_inspect')
        allns = list(self.available['features']['isolation'].keys())

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
                self.assertEqual(
                    obj['NS'][ns.upper()],
                    self.available['features']['isolation'][ns],
                    '%s match' % ns,
                )


if __name__ == '__main__':
    TestGoIsolation.main()
