import pwd
import grp
import json
import unittest
from unit.applications.lang.go import TestApplicationGo
from unit.feature.isolation import TestFeatureIsolation


class TestGoIsolation(TestApplicationGo):
    prerequisites = {'modules': ['go'], 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.testdir)

        return unit if not complete_check else unit.complete()

    def isolation_key(self, key):
        return key in self.available['features']['isolation'].keys()

    def conf_isolation(self, isolation):
        self.assertIn(
            'success',
            self.conf(isolation, 'applications/ns_inspect/isolation'),
            'configure isolation',
        )

    def test_isolation_values(self):
        self.load('ns_inspect')

        obj = self.getjson()['body']

        for ns, ns_value in self.available['features']['isolation'].items():
            if ns.upper() in obj['NS']:
                self.assertEqual(
                    obj['NS'][ns.upper()], ns_value, '%s match' % ns
                )

    def test_isolation_user(self):
        if not self.isolation_key('unprivileged_userns_clone'):
            print('unprivileged clone is not available')
            raise unittest.SkipTest()

        self.load('ns_inspect')

        user_id = pwd.getpwnam('nobody').pw_uid

        try:
            group_id = grp.getgrnam('nogroup').gr_gid
        except:
            group_id = grp.getgrnam('nobody').gr_gid

        obj = self.getjson()['body']

        self.assertTrue(obj['UID'] != 0, 'uid not zero')
        self.assertTrue(obj['GID'] != 0, 'gid not zero')

        if self.is_su:
            self.assertEqual(obj['UID'], user_id, 'uid match')
            self.assertEqual(obj['GID'], group_id, 'gid match')
        else:
            self.assertEqual(obj['UID'], self.uid, 'uid match')
            self.assertEqual(obj['GID'], self.gid, 'gid match')

        self.conf_isolation({"namespaces": {"credential": True}})

        obj = self.getjson()['body']

        # default uid and gid maps current user to nobody
        self.assertEqual(obj['UID'], user_id, 'uid nobody')
        self.assertEqual(obj['GID'], group_id, 'gid nobody')

        self.conf_isolation(
            {
                "namespaces": {"credential": True},
                "uidmap": [
                    {"container": user_id, "host": self.uid, "size": 1}
                ],
                "gidmap": [
                    {"container": group_id, "host": self.gid, "size": 1}
                ],
            }
        )

        obj = self.getjson()['body']

        self.assertEqual(obj['UID'], user_id, 'uid match')
        self.assertEqual(obj['GID'], group_id, 'gid match')

    def test_isolation_mnt(self):
        if not self.isolation_key('mnt'):
            print('mnt namespace is not supported')
            raise unittest.SkipTest()

        if not self.isolation_key('unprivileged_userns_clone'):
            print('unprivileged clone is not available')
            raise unittest.SkipTest()

        self.load('ns_inspect')
        self.conf_isolation(
            {"namespaces": {"mount": True, "credential": True}}
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

        if not self.isolation_key('unprivileged_userns_clone'):
            print('unprivileged clone is not available')
            raise unittest.SkipTest()

        self.load('ns_inspect')
        self.conf_isolation({"namespaces": {"pid": True, "credential": True}})

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

        self.conf_isolation({"namespaces": namespaces})

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
