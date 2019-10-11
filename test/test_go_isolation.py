import os
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

        obj = self.isolation.parsejson(self.get()['body'])

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
        obj = self.isolation.parsejson(self.get()['body'])

        self.assertTrue(obj['UID'] != 0, 'uid not zero')
        self.assertTrue(obj['GID'] != 0, 'gid not zero')
        self.assertEqual(obj['UID'], os.getuid(), 'uid match')
        self.assertEqual(obj['GID'], os.getgid(), 'gid match')

        self.conf_isolation({"namespaces": {"credential": True}})

        obj = self.isolation.parsejson(self.get()['body'])

        # default uid and gid maps current user to nobody
        self.assertEqual(obj['UID'], 65534, 'uid nobody')
        self.assertEqual(obj['GID'], 65534, 'gid nobody')

        self.conf_isolation(
            {
                "namespaces": {"credential": True},
                "uidmap": [
                    {"container": 1000, "host": os.geteuid(), "size": 1}
                ],
                "gidmap": [
                    {"container": 1000, "host": os.getegid(), "size": 1}
                ],
            }
        )

        obj = self.isolation.parsejson(self.get()['body'])

        # default uid and gid maps current user to root
        self.assertEqual(obj['UID'], 1000, 'uid root')
        self.assertEqual(obj['GID'], 1000, 'gid root')

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

        obj = self.isolation.parsejson(self.get()['body'])

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

        obj = self.isolation.parsejson(self.get()['body'])

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

        obj = self.isolation.parsejson(self.get()['body'])

        for ns in allns:
            if ns.upper() in obj['NS']:
                self.assertEqual(
                    obj['NS'][ns.upper()],
                    self.available['features']['isolation'][ns],
                    '%s match' % ns,
                )


if __name__ == '__main__':
    TestGoIsolation.main()
