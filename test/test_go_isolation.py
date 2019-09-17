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
            self.assertEqual(obj['NS'][ns.upper()], ns_value, '%s match' % ns)

    def test_isolation_user(self):
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
                    {"containerID": 1000, "hostID": os.geteuid(), "size": 1}
                ],
                "gidmap": [
                    {"containerID": 1000, "hostID": os.getegid(), "size": 1}
                ],
            }
        )

        obj = self.isolation.parsejson(self.get()['body'])

        # default uid and gid maps current user to root
        self.assertEqual(obj['UID'], 1000, 'uid root')
        self.assertEqual(obj['GID'], 1000, 'gid root')

    def test_isolation_mnt(self):
        if 'mnt' not in self.available['features']['isolation'].keys():
            print('mnt namespace not supported')
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
        if 'pid' not in self.available['features']['isolation'].keys():
            print('pid namespace not supported')
            raise unittest.SkipTest()

        self.load('ns_inspect')
        self.conf_isolation({"namespaces": {"pid": True, "credential": True}})

        obj = self.isolation.parsejson(self.get()['body'])

        self.assertEqual(obj['PID'], 1, 'pid of container is 1')


if __name__ == '__main__':
    TestGoIsolation.main()
