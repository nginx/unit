from unit.applications.lang.go import TestApplicationGo
import unittest
import os
import json

def getns(nstype):
    # read namespace id from link file:
    # it points to: '<nstype>:[<ns id>]'
    # # eg.: 'pid:[4026531836]' 
    data = os.readlink("/proc/self/ns/%s" % nstype)[len(nstype) + 2 : -1]
    return int(data)

def parsejson(data):
    parts = data.split("\n")
    return json.loads(parts[1])

class TestIsolation(TestApplicationGo):
    prerequisites = ['go']

    @classmethod
    def setUpClass(cls):
        allns = ["user", "pid", "mnt", "ipc", "uts", "cgroup", "net"]
        cls._availablens = {}

        for i in range(len(allns)):
            try:
                ns = getns(allns[i])
            except:
                continue

            cls._availablens[allns[i]] = ns
        
        if len(cls._availablens) == 0:
            raise unittest.SkipTest("namespace not supported")

    def test_no_isolation(self):
        self.load('ns_inspect', isolation={}, assert_conf=True)

        body = self.get()['body']
        obj = parsejson(body)

        nsnames = list(self._availablens.keys())
        for i in range(len(nsnames)):
            self.assertEqual(obj["NS"][nsnames[i].upper()], 
                            self._availablens[nsnames[i]], "%s not equal" % nsnames[i])
    
    @unittest.skip('not yet')
    def test_user_isolation_enforced(self):
        isolation = {
            "namespaces": {
                "mount": True,
            }
        }

        conf_status = self.load('ns_inspect', isolation=isolation, assert_conf=False)

        if 'success' in conf_status and os.getuid() is not 0:
            self.fail("requires userns if unprivileged unit")
        
    def test_mnt_isolation(self):
        if (not self._availablens.get("mnt") and 
            not self._availablens.get("user")):
            raise unittest.SkipTest("mnt or user namespace not supported")

        isolation = {
            "namespaces": {
                "mount": True,
                "user": True,
            }
        }

        self.load('ns_inspect', isolation=isolation, assert_conf=True)

        body = self.get()['body']
        obj = parsejson(body)
    
        # all but user and mnt
        ns = list(self._availablens.keys())
        ns.remove("user")
        ns.remove("mnt")

        for i in range(len(ns)):
            self.assertEqual(obj["NS"][ns[i].upper()], 
                            self._availablens[ns[i]], "%s not equal" % ns[i])

        self.assertNotEqual(obj["NS"]["MNT"], getns("mnt"), "mnt ns not set")
        self.assertNotEqual(obj["NS"]["USER"], getns("user"), "user ns not set")

if __name__ == '__main__':
    TestIsolation.main()
        