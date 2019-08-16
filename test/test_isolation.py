from unit.applications.lang.go import TestApplicationGo
import unittest
import os
import json

def getns(nstype):
    # read namespace id from symlink file:
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
            raise unittest.SkipTest("clone namespaces not supported")
        
        if not cls._availablens.get("user"):
            raise unittest.SkipTest("userns is required to run unprivileged tests")

    def test_no_isolation(self):
        self.load('ns_inspect', isolation={})

        obj = parsejson(self.get()['body'])

        nsnames = list(self._availablens.keys())
        for i in range(len(nsnames)):
            self.assertEqual(obj["NS"][nsnames[i].upper()], 
                            self._availablens[nsnames[i]], "%s not equal" % nsnames[i])
      
    def test_user_isolation(self):
        isolation = {}

        self.load('ns_inspect', isolation=isolation)
        obj = parsejson(self.get()['body'])

        self.assertEqual(obj["UID"], os.getuid(), "uid mismatch")
        self.assertEqual(obj["GID"], os.getuid(), "gid mismatch")

        isolation = {
            "namespaces": {
                "user": True
            }
        }

        self.load('ns_inspect', isolation=isolation)
        obj = parsejson(self.get()['body'])

        self.assertEqual(obj["UID"], 0, "uid is not from root")
        self.assertEqual(obj["GID"], 0, "gid is not from root")

    def test_mnt_isolation(self):
        if not self._availablens.get("mnt"):
            raise unittest.SkipTest("mnt namespace not supported")

        isolation = {
            "namespaces": {
                "mount": True,
                "user": True,
            }
        }

        self.load('ns_inspect', isolation=isolation)

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
    
    def test_pid_isolation(self):
        if not self._availablens.get("pid"):
            raise unittest.SkipTest("pid namespace not supported")
            
        isolation = {
            "namespaces": {
                "pid": True,
                "user": True,
            }
        }

        self.load('ns_inspect', isolation=isolation)

        body = self.get()['body']
        obj = parsejson(body)

        self.assertEqual(obj["PID"], 1, "pid of container is not 1")

if __name__ == '__main__':
    TestIsolation.main()
        