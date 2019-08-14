from unit.applications.lang.go import TestApplicationGo
import os
import json

def getns(nstype):
    data = os.readlink("/proc/self/ns/%s" % nstype)
    data = data[len(nstype)+2:]
    data = data[:len(data)-1]
    return int(data)

def parsejson(data):
    parts = data.split("\n")
    return json.loads(parts[1])

class TestIsolation(TestApplicationGo):
    prerequisites = ['go']

    def test_detect_isolation_allowed(self):
        isolation = {
            "namespaces": {
                "user": True,
                "pid": True
            }
        }

        conf_status = self.load('ns_inspect', 
                                isolation=isolation, 
                                assert_conf=False)
        if "error" in conf_status:
            self.skipTest("isolation not supported")

        body = self.get()['body']
        self.assertIn('"PID":1,', body, "pid 1 not found")
    
    def test_no_isolation(self):
        self.load('ns_inspect', isolation={}, assert_conf=True)

        body = self.get()['body']
        obj = parsejson(body)

        ns = ["user", "pid", "mnt", "ipc", "uts", "cgroup", "net"]

        for i in range(len(ns)):
            self.assertEqual(obj["NS"][ns[i].upper()], 
                            getns(ns[i]), "%s not equal" % ns[i])
    
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
        ns = ["pid", "ipc", "uts", "cgroup", "net"]

        for i in range(len(ns)):
            self.assertEqual(obj["NS"][ns[i].upper()], 
                            getns(ns[i]), "%s not equal" % ns[i])

        self.assertNotEqual(obj["NS"]["MNT"], getns("mnt"), "mnt ns not set")
        self.assertNotEqual(obj["NS"]["USER"], getns("user"), "user ns not set")

if __name__ == '__main__':
    TestIsolation.main()
        