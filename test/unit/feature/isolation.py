import os
import json
from unit.applications.proto import TestApplicationProto
from unit.applications.lang.go import TestApplicationGo
from unit.applications.lang.java import TestApplicationJava
from unit.applications.lang.node import TestApplicationNode
from unit.applications.lang.perl import TestApplicationPerl
from unit.applications.lang.php import TestApplicationPHP
from unit.applications.lang.python import TestApplicationPython
from unit.applications.lang.ruby import TestApplicationRuby


class TestFeatureIsolation(TestApplicationProto):
    allns = ['pid', 'mnt', 'ipc', 'uts', 'cgroup', 'net']

    def check(self, available, testdir):
        test_conf = {"namespaces": {"credential": True}}

        module = ''
        app = 'empty'
        if 'go' in available['modules']:
            module = TestApplicationGo()

        elif 'java' in available['modules']:
            module = TestApplicationJava()

        elif 'node' in available['modules']:
            module = TestApplicationNode()
            app = 'basic'

        elif 'perl' in available['modules']:
            module = TestApplicationPerl()
            app = 'body_empty'

        elif 'php' in available['modules']:
            module = TestApplicationPHP()
            app = 'phpinfo'

        elif 'python' in available['modules']:
            module = TestApplicationPython()

        elif 'ruby' in available['modules']:
            module = TestApplicationRuby()

        if not module:
            return

        module.testdir = testdir
        module.load(app)

        resp = module.conf(test_conf, 'applications/' + app + '/isolation')
        if 'success' not in resp:
            return

        userns = self.getns('user')
        if not userns:
            return

        available['features']['isolation'] = {'user': userns}

        unp_clone_path = '/proc/sys/kernel/unprivileged_userns_clone'
        if os.path.exists(unp_clone_path):
            with open(unp_clone_path, 'r') as f:
                if str(f.read()).rstrip() == '1':
                    available['features']['isolation'][
                        'unprivileged_userns_clone'
                    ] = True

        for ns in self.allns:
            ns_value = self.getns(ns)
            if ns_value:
                available['features']['isolation'][ns] = ns_value

    def getns(self, nstype):
        # read namespace id from symlink file:
        # it points to: '<nstype>:[<ns id>]'
        # # eg.: 'pid:[4026531836]'
        nspath = '/proc/self/ns/' + nstype
        data = None

        if os.path.exists(nspath):
            data = int(os.readlink(nspath)[len(nstype) + 2 : -1])

        return data

    def parsejson(self, data):
        return json.loads(data.split('\n')[1])
