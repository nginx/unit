import os

from unit.applications.lang.go import TestApplicationGo
from unit.applications.lang.java import TestApplicationJava
from unit.applications.lang.node import TestApplicationNode
from unit.applications.proto import TestApplicationProto
from conftest import option


class TestFeatureIsolation(TestApplicationProto):
    allns = ['pid', 'mnt', 'ipc', 'uts', 'cgroup', 'net']

    def check(self, available, temp_dir):
        test_conf = {"namespaces": {"credential": True}}

        conf = ''
        if 'go' in available['modules']:
            TestApplicationGo().prepare_env('empty', 'app')

            conf = {
                "listeners": {"*:7080": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": option.test_dir + "/go/empty",
                        "executable": option.temp_dir + "/go/app",
                        "isolation": {"namespaces": {"credential": True}},
                    },
                },
            }

        elif 'python' in available['modules']:
            conf = {
                "listeners": {"*:7080": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/empty",
                        "working_directory": option.test_dir + "/python/empty",
                        "module": "wsgi",
                        "isolation": {"namespaces": {"credential": True}},
                    }
                },
            }

        elif 'php' in available['modules']:
            conf = {
                "listeners": {"*:7080": {"pass": "applications/phpinfo"}},
                "applications": {
                    "phpinfo": {
                        "type": "php",
                        "processes": {"spare": 0},
                        "root": option.test_dir + "/php/phpinfo",
                        "working_directory": option.test_dir + "/php/phpinfo",
                        "index": "index.php",
                        "isolation": {"namespaces": {"credential": True}},
                    }
                },
            }

        elif 'ruby' in available['modules']:
            conf = {
                "listeners": {"*:7080": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "type": "ruby",
                        "processes": {"spare": 0},
                        "working_directory": option.test_dir + "/ruby/empty",
                        "script": option.test_dir + "/ruby/empty/config.ru",
                        "isolation": {"namespaces": {"credential": True}},
                    }
                },
            }

        elif 'java' in available['modules']:
            TestApplicationJava().prepare_env('empty')

            conf = {
                "listeners": {"*:7080": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "unit_jars": option.current_dir + "/build",
                        "type": "java",
                        "processes": {"spare": 0},
                        "working_directory": option.test_dir + "/java/empty/",
                        "webapp": option.temp_dir + "/java",
                        "isolation": {"namespaces": {"credential": True}},
                    }
                },
            }

        elif 'node' in available['modules']:
            TestApplicationNode().prepare_env('basic')

            conf = {
                "listeners": {"*:7080": {"pass": "applications/basic"}},
                "applications": {
                    "basic": {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": option.temp_dir + "/node",
                        "executable": "app.js",
                        "isolation": {"namespaces": {"credential": True}},
                    }
                },
            }

        elif 'perl' in available['modules']:
            conf = {
                "listeners": {"*:7080": {"pass": "applications/body_empty"}},
                "applications": {
                    "body_empty": {
                        "type": "perl",
                        "processes": {"spare": 0},
                        "working_directory": option.test_dir
                        + "/perl/body_empty",
                        "script": option.test_dir + "/perl/body_empty/psgi.pl",
                        "isolation": {"namespaces": {"credential": True}},
                    }
                },
            }

        else:
            return

        if 'success' not in self.conf(conf):
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
