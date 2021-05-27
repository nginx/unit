import json
import os

from unit.applications.lang.go import TestApplicationGo
from unit.applications.lang.java import TestApplicationJava
from unit.applications.lang.node import TestApplicationNode
from unit.applications.proto import TestApplicationProto
from unit.http import TestHTTP
from unit.option import option
from unit.utils import getns

allns = ['pid', 'mnt', 'ipc', 'uts', 'cgroup', 'net']
http = TestHTTP()


def check_isolation():
    test_conf = {"namespaces": {"credential": True}}
    available = option.available

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
                    "working_directory": option.test_dir + "/perl/body_empty",
                    "script": option.test_dir + "/perl/body_empty/psgi.pl",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    else:
        return

    resp = http.put(
        url='/config',
        sock_type='unix',
        addr=option.temp_dir + '/control.unit.sock',
        body=json.dumps(conf),
    )

    if 'success' not in resp['body']:
        return

    userns = getns('user')
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

    for ns in allns:
        ns_value = getns(ns)
        if ns_value:
            available['features']['isolation'][ns] = ns_value
