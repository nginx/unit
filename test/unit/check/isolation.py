import json
from pathlib import Path

from unit.applications.lang.go import ApplicationGo
from unit.applications.lang.java import ApplicationJava
from unit.applications.lang.node import ApplicationNode
from unit.applications.lang.ruby import ApplicationRuby
from unit.http import HTTP1
from unit.option import option
from unit.utils import getns

allns = ['pid', 'mnt', 'ipc', 'uts', 'cgroup', 'net']
http = HTTP1()


def check_isolation():
    available = option.available

    conf = ''
    if 'go' in available['modules']:
        ApplicationGo().prepare_env('empty', 'app')

        conf = {
            "listeners": {"*:8080": {"pass": "applications/empty"}},
            "applications": {
                "empty": {
                    "type": "external",
                    "processes": {"spare": 0},
                    "working_directory": f"{option.test_dir}/go/empty",
                    "executable": f"{option.test_dir}/go/app",
                    "isolation": {"namespaces": {"credential": True}},
                },
            },
        }

    elif 'python' in available['modules']:
        conf = {
            "listeners": {"*:8080": {"pass": "applications/empty"}},
            "applications": {
                "empty": {
                    "type": "python",
                    "processes": {"spare": 0},
                    "path": f"{option.test_dir}/python/empty",
                    "working_directory": f"{option.test_dir}/python/empty",
                    "module": "wsgi",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    elif 'php' in available['modules']:
        conf = {
            "listeners": {"*:8080": {"pass": "applications/phpinfo"}},
            "applications": {
                "phpinfo": {
                    "type": "php",
                    "processes": {"spare": 0},
                    "root": f"{option.test_dir}/php/phpinfo",
                    "working_directory": f"{option.test_dir}/php/phpinfo",
                    "index": "index.php",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    elif 'ruby' in available['modules']:
        ApplicationRuby().prepare_env('empty')

        conf = {
            "listeners": {"*:8080": {"pass": "applications/empty"}},
            "applications": {
                "empty": {
                    "type": "ruby",
                    "processes": {"spare": 0},
                    "working_directory": f"{option.temp_dir}/ruby/empty",
                    "script": f"{option.temp_dir}/ruby/empty/config.ru",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    elif 'java' in available['modules']:
        ApplicationJava().prepare_env('empty')

        conf = {
            "listeners": {"*:8080": {"pass": "applications/empty"}},
            "applications": {
                "empty": {
                    "unit_jars": f"{option.current_dir}/build",
                    "type": "java",
                    "processes": {"spare": 0},
                    "working_directory": f"{option.temp_dir}/java/empty/",
                    "webapp": f"{option.temp_dir}/java",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    elif 'node' in available['modules']:
        ApplicationNode().prepare_env('basic')

        conf = {
            "listeners": {"*:8080": {"pass": "applications/basic"}},
            "applications": {
                "basic": {
                    "type": "external",
                    "processes": {"spare": 0},
                    "working_directory": f"{option.temp_dir}/node",
                    "executable": "app.js",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    elif 'perl' in available['modules']:
        conf = {
            "listeners": {"*:8080": {"pass": "applications/body_empty"}},
            "applications": {
                "body_empty": {
                    "type": "perl",
                    "processes": {"spare": 0},
                    "working_directory": f"{option.test_dir}/perl/body_empty",
                    "script": f"{option.test_dir}/perl/body_empty/psgi.pl",
                    "isolation": {"namespaces": {"credential": True}},
                }
            },
        }

    else:
        return False

    resp = http.put(
        url='/config',
        sock_type='unix',
        addr=f'{option.temp_dir}/control.unit.sock',
        body=json.dumps(conf),
    )

    if 'success' not in resp['body']:
        return False

    userns = getns('user')
    if not userns:
        return False

    isolation = {'user': userns}

    path_clone = Path('/proc/sys/kernel/unprivileged_userns_clone')
    if (
        path_clone.exists()
        and path_clone.read_text(encoding='utf-8').rstrip() == '1'
    ):
        isolation['unprivileged_userns_clone'] = True

    for ns in allns:
        ns_value = getns(ns)
        if ns_value:
            isolation[ns] = ns_value

    return isolation
