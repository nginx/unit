import time

import pytest
from unit.applications.lang.python import TestApplicationPython
from unit.option import option
from unit.status import Status


class TestStatus(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_status(self):
        assert 'error' in self.conf_delete('/status'), 'DELETE method'

    def test_status_requests(self, skip_alert):
        skip_alert(r'Python failed to import module "blah"')

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes"},
                    "*:7081": {"pass": "applications/empty"},
                    "*:7082": {"pass": "applications/blah"},
                },
                "routes": [{"action": {"return": 200}}],
                "applications": {
                    "empty": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "path": option.test_dir + '/python/empty',
                        "working_directory": option.test_dir + '/python/empty',
                        "module": "wsgi",
                    },
                    "blah": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "module": "blah",
                    },
                },
            },
        )

        Status.init()

        assert self.get()['status'] == 200
        assert Status.get('/requests/total') == 1, '2xx'

        assert self.get(port=7081)['status'] == 200
        assert Status.get('/requests/total') == 2, '2xx app'

        assert (
            self.get(headers={'Host': '/', 'Connection': 'close'})['status']
            == 400
        )
        assert Status.get('/requests/total') == 3, '4xx'

        assert self.get(port=7082)['status'] == 503
        assert Status.get('/requests/total') == 4, '5xx'

        self.http(
            b"""GET / HTTP/1.1
Host: localhost

GET / HTTP/1.1
Host: localhost
Connection: close

""",
            raw=True,
        )
        assert Status.get('/requests/total') == 6, 'pipeline'

        (_, sock) = self.get(port=7081, no_recv=True, start=True)

        time.sleep(1)

        assert Status.get('/requests/total') == 7, 'no receive'

        sock.close()

    def test_status_connections(self):
        def check_connections(accepted, active, idle, closed):
            Status.get('/connections') == {
                'accepted': accepted,
                'active': active,
                'idle': idle,
                'closed': closed,
            }

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes"},
                    "*:7081": {"pass": "applications/delayed"},
                },
                "routes": [{"action": {"return": 200}}],
                "applications": {
                    "delayed": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/delayed",
                        "working_directory": option.test_dir
                        + "/python/delayed",
                        "module": "wsgi",
                    },
                },
            },
        )

        Status.init()

        # accepted, closed

        assert self.get()['status'] == 200
        check_connections(1, 0, 0, 1)

        # idle

        _, sock = self.http(b'', start=True, raw=True, no_recv=True)
        check_connections(2, 0, 1, 1)

        self.get(sock=sock)
        check_connections(2, 0, 0, 2)

        # active

        (_, sock) = self.get(
            headers={
                'Host': 'localhost',
                'X-Delay': '2',
                'Connection': 'close',
            },
            port=7081,
            start=True,
            read_timeout=1,
        )
        check_connections(3, 1, 0, 2)

        self.get(sock=sock)
        check_connections(3, 0, 0, 3)

    def test_status_applications(self):
        def check_applications(expert):
            apps = list(self.conf_get('/status/applications').keys()).sort()
            assert apps == expert.sort()

        def check_application(name, running, starting, idle, active):
            Status.get('/applications/' + name) == {
                'processes': {
                    'running': running,
                    'starting': starting,
                    'idle': idle,
                },
                'requests': {'active': active},
            }

        self.load('delayed')
        Status.init()

        check_applications(['delayed'])
        check_application('delayed', 0, 0, 0, 0)

        # idle

        assert self.get()['status'] == 200
        check_application('delayed', 1, 0, 1, 0)

        assert 'success' in self.conf('4', 'applications/delayed/processes')
        check_application('delayed', 4, 0, 4, 0)

        # active

        (_, sock) = self.get(
            headers={
                'Host': 'localhost',
                'X-Delay': '2',
                'Connection': 'close',
            },
            start=True,
            read_timeout=1,
        )
        check_application('delayed', 4, 0, 3, 1)
        sock.close()

        # starting

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "applications/restart"},
                    "*:7081": {"pass": "applications/delayed"},
                },
                "routes": [],
                "applications": {
                    "restart": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/restart",
                        "working_directory": option.test_dir
                        + "/python/restart",
                        "module": "longstart",
                    },
                    "delayed": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/delayed",
                        "working_directory": option.test_dir
                        + "/python/delayed",
                        "module": "wsgi",
                    },
                },
            },
        )
        Status.init()

        check_applications(['delayed', 'restart'])
        check_application('restart', 0, 0, 0, 0)
        check_application('delayed', 0, 0, 0, 0)

        self.get(read_timeout=1)

        check_application('restart', 0, 1, 0, 1)
        check_application('delayed', 0, 0, 0, 0)
