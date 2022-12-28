from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestPythonTargets(TestApplicationPython):
    prerequisites = {'modules': {'python': 'all'}}

    def test_python_targets(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {
                        "match": {"uri": "/1"},
                        "action": {"pass": "applications/targets/1"},
                    },
                    {
                        "match": {"uri": "/2"},
                        "action": {"pass": "applications/targets/2"},
                    },
                ],
                "applications": {
                    "targets": {
                        "type": self.get_application_type(),
                        "working_directory": option.test_dir
                        + "/python/targets/",
                        "path": option.test_dir + '/python/targets/',
                        "targets": {
                            "1": {
                                "module": "wsgi",
                                "callable": "wsgi_target_a",
                            },
                            "2": {
                                "module": "wsgi",
                                "callable": "wsgi_target_b",
                            },
                        },
                    }
                },
            }
        )

        resp = self.get(url='/1')
        assert resp['status'] == 200
        assert resp['body'] == '1'

        resp = self.get(url='/2')
        assert resp['status'] == 200
        assert resp['body'] == '2'

    def test_python_targets_prefix(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {
                        "match": {"uri": ["/app*"]},
                        "action": {"pass": "applications/targets/app"},
                    },
                    {
                        "match": {"uri": "*"},
                        "action": {"pass": "applications/targets/catchall"},
                    },
                ],
                "applications": {
                    "targets": {
                        "type": "python",
                        "working_directory": option.test_dir
                        + "/python/targets/",
                        "path": option.test_dir + '/python/targets/',
                        "protocol": "wsgi",
                        "targets": {
                            "app": {
                                "module": "wsgi",
                                "callable": "wsgi_target_prefix",
                                "prefix": "/app/",
                            },
                            "catchall": {
                                "module": "wsgi",
                                "callable": "wsgi_target_prefix",
                                "prefix": "/api",
                            },
                        },
                    }
                },
            }
        )

        def check_prefix(url, body):
            resp = self.get(url=url)
            assert resp['status'] == 200
            assert resp['body'] == body

        check_prefix('/app', '/app ')
        check_prefix('/app/', '/app /')
        check_prefix('/app/rest/user/', '/app /rest/user/')
        check_prefix('/catchall', 'No Script Name /catchall')
        check_prefix('/api', '/api ')
        check_prefix('/api/', '/api /')
        check_prefix('/apis', 'No Script Name /apis')
        check_prefix('/api/users/', '/api /users/')
