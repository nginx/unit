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
                        "type": "python",
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
