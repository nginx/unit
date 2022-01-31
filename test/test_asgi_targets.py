import pytest
from packaging import version
from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestASGITargets(TestApplicationPython):
    prerequisites = {
        'modules': {
            'python': lambda v: version.parse(v) >= version.parse('3.5')
        }
    }
    load_module = 'asgi'

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self):
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
                        "processes": {"spare": 0},
                        "working_directory": option.test_dir
                        + "/python/targets/",
                        "path": option.test_dir + '/python/targets/',
                        "protocol": "asgi",
                        "targets": {
                            "1": {
                                "module": "asgi",
                                "callable": "application_200",
                            },
                            "2": {
                                "module": "asgi",
                                "callable": "application_201",
                            },
                        },
                    }
                },
            }
        )

    def conf_targets(self, targets):
        assert 'success' in self.conf(targets, 'applications/targets/targets')

    def test_asgi_targets(self):
        assert self.get(url='/1')['status'] == 200
        assert self.get(url='/2')['status'] == 201

    def test_asgi_targets_legacy(self):
        self.conf_targets(
            {
                "1": {"module": "asgi", "callable": "legacy_application_200"},
                "2": {"module": "asgi", "callable": "legacy_application_201"},
            }
        )

        assert self.get(url='/1')['status'] == 200
        assert self.get(url='/2')['status'] == 201

    def test_asgi_targets_mix(self):
        self.conf_targets(
            {
                "1": {"module": "asgi", "callable": "application_200"},
                "2": {"module": "asgi", "callable": "legacy_application_201"},
            }
        )

        assert self.get(url='/1')['status'] == 200
        assert self.get(url='/2')['status'] == 201

    def test_asgi_targets_broken(self, skip_alert):
        skip_alert(r'Python failed to get "blah" from module')

        self.conf_targets(
            {
                "1": {"module": "asgi", "callable": "application_200"},
                "2": {"module": "asgi", "callable": "blah"},
            }
        )

        assert self.get(url='/1')['status'] != 200
