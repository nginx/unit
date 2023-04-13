from unit.applications.lang.php import TestApplicationPHP
from unit.option import option


class TestPHPTargets(TestApplicationPHP):
    prerequisites = {'modules': {'php': 'any'}}

    def test_php_application_targets(self):
        targets_dir = f"{option.test_dir}/php/targets"
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
                    {"action": {"pass": "applications/targets/default"}},
                ],
                "applications": {
                    "targets": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "targets": {
                            "1": {
                                "script": "1.php",
                                "root": targets_dir,
                            },
                            "2": {
                                "script": "2.php",
                                "root": f'{targets_dir}/2',
                            },
                            "default": {
                                "index": "index.php",
                                "root": targets_dir,
                            },
                        },
                    }
                },
            }
        )

        assert self.get(url='/1')['body'] == '1'
        assert self.get(url='/2')['body'] == '2'
        assert self.get(url='/blah')['status'] == 404
        assert self.get(url='/')['body'] == 'index'
        assert self.get(url='/1.php?test=test.php/')['body'] == '1'

        assert 'success' in self.conf(
            "\"1.php\"", 'applications/targets/targets/default/index'
        ), 'change targets index'
        assert self.get(url='/')['body'] == '1'

        assert 'success' in self.conf_delete(
            'applications/targets/targets/default/index'
        ), 'remove targets index'
        assert self.get(url='/')['body'] == 'index'

    def test_php_application_targets_error(self):
        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "applications/targets/default"}
                },
                "applications": {
                    "targets": {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "targets": {
                            "default": {
                                "index": "index.php",
                                "root": f"{option.test_dir}/php/targets",
                            },
                        },
                    }
                },
            }
        ), 'initial configuration'
        assert self.get()['status'] == 200

        assert 'error' in self.conf(
            {"pass": "applications/targets/blah"}, 'listeners/*:7080'
        ), 'invalid targets pass'
        assert 'error' in self.conf(
            f'"{option.test_dir}/php/targets"',
            'applications/targets/root',
        ), 'invalid root'
        assert 'error' in self.conf(
            '"index.php"', 'applications/targets/index'
        ), 'invalid index'
        assert 'error' in self.conf(
            '"index.php"', 'applications/targets/script'
        ), 'invalid script'
        assert 'error' in self.conf_delete(
            'applications/targets/default/root'
        ), 'root remove'
