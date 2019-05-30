from unit.applications.proto import TestApplicationProto


class TestApplicationRuby(TestApplicationProto):
    def load(self, script, name='config.ru'):
        script_path = self.current_dir + '/ruby/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": "ruby",
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "script": script_path + '/' + name,
                    }
                },
            }
        )
