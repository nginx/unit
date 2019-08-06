from unit.applications.proto import TestApplicationProto


class TestApplicationRuby(TestApplicationProto):
    application_type = "ruby"

    def load(self, script, name='config.ru'):
        script_path = self.current_dir + '/ruby/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": self.application_type,
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "script": script_path + '/' + name,
                    }
                },
            }
        )
