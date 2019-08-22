from unit.applications.proto import TestApplicationProto


class TestApplicationPHP(TestApplicationProto):
    application_type = "php"

    def load(self, script, name='index.php'):
        script_path = self.current_dir + '/php/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": self.application_type,
                        "processes": {"spare": 0},
                        "root": script_path,
                        "working_directory": script_path,
                        "index": name,
                    }
                },
            }
        )
