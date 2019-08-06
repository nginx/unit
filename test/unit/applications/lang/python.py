from unit.applications.proto import TestApplicationProto


class TestApplicationPython(TestApplicationProto):
    application_type = "python"

    def load(self, script, name=None):
        if name is None:
            name = script

        script_path = self.current_dir + '/python/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + name}},
                "applications": {
                    name: {
                        "type": self.application_type,
                        "processes": {"spare": 0},
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                    }
                },
            }
        )
