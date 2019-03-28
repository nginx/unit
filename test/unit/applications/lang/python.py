from unit.applications.proto import TestApplicationProto


class TestApplicationPython(TestApplicationProto):
    def load(self, script, name=None):
        if name is None:
            name = script

        script_path = self.current_dir + '/python/' + script

        self.conf(
            {
                "listeners": {"*:7080": {"application": name}},
                "applications": {
                    name: {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                    }
                },
            }
        )
