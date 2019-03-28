from unit.applications.proto import TestApplicationProto


class TestApplicationPerl(TestApplicationProto):
    def load(self, script, name='psgi.pl'):
        script_path = self.current_dir + '/perl/' + script

        self.conf(
            {
                "listeners": {"*:7080": {"application": script}},
                "applications": {
                    script: {
                        "type": "perl",
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "script": script_path + '/' + name,
                    }
                },
            }
        )
