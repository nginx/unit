from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestApplicationPerl(TestApplicationProto):
    application_type = "perl"

    def load(self, script, name='psgi.pl', **kwargs):
        script_path = option.test_dir + '/perl/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "script": script_path + '/' + name,
                    }
                },
            },
            **kwargs
        )
