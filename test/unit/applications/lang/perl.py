from conftest import option
from unit.applications.proto import TestApplicationProto


class TestApplicationPerl(TestApplicationProto):
    application_type = "perl"

    def load(self, script, name='psgi.pl', **kwargs):
        script_path = option.test_dir + '/perl/' + script
        appication_type = self.get_appication_type()

        if appication_type is None:
            appication_type = self.application_type

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": appication_type,
                        "processes": {"spare": 0},
                        "working_directory": script_path,
                        "script": script_path + '/' + name,
                    }
                },
            },
            **kwargs
        )
