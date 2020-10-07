from unit.applications.proto import TestApplicationProto
from conftest import option


class TestApplicationRuby(TestApplicationProto):
    application_type = "ruby"

    def load(self, script, name='config.ru', **kwargs):
        script_path = option.test_dir + '/ruby/' + script
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
