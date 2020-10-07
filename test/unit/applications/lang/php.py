from conftest import option
from unit.applications.proto import TestApplicationProto


class TestApplicationPHP(TestApplicationProto):
    application_type = "php"

    def load(self, script, index='index.php', **kwargs):
        script_path = option.test_dir + '/php/' + script
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
                        "root": script_path,
                        "working_directory": script_path,
                        "index": index,
                    }
                },
            },
            **kwargs
        )
