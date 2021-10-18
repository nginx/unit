import shutil

from unit.applications.proto import TestApplicationProto
from unit.option import option
from unit.utils import public_dir


class TestApplicationRuby(TestApplicationProto):
    application_type = "ruby"

    def prepare_env(self, script):
        shutil.copytree(
            option.test_dir + '/ruby/' + script,
            option.temp_dir + '/ruby/' + script,
        )

        public_dir(option.temp_dir + '/ruby/' + script)

    def load(self, script, name='config.ru', **kwargs):
        self.prepare_env(script)

        script_path = option.temp_dir + '/ruby/' + script

        app = {
            "type": self.get_application_type(),
            "processes": {"spare": 0},
            "working_directory": script_path,
            "script": script_path + '/' + name,
        }

        for key in [
            'hooks',
        ]:
            if key in kwargs:
                app[key] = kwargs[key]

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {script: app},
            },
            **kwargs
        )
