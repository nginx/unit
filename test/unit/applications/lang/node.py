import shutil
from urllib.parse import quote

from unit.applications.proto import TestApplicationProto
from unit.option import option
from unit.utils import public_dir


class TestApplicationNode(TestApplicationProto):
    def prepare_env(self, script):
        # copy application

        shutil.copytree(
            option.test_dir + '/node/' + script, option.temp_dir + '/node'
        )

        # copy modules

        shutil.copytree(
            option.current_dir + '/node/node_modules',
            option.temp_dir + '/node/node_modules',
        )

        public_dir(option.temp_dir + '/node')

    def load(self, script, name='app.js', **kwargs):
        self.prepare_env(script)

        self._load_conf(
            {
                "listeners": {
                    "*:7080": {"pass": "applications/" + quote(script, '')}
                },
                "applications": {
                    script: {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": option.temp_dir + '/node',
                        "executable": name,
                    }
                },
            },
            **kwargs
        )
