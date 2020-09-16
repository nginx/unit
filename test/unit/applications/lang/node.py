import os
import shutil
from urllib.parse import quote

from unit.applications.proto import TestApplicationProto
from conftest import option, public_dir


class TestApplicationNode(TestApplicationProto):
    @classmethod
    def setup_class(cls, complete_check=True):
        unit = super().setup_class(complete_check=False)

        # check node module

        if os.path.exists(unit.pardir + '/node/node_modules'):
            cls.available['modules']['node'] = []

        return unit if not complete_check else unit.complete()

    def load(self, script, name='app.js', **kwargs):
        # copy application

        shutil.copytree(
            option.test_dir + '/node/' + script, self.temp_dir + '/node'
        )

        # copy modules

        shutil.copytree(
            self.pardir + '/node/node_modules',
            self.temp_dir + '/node/node_modules',
        )

        public_dir(self.temp_dir + '/node')

        self._load_conf(
            {
                "listeners": {
                    "*:7080": {"pass": "applications/" + quote(script, '')}
                },
                "applications": {
                    script: {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": self.temp_dir + '/node',
                        "executable": name,
                    }
                },
            },
            **kwargs
        )
