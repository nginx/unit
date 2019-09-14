import os
import shutil
from unit.applications.proto import TestApplicationProto


class TestApplicationNode(TestApplicationProto):
    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        # check node module

        if os.path.exists(unit.pardir + '/node/node_modules'):
            cls.available['modules']['node'] = []

        return unit if not complete_check else unit.complete()

    def load(self, script, name='app.js'):
        # copy application

        shutil.copytree(
            self.current_dir + '/node/' + script, self.testdir + '/node'
        )

        # link modules

        os.symlink(
            self.pardir + '/node/node_modules',
            self.testdir + '/node/node_modules',
        )

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": self.testdir + '/node',
                        "executable": name,
                    }
                },
            }
        )
