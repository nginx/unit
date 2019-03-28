import os
import shutil
from unit.applications.proto import TestApplicationProto


class TestApplicationNode(TestApplicationProto):
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

        self.conf(
            {
                "listeners": {"*:7080": {"application": script}},
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
