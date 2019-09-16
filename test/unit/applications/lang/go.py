import os
from subprocess import Popen
from unit.applications.proto import TestApplicationProto


class TestApplicationGo(TestApplicationProto):
    def prepare_env(self, script, name):
        if not os.path.exists(self.testdir + '/go'):
            os.mkdir(self.testdir + '/go')

        env = os.environ.copy()
        env['GOPATH'] = self.pardir + '/go'
        process = Popen(
            [
                'go',
                'build',
                '-o',
                self.testdir + '/go/' + name,
                self.current_dir + '/go/' + script + '/' + name + '.go',
            ],
            env=env,
        )

        process.communicate()

        return process

    def load(self, script, name='app'):
        self.prepare_env(script, name)

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": self.current_dir
                        + "/go/"
                        + script,
                        "executable": self.testdir + "/go/" + name,
                    }
                },
            }
        )
