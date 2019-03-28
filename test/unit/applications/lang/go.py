import os
from subprocess import Popen
from unit.applications.proto import TestApplicationProto


class TestApplicationGo(TestApplicationProto):
    def load(self, script, name='app'):

        if not os.path.isdir(self.testdir + '/go'):
            os.mkdir(self.testdir + '/go')

        go_app_path = self.current_dir + '/go/'

        env = os.environ.copy()
        env['GOPATH'] = self.pardir + '/go'
        process = Popen(
            [
                'go',
                'build',
                '-o',
                self.testdir + '/go/' + name,
                go_app_path + script + '/' + name + '.go',
            ],
            env=env,
        )
        process.communicate()

        self.conf(
            {
                "listeners": {"*:7080": {"application": script}},
                "applications": {
                    script: {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": go_app_path + script,
                        "executable": self.testdir + '/go/' + name,
                    }
                },
            }
        )
