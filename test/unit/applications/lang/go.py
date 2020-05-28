import os
import subprocess

from unit.applications.proto import TestApplicationProto


class TestApplicationGo(TestApplicationProto):
    @classmethod
    def setUpClass(cls, complete_check=True):
        unit = super().setUpClass(complete_check=False)

        # check go module

        go_app = TestApplicationGo()
        go_app.testdir = unit.testdir
        proc = go_app.prepare_env('empty', 'app')
        if proc and proc.returncode == 0:
            cls.available['modules']['go'] = []

        return unit if not complete_check else unit.complete()

    def prepare_env(self, script, name, static=False):
        if not os.path.exists(self.testdir + '/go'):
            os.mkdir(self.testdir + '/go')

        env = os.environ.copy()
        env['GOPATH'] = self.pardir + '/build/go'

        if static:
            args = [
                'go',
                'build',
                '-tags',
                'netgo',
                '-ldflags',
                '-extldflags "-static"',
                '-o',
                self.testdir + '/go/' + name,
                self.current_dir + '/go/' + script + '/' + name + '.go',
            ]
        else:
            args = [
                'go',
                'build',
                '-o',
                self.testdir + '/go/' + name,
                self.current_dir + '/go/' + script + '/' + name + '.go',
            ]

        try:
            process = subprocess.Popen(args, env=env)
            process.communicate()

        except:
            return None

        return process

    def load(self, script, name='app', **kwargs):
        static_build = False

        wdir = self.current_dir + "/go/" + script
        executable = self.testdir + "/go/" + name

        if 'isolation' in kwargs and 'rootfs' in kwargs['isolation']:
            wdir = "/go/"
            executable = "/go/" + name
            static_build = True

        self.prepare_env(script, name, static=static_build)

        conf = {
            "listeners": {"*:7080": {"pass": "applications/" + script}},
            "applications": {
                script: {
                    "type": "external",
                    "processes": {"spare": 0},
                    "working_directory": wdir,
                    "executable": executable,
                },
            },
        }

        self._load_conf(conf, **kwargs)
