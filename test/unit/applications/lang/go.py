import os
import subprocess

from unit.applications.proto import TestApplicationProto
from conftest import option


class TestApplicationGo(TestApplicationProto):
    def prepare_env(self, script, name, static=False):
        if not os.path.exists(self.temp_dir + '/go'):
            os.mkdir(self.temp_dir + '/go')

        env = os.environ.copy()
        env['GOPATH'] = option.current_dir + '/build/go'

        if static:
            args = [
                'go',
                'build',
                '-tags',
                'netgo',
                '-ldflags',
                '-extldflags "-static"',
                '-o',
                self.temp_dir + '/go/' + name,
                option.test_dir + '/go/' + script + '/' + name + '.go',
            ]
        else:
            args = [
                'go',
                'build',
                '-o',
                self.temp_dir + '/go/' + name,
                option.test_dir + '/go/' + script + '/' + name + '.go',
            ]

        try:
            process = subprocess.Popen(args, env=env)
            process.communicate()

        except:
            return None

        return process

    def load(self, script, name='app', **kwargs):
        static_build = False

        wdir = option.test_dir + "/go/" + script
        executable = self.temp_dir + "/go/" + name

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
