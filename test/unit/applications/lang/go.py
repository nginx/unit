import os
import subprocess

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestApplicationGo(TestApplicationProto):
    def prepare_env(self, script, name, static=False):
        if not os.path.exists(option.temp_dir + '/go'):
            os.mkdir(option.temp_dir + '/go')

        env = os.environ.copy()
        env['GOPATH'] = option.current_dir + '/build/go'
        env['GOCACHE'] = option.cache_dir + '/go'

        if static:
            args = [
                'go',
                'build',
                '-tags',
                'netgo',
                '-ldflags',
                '-extldflags "-static"',
                '-o',
                option.temp_dir + '/go/' + name,
                option.test_dir + '/go/' + script + '/' + name + '.go',
            ]
        else:
            args = [
                'go',
                'build',
                '-o',
                option.temp_dir + '/go/' + name,
                option.test_dir + '/go/' + script + '/' + name + '.go',
            ]

        if option.detailed:
            print("\n$ GOPATH=" + env['GOPATH'] + " " + " ".join(args))

        try:
            process = subprocess.Popen(args, env=env)
            process.communicate()

        except KeyboardInterrupt:
            raise

        except:
            return None

        return process

    def load(self, script, name='app', **kwargs):
        static_build = False

        wdir = option.test_dir + "/go/" + script
        executable = option.temp_dir + "/go/" + name

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
