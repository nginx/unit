import os
import shutil
import subprocess

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestApplicationGo(TestApplicationProto):
    @staticmethod
    def prepare_env(script, name='app', static=False):
        try:
            subprocess.check_output(['which', 'go'])
        except subprocess.CalledProcessError:
            return None

        temp_dir = option.temp_dir + '/go/'

        if not os.path.exists(temp_dir):
            os.mkdir(temp_dir)

        cache_dir = option.cache_dir + '/go-build'

        if not os.path.exists(cache_dir):
            os.mkdir(cache_dir)

        env = os.environ.copy()
        env['GOPATH'] = option.current_dir + '/build/go'
        env['GOCACHE'] = cache_dir

        shutil.copy2(
            option.test_dir + '/go/' + script + '/' + name + '.go', temp_dir
        )

        if static:
            args = [
                'go',
                'build',
                '-tags',
                'netgo',
                '-ldflags',
                '-extldflags "-static"',
                '-o',
                temp_dir + name,
                temp_dir + name + '.go',
            ]
        else:
            args = [
                'go',
                'build',
                '-o',
                temp_dir + name,
                temp_dir + name + '.go',
            ]

        replace_path = option.current_dir + '/build/go/src/unit.nginx.org/go'

        with open(temp_dir + 'go.mod', 'w') as f:
            f.write(
                f"""module test/app
require unit.nginx.org/go v0.0.0
replace unit.nginx.org/go => {replace_path}
"""
            )

        if option.detailed:
            print("\n$ GOPATH=" + env['GOPATH'] + " " + " ".join(args))

        try:
            output = subprocess.check_output(
                args, env=env, cwd=temp_dir, stderr=subprocess.STDOUT
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            return None

        return output

    def load(self, script, name='app', **kwargs):
        static_build = False

        wdir = option.test_dir + "/go/" + script
        executable = option.temp_dir + "/go/" + name

        if 'isolation' in kwargs and 'rootfs' in kwargs['isolation']:
            wdir = "/go/"
            executable = "/go/" + name
            static_build = True

        TestApplicationGo.prepare_env(script, name, static=static_build)

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
