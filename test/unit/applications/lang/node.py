import shutil
from urllib.parse import quote

from unit.applications.proto import ApplicationProto
from unit.option import option
from unit.utils import public_dir


class ApplicationNode(ApplicationProto):
    def __init__(self, application_type='node', es_modules=False):
        self.application_type = application_type
        self.es_modules = es_modules

    def prepare_env(self, script):
        # copy application
        shutil.copytree(
            f'{option.test_dir}/node/{script}', f'{option.temp_dir}/node'
        )

        # copy modules
        shutil.copytree(
            f'{option.current_dir}/node/node_modules',
            f'{option.temp_dir}/node/node_modules',
        )

        public_dir(f'{option.temp_dir}/node')

    def load(self, script, name='app.js', **kwargs):
        self.prepare_env(script)

        if self.es_modules:
            arguments = [
                "node",
                "--loader",
                "unit-http/loader.mjs",
                "--require",
                "unit-http/loader",
                name,
            ]

        else:
            arguments = ["node", "--require", "unit-http/loader", name]

        self._load_conf(
            {
                "listeners": {
                    "*:8080": {"pass": f"applications/{quote(script, '')}"}
                },
                "applications": {
                    script: {
                        "type": "external",
                        "processes": {"spare": 0},
                        "working_directory": f'{option.temp_dir}/node',
                        "executable": '/usr/bin/env',
                        "arguments": arguments,
                    }
                },
            },
            **kwargs,
        )
