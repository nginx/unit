import shutil
from urllib.parse import quote

from unit.applications.proto import TestApplicationProto
from unit.option import option
from unit.utils import public_dir


class TestApplicationNode(TestApplicationProto):
    application_type = "node"
    es_modules = False

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
                    "*:7080": {"pass": f"applications/{quote(script, '')}"}
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
