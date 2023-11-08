import shutil

from unit.applications.proto import ApplicationProto
from unit.option import option
from unit.utils import public_dir


class ApplicationRuby(ApplicationProto):
    def __init__(self, application_type='ruby'):
        self.application_type = application_type

    def prepare_env(self, script):
        shutil.copytree(
            f'{option.test_dir}/ruby/{script}',
            f'{option.temp_dir}/ruby/{script}',
        )

        public_dir(f'{option.temp_dir}/ruby/{script}')

    def load(self, script, name='config.ru', **kwargs):
        self.prepare_env(script)

        script_path = f'{option.temp_dir}/ruby/{script}'

        app = {
            "type": self.get_application_type(),
            "processes": {"spare": 0},
            "working_directory": script_path,
            "script": f'{script_path}/{name}',
        }

        for key in [
            'hooks',
        ]:
            if key in kwargs:
                app[key] = kwargs[key]

        self._load_conf(
            {
                "listeners": {"*:8080": {"pass": f"applications/{script}"}},
                "applications": {script: app},
            },
            **kwargs,
        )
