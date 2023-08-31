import os
import shutil

from unit.applications.proto import ApplicationProto
from unit.option import option


class ApplicationPHP(ApplicationProto):
    def __init__(self, application_type='php'):
        self.application_type = application_type

    def load(self, script, index='index.php', **kwargs):
        script_path = f'{option.test_dir}/php/{script}'

        if kwargs.get('isolation') and kwargs['isolation'].get('rootfs'):
            rootfs = kwargs['isolation']['rootfs']

            if not os.path.exists(f'{rootfs}/app/php/'):
                os.makedirs(f'{rootfs}/app/php/')

            if not os.path.exists(f'{rootfs}/app/php/{script}'):
                shutil.copytree(script_path, f'{rootfs}/app/php/{script}')

            script_path = f'/app/php/{script}'

        app = {
            "type": self.get_application_type(),
            "processes": kwargs.pop('processes', {"spare": 0}),
            "root": script_path,
            "working_directory": script_path,
            "index": index,
        }

        for attr in (
            'environment',
            'limits',
            'options',
            'targets',
        ):
            if attr in kwargs:
                app[attr] = kwargs.pop(attr)

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": f"applications/{script}"}},
                "applications": {script: app},
            },
            **kwargs,
        )
