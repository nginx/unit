from pathlib import Path
import shutil
from urllib.parse import quote

from unit.applications.proto import ApplicationProto
from unit.option import option


class ApplicationPython(ApplicationProto):
    def __init__(self, application_type='python', load_module='wsgi'):
        self.application_type = application_type
        self.load_module = load_module

    def load(self, script, name=None, module=None, **kwargs):
        if name is None:
            name = script

        if module is None:
            module = self.load_module

        if script[0] == '/':
            script_path = script
        else:
            script_path = f'{option.test_dir}/python/{script}'

        if kwargs.get('isolation') and kwargs['isolation'].get('rootfs'):
            rootfs = kwargs['isolation']['rootfs']

            Path(f'{rootfs}/app/python/').mkdir(parents=True, exist_ok=True)

            if not Path(f'{rootfs}/app/python/{name}').exists():
                shutil.copytree(script_path, f'{rootfs}/app/python/{name}')

            script_path = f'/app/python/{name}'

        app = {
            "type": self.get_application_type(),
            "processes": kwargs.pop('processes', {"spare": 0}),
            "path": script_path,
            "working_directory": script_path,
            "module": module,
        }

        for attr in (
            'callable',
            'environment',
            'home',
            'limits',
            'path',
            'protocol',
            'targets',
            'threads',
            'prefix',
        ):
            if attr in kwargs:
                app[attr] = kwargs.pop(attr)

        self._load_conf(
            {
                "listeners": {
                    "*:8080": {"pass": f"applications/{quote(name, '')}"}
                },
                "applications": {name: app},
            },
            **kwargs,
        )
