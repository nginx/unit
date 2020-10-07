import os
import shutil
from urllib.parse import quote

import pytest
from conftest import option
from unit.applications.proto import TestApplicationProto


class TestApplicationPython(TestApplicationProto):
    application_type = "python"
    load_module = "wsgi"

    def load(self, script, name=None, module=None, **kwargs):
        print()
        if name is None:
            name = script

        if module is None:
            module = self.load_module

        if script[0] == '/':
            script_path = script
        else:
            script_path = option.test_dir + '/python/' + script

        if kwargs.get('isolation') and kwargs['isolation'].get('rootfs'):
            rootfs = kwargs['isolation']['rootfs']

            if not os.path.exists(rootfs + '/app/python/'):
                os.makedirs(rootfs + '/app/python/')

            if not os.path.exists(rootfs + '/app/python/' + name):
                shutil.copytree(script_path, rootfs + '/app/python/' + name)

            script_path = '/app/python/' + name

        appication_type = self.get_appication_type()

        if appication_type is None:
            appication_type = self.application_type

        self._load_conf(
            {
                "listeners": {
                    "*:7080": {"pass": "applications/" + quote(name, '')}
                },
                "applications": {
                    name: {
                        "type": appication_type,
                        "processes": {"spare": 0},
                        "path": script_path,
                        "working_directory": script_path,
                        "module": module,
                    }
                },
            },
            **kwargs
        )
