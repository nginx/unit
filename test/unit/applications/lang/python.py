import os
import shutil

from unit.applications.proto import TestApplicationProto


class TestApplicationPython(TestApplicationProto):
    application_type = "python"

    def load(self, script, name=None, **kwargs):
        if name is None:
            name = script

        if script[0] == '/':
            script_path = script
        else:
            script_path = self.current_dir + '/python/' + script

        if kwargs.get('isolation') and kwargs['isolation'].get('rootfs'):
            rootfs = kwargs['isolation']['rootfs']

            if not os.path.exists(rootfs + '/app/python/'):
                os.makedirs(rootfs + '/app/python/')

            if not os.path.exists(rootfs + '/app/python/' + name):
                shutil.copytree(script_path, rootfs + '/app/python/' + name)

            script_path = '/app/python/' + name

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + name}},
                "applications": {
                    name: {
                        "type": self.application_type,
                        "processes": {"spare": 0},
                        "path": script_path,
                        "working_directory": script_path,
                        "module": "wsgi",
                    }
                },
            },
            **kwargs
        )
