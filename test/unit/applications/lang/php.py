import os
import shutil

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestApplicationPHP(TestApplicationProto):
    application_type = "php"

    def load(self, script, index='index.php', **kwargs):
        script_path = option.test_dir + '/php/' + script

        if kwargs.get('isolation') and kwargs['isolation'].get('rootfs'):
            rootfs = kwargs['isolation']['rootfs']

            if not os.path.exists(rootfs + '/app/php/'):
                os.makedirs(rootfs + '/app/php/')

            if not os.path.exists(rootfs + '/app/php/' + script):
                shutil.copytree(script_path, rootfs + '/app/php/' + script)

            script_path = '/app/php/' + script

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "applications/" + script}},
                "applications": {
                    script: {
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "root": script_path,
                        "working_directory": script_path,
                        "index": index,
                    }
                },
            },
            **kwargs
        )
