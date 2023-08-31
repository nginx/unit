import os

from unit.control import Control
from unit.option import option


class ApplicationProto(Control):
    application_type = None

    def get_application_type(self):
        current_test = (
            os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
        )

        return option.generated_tests.get(current_test, self.application_type)

    def _load_conf(self, conf, **kwargs):
        if 'applications' in conf:
            for app in conf['applications'].keys():
                app_conf = conf['applications'][app]

                for key in [
                    'user',
                    'group',
                    'isolation',
                    'processes',
                    'threads',
                ]:
                    if key in kwargs:
                        app_conf[key] = kwargs[key]

        assert 'success' in self.conf(conf), 'load application configuration'
