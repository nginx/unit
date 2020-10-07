import os
import re
import time

from conftest import option
from unit.control import TestControl


class TestApplicationProto(TestControl):
    def sec_epoch(self):
        return time.mktime(time.gmtime())

    def date_to_sec_epoch(self, date, template='%a, %d %b %Y %H:%M:%S %Z'):
        return time.mktime(time.strptime(date, template))

    def search_in_log(self, pattern, name='unit.log'):
        with open(self.temp_dir + '/' + name, 'r', errors='ignore') as f:
            return re.search(pattern, f.read())

    def wait_for_record(self, pattern, name='unit.log'):
        for i in range(50):
            found = self.search_in_log(pattern, name)

            if found is not None:
                break

            time.sleep(0.1)

        return found

    def get_appication_type(self):
        current_test = (
            os.environ.get('PYTEST_CURRENT_TEST').split(':')[-1].split(' ')[0]
        )

        if current_test in option.generated_tests:
            return option.generated_tests[current_test]

        return None

    def _load_conf(self, conf, **kwargs):
        if 'applications' in conf:
            for app in conf['applications'].keys():
                app_conf = conf['applications'][app]
                if 'user' in kwargs:
                    app_conf['user'] = kwargs['user']

                if 'group' in kwargs:
                    app_conf['group'] = kwargs['group']

                if 'isolation' in kwargs:
                    app_conf['isolation'] = kwargs['isolation']

        assert 'success' in self.conf(conf), 'load application configuration'
