import shutil

import pytest

from conftest import option
from conftest import unit_run
from conftest import unit_stop
from unit.applications.lang.ruby import TestApplicationRuby
from unit.feature.isolation import TestFeatureIsolation


class TestRubyIsolation(TestApplicationRuby):
    prerequisites = {'modules': {'ruby': 'any'}, 'features': ['isolation']}

    @classmethod
    def setup_class(cls, complete_check=True):
        check = super().setup_class(complete_check=False)

        unit = unit_run()
        option.temp_dir = unit['temp_dir']

        TestFeatureIsolation().check(option.available, unit['temp_dir'])

        assert unit_stop() is None
        shutil.rmtree(unit['temp_dir'])

        return check if not complete_check else check()

    def test_ruby_isolation_rootfs(self, is_su):
        isolation_features = option.available['features']['isolation'].keys()

        if 'mnt' not in isolation_features:
            pytest.skip('requires mnt ns')

        if not is_su:
            if 'user' not in isolation_features:
                pytest.skip('requires unprivileged userns or root')

            if not 'unprivileged_userns_clone' in isolation_features:
                pytest.skip('requires unprivileged userns or root')

        isolation = {
            'namespaces': {'credential': not is_su, 'mount': True},
            'rootfs': option.test_dir,
        }

        self.load('status_int', isolation=isolation)

        assert 'success' in self.conf(
            '"/ruby/status_int/config.ru"', 'applications/status_int/script',
        )

        assert 'success' in self.conf(
            '"/ruby/status_int"', 'applications/status_int/working_directory',
        )

        assert self.get()['status'] == 200, 'status int'
