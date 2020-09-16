import os
import pytest
import shutil

from unit.applications.lang.ruby import TestApplicationRuby
from unit.feature.isolation import TestFeatureIsolation
from conftest import option


class TestRubyIsolation(TestApplicationRuby):
    prerequisites = {'modules': {'ruby': 'any'}, 'features': ['isolation']}

    isolation = TestFeatureIsolation()

    @classmethod
    def setup_class(cls, complete_check=True):
        unit = super().setup_class(complete_check=False)

        TestFeatureIsolation().check(cls.available, unit.temp_dir)

        return unit if not complete_check else unit.complete()

    def test_ruby_isolation_rootfs(self, is_su):
        isolation_features = self.available['features']['isolation'].keys()

        if 'mnt' not in isolation_features:
            pytest.skip('requires mnt ns')

        if not is_su:
            if 'user' not in isolation_features:
                pytest.skip('requires unprivileged userns or root')

            if not 'unprivileged_userns_clone' in isolation_features:
                pytest.skip('requires unprivileged userns or root')

        os.mkdir(self.temp_dir + '/ruby')

        shutil.copytree(
            option.test_dir + '/ruby/status_int',
            self.temp_dir + '/ruby/status_int',
        )
        isolation = {
            'namespaces': {'credential': not is_su, 'mount': True},
            'rootfs': self.temp_dir,
        }

        self.load('status_int', isolation=isolation)

        assert 'success' in self.conf(
            '"/ruby/status_int/config.ru"', 'applications/status_int/script',
        )

        assert 'success' in self.conf(
            '"/ruby/status_int"', 'applications/status_int/working_directory',
        )

        assert self.get()['status'] == 200, 'status int'
