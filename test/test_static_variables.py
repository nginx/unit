import os
from pathlib import Path

import pytest
from unit.applications.proto import TestApplicationProto


class TestStaticVariables(TestApplicationProto):
    prerequisites = {}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, temp_dir):
        os.makedirs(temp_dir + '/assets/dir')
        os.makedirs(temp_dir + '/assets/d$r')
        Path(temp_dir + '/assets/index.html').write_text('0123456789')
        Path(temp_dir + '/assets/dir/file').write_text('file')
        Path(temp_dir + '/assets/d$r/file').write_text('d$r')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets$uri"}}],
            }
        )

    def update_share(self, share):
        if isinstance(share, list):
            return self.conf(share, 'routes/0/action/share')

        return self.conf('"' + share + '"', 'routes/0/action/share')

    def test_static_variables(self, temp_dir):
        assert self.get(url='/index.html')['status'] == 200
        assert self.get(url='/d$r/file')['status'] == 200

        assert 'success' in self.update_share('$uri')
        assert self.get(url=temp_dir + '/assets/index.html')['status'] == 200

        assert 'success' in self.update_share(temp_dir + '/assets${uri}')
        assert self.get(url='/index.html')['status'] == 200

    def test_static_variables_array(self, temp_dir):
        assert 'success' in self.update_share(
            [temp_dir + '/assets$uri', '$uri']
        )

        assert self.get(url='/dir/file')['status'] == 200
        assert self.get(url=temp_dir + '/assets/index.html')['status'] == 200
        assert self.get(url='/blah')['status'] == 404

        assert 'success' in self.conf(
            {
                "share": [temp_dir + '/assets$uri', '$uri'],
                "fallback": {"return": 201},
            },
            'routes/0/action',
        )

        assert self.get(url='/dir/file')['status'] == 200
        assert self.get(url=temp_dir + '/assets/index.html')['status'] == 200
        assert self.get(url='/dir/blah')['status'] == 201

    def test_static_variables_buildin_start(self, temp_dir):
        assert 'success' in self.update_share('$uri/assets/index.html')
        assert self.get(url=temp_dir)['status'] == 200

    def test_static_variables_buildin_mid(self, temp_dir):
        assert 'success' in self.update_share(temp_dir + '$uri/index.html')
        assert self.get(url='/assets')['status'] == 200

    def test_static_variables_buildin_end(self):
        assert self.get(url='/index.html')['status'] == 200

    def test_static_variables_invalid(self, temp_dir):
        assert 'error' in self.update_share(temp_dir + '/assets/d$r$uri')
        assert 'error' in self.update_share(temp_dir + '/assets/$$uri')
        assert 'error' in self.update_share(
            [temp_dir + '/assets$uri', temp_dir + '/assets/dir', '$$uri']
        )
