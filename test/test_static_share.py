import os
from pathlib import Path

import pytest
from unit.applications.proto import TestApplicationProto


class TestStaticShare(TestApplicationProto):
    prerequisites = {}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, temp_dir):
        os.makedirs(temp_dir + '/assets/dir')
        os.makedirs(temp_dir + '/assets/dir2')

        Path(temp_dir + '/assets/dir/file').write_text('1')
        Path(temp_dir + '/assets/dir2/file2').write_text('2')

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets$uri"}}],
                "applications": {},
            }
        )

    def action_update(self, conf):
        assert 'success' in self.conf(conf, 'routes/0/action')

    def test_share_array(self, temp_dir):
        assert self.get(url='/dir/file')['body'] == '1'
        assert self.get(url='/dir2/file2')['body'] == '2'

        self.action_update({"share": [temp_dir + "/assets/dir$uri"]})

        assert self.get(url='/file')['body'] == '1'
        assert self.get(url='/file2')['status'] == 404

        self.action_update(
            {
                "share": [
                    temp_dir + "/assets/dir$uri",
                    temp_dir + "/assets/dir2$uri",
                ]
            }
        )

        assert self.get(url='/file')['body'] == '1'
        assert self.get(url='/file2')['body'] == '2'

        self.action_update(
            {
                "share": [
                    temp_dir + "/assets/dir2$uri",
                    temp_dir + "/assets/dir3$uri",
                ]
            }
        )

        assert self.get(url='/file')['status'] == 404
        assert self.get(url='/file2')['body'] == '2'

    def test_share_array_fallback(self):
        self.action_update(
            {"share": ["/blah", "/blah2"], "fallback": {"return": 201}}
        )

        assert self.get()['status'] == 201

    def test_share_array_invalid(self):
        assert 'error' in self.conf({"share": []}, 'routes/0/action')
        assert 'error' in self.conf({"share": {}}, 'routes/0/action')
