import os

import pytest

from unit.applications.proto import TestApplicationProto


class TestShareSymlink(TestApplicationProto):
    prerequisites = {'features': ['chroot']}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, temp_dir):
        os.makedirs(temp_dir + '/assets/dir/dir')
        with open(temp_dir + '/assets/index.html', 'w') as index, open(
            temp_dir + '/assets/dir/file', 'w'
        ) as file:
            index.write('0123456789')
            file.write('blah')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets"}}],
            }
        )

    def test_share_symlink(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        os.symlink(temp_dir + '/assets/dir', temp_dir + '/assets/link')

        assert self.get(url='/dir')['status'] == 301, 'dir'
        assert self.get(url='/dir/file')['status'] == 200, 'file'
        assert self.get(url='/link')['status'] == 301, 'symlink dir'
        assert self.get(url='/link/file')['status'] == 200, 'symlink file'

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets", "follow_symlinks": False},
            'routes/0/action',
        ), 'configure symlink disable'

        assert self.get(url='/link/file')['status'] == 403, 'symlink disabled'

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets", "follow_symlinks": True},
            'routes/0/action',
        ), 'configure symlink enable'

        assert self.get(url='/link/file')['status'] == 200, 'symlink enabled'

    def test_share_symlink_two_blocks(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        os.symlink(temp_dir + '/assets/dir', temp_dir + '/assets/link')

        assert 'success' in self.conf(
            [
                {
                    "match": {"method": "HEAD"},
                    "action": {
                        "share": temp_dir + "/assets",
                        "follow_symlinks": False,
                    },
                },
                {
                    "match": {"method": "GET"},
                    "action": {
                        "share": temp_dir + "/assets",
                        "follow_symlinks": True,
                    },
                },
            ],
            'routes',
        ), 'configure two options'

        assert self.get(url='/link/file')['status'] == 200, 'block enabled'
        assert self.head(url='/link/file')['status'] == 403, 'block disabled'

    def test_share_symlink_chroot(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        os.symlink(
            temp_dir + '/assets/dir/file', temp_dir + '/assets/dir/dir/link'
        )

        assert self.get(url='/dir/dir/link')['status'] == 200, 'default chroot'

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets",
                "chroot": temp_dir + "/assets/dir/dir",
            },
            'routes/0/action',
        ), 'configure chroot'

        assert self.get(url='/dir/dir/link')['status'] == 404, 'chroot'
