import os
from pathlib import Path

import pytest

from unit.applications.proto import TestApplicationProto


class TestStaticChroot(TestApplicationProto):
    prerequisites = {'features': ['chroot']}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, temp_dir):
        os.makedirs(temp_dir + '/assets/dir')
        Path(temp_dir + '/assets/index.html').write_text('0123456789')
        Path(temp_dir + '/assets/dir/file').write_text('blah')

        test = Path(__file__)
        self.test_path = '/' + test.parent.name + '/' + test.name

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets$uri"}}],
            }
        )

    def test_static_chroot(self, temp_dir):
        assert self.get(url='/dir/file')['status'] == 200, 'default chroot'
        assert self.get(url='/index.html')['status'] == 200, 'default chroot 2'

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets$uri",
                "chroot": temp_dir + "/assets/dir",
            },
            'routes/0/action',
        ), 'configure chroot'

        assert self.get(url='/dir/file')['status'] == 200, 'chroot'
        assert self.get(url='/index.html')['status'] == 403, 'chroot 403 2'
        assert self.get(url='/file')['status'] == 403, 'chroot 403'

    def test_static_chroot_permission(self, is_su, temp_dir):
        if is_su:
            pytest.skip('does\'t work under root')

        os.chmod(temp_dir + '/assets/dir', 0o100)

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets$uri",
                "chroot": temp_dir + "/assets/dir",
            },
            'routes/0/action',
        ), 'configure chroot'

        assert self.get(url='/dir/file')['status'] == 200, 'chroot'

    def test_static_chroot_empty(self, temp_dir):
        assert 'success' in self.conf(
            {"share": temp_dir + "/assets$uri", "chroot": ""},
            'routes/0/action',
        ), 'configure chroot empty absolute'

        assert (
            self.get(url='/dir/file')['status'] == 200
        ), 'chroot empty absolute'

        assert 'success' in self.conf(
            {"share": ".$uri", "chroot": ""}, 'routes/0/action',
        ), 'configure chroot empty relative'

        assert (
            self.get(url=self.test_path)['status'] == 200
        ), 'chroot empty relative'

    def test_static_chroot_relative(self, is_su, temp_dir):
        if is_su:
            pytest.skip('does\'t work under root')

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets$uri", "chroot": "."},
            'routes/0/action',
        ), 'configure relative chroot'

        assert self.get(url='/dir/file')['status'] == 403, 'relative chroot'

        assert 'success' in self.conf(
            {"share": ".$uri"}, 'routes/0/action',
        ), 'configure relative share'

        assert self.get(url=self.test_path)['status'] == 200, 'relative share'

        assert 'success' in self.conf(
            {"share": ".$uri", "chroot": "."}, 'routes/0/action',
        ), 'configure relative'

        assert self.get(url=self.test_path)['status'] == 200, 'relative'

    def test_static_chroot_invalid(self, temp_dir):
        assert 'error' in self.conf(
            {"share": temp_dir, "chroot": True}, 'routes/0/action',
        ), 'configure chroot error'
        assert 'error' in self.conf(
            {"share": temp_dir, "symlinks": "True"}, 'routes/0/action',
        ), 'configure symlink error'
        assert 'error' in self.conf(
            {"share": temp_dir, "mount": "True"}, 'routes/0/action',
        ), 'configure mount error'
