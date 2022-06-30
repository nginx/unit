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

        self.test_path = '/' + os.path.relpath(Path(__file__))

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets$uri"}}],
            }
        )

    def update_action(self, share, chroot):
        return self.conf(
            {"share": share, "chroot": chroot},
            'routes/0/action',
        )

    def get_custom(self, uri, host):
        return self.get(url=uri, headers={'Host': host, 'Connection': 'close'})[
            'status'
        ]

    def test_static_chroot(self, temp_dir):
        assert self.get(url='/dir/file')['status'] == 200, 'default chroot'
        assert self.get(url='/index.html')['status'] == 200, 'default chroot 2'

        assert 'success' in self.update_action(
            temp_dir + "/assets$uri", temp_dir + "/assets/dir"
        )

        assert self.get(url='/dir/file')['status'] == 200, 'chroot'
        assert self.get(url='/index.html')['status'] == 403, 'chroot 403 2'
        assert self.get(url='/file')['status'] == 403, 'chroot 403'

    def test_share_chroot_array(self, temp_dir):
        assert 'success' in self.update_action(
            ["/blah", temp_dir + "/assets$uri"], temp_dir + "/assets/dir"
        )
        assert self.get(url='/dir/file')['status'] == 200, 'share array'

        assert 'success' in self.update_action(
            ["/blah", temp_dir + '/assets$uri'], temp_dir + '/assets/$host'
        )
        assert self.get_custom('/dir/file', 'dir') == 200, 'array variable'

        assert 'success' in self.update_action(
            ["/blah", "/blah2"], temp_dir + "/assets/dir"
        )
        assert self.get()['status'] != 200, 'share array bad'

    def test_static_chroot_permission(self, is_su, temp_dir):
        if is_su:
            pytest.skip('does\'t work under root')

        os.chmod(temp_dir + '/assets/dir', 0o100)

        assert 'success' in self.update_action(
            temp_dir + "/assets$uri", temp_dir + "/assets/dir"
        ), 'configure chroot'

        assert self.get(url='/dir/file')['status'] == 200, 'chroot'

    def test_static_chroot_empty(self, temp_dir):
        assert 'success' in self.update_action(temp_dir + "/assets$uri", "")
        assert self.get(url='/dir/file')['status'] == 200, 'empty absolute'

        assert 'success' in self.update_action(".$uri", "")
        assert self.get(url=self.test_path)['status'] == 200, 'empty relative'

    def test_static_chroot_relative(self, is_su, temp_dir):
        if is_su:
            pytest.skip('does\'t work under root')

        assert 'success' in self.update_action(temp_dir + "/assets$uri", ".")
        assert self.get(url='/dir/file')['status'] == 403, 'relative chroot'

        assert 'success' in self.conf({"share": ".$uri"}, 'routes/0/action')
        assert self.get(url=self.test_path)['status'] == 200, 'relative share'

        assert 'success' in self.update_action(".$uri", ".")
        assert self.get(url=self.test_path)['status'] == 200, 'relative'

    def test_static_chroot_variables(self, temp_dir):
        assert 'success' in self.update_action(
            temp_dir + '/assets$uri', temp_dir + '/assets/$host'
        )
        assert self.get_custom('/dir/file', 'dir') == 200

        assert 'success' in self.update_action(
            temp_dir + '/assets$uri', temp_dir + '/assets/${host}'
        )
        assert self.get_custom('/dir/file', 'dir') == 200

    def test_static_chroot_variables_buildin_start(self, temp_dir):
        assert 'success' in self.update_action(
            temp_dir + '/assets/dir/$host', '$uri/assets/dir'
        )
        assert self.get_custom(temp_dir, 'file') == 200

    def test_static_chroot_variables_buildin_mid(self, temp_dir):
        assert 'success' in self.update_action(
            temp_dir + '/assets$uri', temp_dir + '/$host/dir'
        )
        assert self.get_custom('/dir/file', 'assets') == 200

    def test_static_chroot_variables_buildin_end(self, temp_dir):
        assert 'success' in self.update_action(
            temp_dir + '/assets$uri', temp_dir + '/assets/$host'
        )
        assert self.get_custom('/dir/file', 'dir') == 200

    def test_static_chroot_slash(self, temp_dir):
        assert 'success' in self.update_action(
            temp_dir + "/assets$uri", temp_dir + "/assets/dir/"
        )
        assert self.get(url='/dir/file')['status'] == 200, 'slash end'
        assert self.get(url='/dirxfile')['status'] == 403, 'slash end bad'

        assert 'success' in self.update_action(
            temp_dir + "/assets$uri", temp_dir + "/assets/dir"
        )
        assert self.get(url='/dir/file')['status'] == 200, 'no slash end'

        assert 'success' in self.update_action(
            temp_dir + "/assets$uri", temp_dir + "/assets/dir/"
        )
        assert self.get(url='/dir/file')['status'] == 200, 'slash end 2'
        assert self.get(url='/dirxfile')['status'] == 403, 'slash end 2 bad'

        assert 'success' in self.update_action(
            temp_dir + "///assets/////$uri", temp_dir + "//assets////dir///"
        )
        assert self.get(url='/dir/file')['status'] == 200, 'multiple slashes'

    def test_static_chroot_invalid(self, temp_dir):
        assert 'error' in self.conf(
            {"share": temp_dir, "chroot": True},
            'routes/0/action',
        ), 'configure chroot error'
        assert 'error' in self.conf(
            {"share": temp_dir, "symlinks": "True"},
            'routes/0/action',
        ), 'configure symlink error'
        assert 'error' in self.conf(
            {"share": temp_dir, "mount": "True"},
            'routes/0/action',
        ), 'configure mount error'

        assert 'error' in self.update_action(
            temp_dir + '/assets$uri', temp_dir + '/assets/d$r$uri'
        )
        assert 'error' in self.update_action(
            temp_dir + '/assets$uri', temp_dir + '/assets/$$uri'
        )
