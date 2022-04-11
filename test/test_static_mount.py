import os
import subprocess
from pathlib import Path

import pytest
from unit.applications.proto import TestApplicationProto


class TestStaticMount(TestApplicationProto):
    prerequisites = {'features': ['chroot']}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        os.makedirs(temp_dir + '/assets/dir/mount')
        os.makedirs(temp_dir + '/assets/dir/dir')
        os.makedirs(temp_dir + '/assets/mount')
        Path(temp_dir + '/assets/index.html').write_text('index')
        Path(temp_dir + '/assets/dir/dir/file').write_text('file')
        Path(temp_dir + '/assets/mount/index.html').write_text('mount')

        try:
            subprocess.check_output(
                [
                    "mount",
                    "--bind",
                    temp_dir + "/assets/mount",
                    temp_dir + "/assets/dir/mount",
                ],
                stderr=subprocess.STDOUT,
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            pytest.fail('Can\'t run mount process.')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets/dir$uri"}}],
            }
        )

        yield

        try:
            subprocess.check_output(
                ["umount", "--lazy", temp_dir + "/assets/dir/mount"],
                stderr=subprocess.STDOUT,
            )

        except KeyboardInterrupt:
            raise

        except subprocess.CalledProcessError:
            pytest.fail('Can\'t run umount process.')

    def test_static_mount(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        resp = self.get(url='/mount/')
        assert resp['status'] == 200
        assert resp['body'] == 'mount'

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets/dir$uri", "traverse_mounts": False},
            'routes/0/action',
        ), 'configure mount disable'

        assert self.get(url='/mount/')['status'] == 403

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets/dir$uri", "traverse_mounts": True},
            'routes/0/action',
        ), 'configure mount enable'

        resp = self.get(url='/mount/')
        assert resp['status'] == 200
        assert resp['body'] == 'mount'

    def test_static_mount_two_blocks(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        os.symlink(temp_dir + '/assets/dir', temp_dir + '/assets/link')

        assert 'success' in self.conf(
            [
                {
                    "match": {"method": "HEAD"},
                    "action": {
                        "share": temp_dir + "/assets/dir$uri",
                        "traverse_mounts": False,
                    },
                },
                {
                    "match": {"method": "GET"},
                    "action": {
                        "share": temp_dir + "/assets/dir$uri",
                        "traverse_mounts": True,
                    },
                },
            ],
            'routes',
        ), 'configure two options'

        assert self.get(url='/mount/')['status'] == 200, 'block enabled'
        assert self.head(url='/mount/')['status'] == 403, 'block disabled'

    def test_static_mount_chroot(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets/dir$uri",
                "chroot": temp_dir + "/assets",
            },
            'routes/0/action',
        ), 'configure chroot mount default'

        assert self.get(url='/mount/')['status'] == 200, 'chroot'

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets/dir$uri",
                "chroot": temp_dir + "/assets",
                "traverse_mounts": False,
            },
            'routes/0/action',
        ), 'configure chroot mount disable'

        assert self.get(url='/mount/')['status'] == 403, 'chroot mount'
