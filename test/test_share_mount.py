import os
import subprocess

import pytest

from unit.applications.proto import TestApplicationProto


class TestShareMount(TestApplicationProto):
    prerequisites = {'features': ['chroot']}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, is_su, temp_dir):
        if not is_su:
            pytest.skip('requires root')

        os.makedirs(temp_dir + '/assets/dir/mount')
        os.makedirs(temp_dir + '/assets/dir/dir')
        os.makedirs(temp_dir + '/assets/mount')
        with open(temp_dir + '/assets/index.html', 'w') as index, open(
            temp_dir + '/assets/dir/dir/file', 'w'
        ) as file, open(temp_dir + '/assets/mount/index.html', 'w') as mount:
            index.write('index')
            file.write('file')
            mount.write('mount')

        try:
            process = subprocess.Popen(
                [
                    "mount",
                    "--bind",
                    temp_dir + "/assets/mount",
                    temp_dir + "/assets/dir/mount",
                ],
                stderr=subprocess.STDOUT,
            )

            process.communicate()

        except KeyboardInterrupt:
            raise

        except:
            pytest.fail('Can\'t run mount process.')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": temp_dir + "/assets/dir"}}],
            }
        )

        yield

        try:
            process = subprocess.Popen(
                ["umount", "--lazy", temp_dir + "/assets/dir/mount"],
                stderr=subprocess.STDOUT,
            )

            process.communicate()

        except KeyboardInterrupt:
            raise

        except:
            pytest.fail('Can\'t run umount process.')

    def test_share_mount(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        resp = self.get(url='/mount/')
        assert resp['status'] == 200
        assert resp['body'] == 'mount'

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets/dir", "traverse_mounts": False},
            'routes/0/action',
        ), 'configure mount disable'

        assert self.get(url='/mount/')['status'] == 403

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets/dir", "traverse_mounts": True},
            'routes/0/action',
        ), 'configure mount enable'

        resp = self.get(url='/mount/')
        assert resp['status'] == 200
        assert resp['body'] == 'mount'

    def test_share_mount_two_blocks(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        os.symlink(temp_dir + '/assets/dir', temp_dir + '/assets/link')

        assert 'success' in self.conf(
            [
                {
                    "match": {"method": "HEAD"},
                    "action": {
                        "share": temp_dir + "/assets/dir",
                        "traverse_mounts": False,
                    },
                },
                {
                    "match": {"method": "GET"},
                    "action": {
                        "share": temp_dir + "/assets/dir",
                        "traverse_mounts": True,
                    },
                },
            ],
            'routes',
        ), 'configure two options'

        assert self.get(url='/mount/')['status'] == 200, 'block enabled'
        assert self.head(url='/mount/')['status'] == 403, 'block disabled'

    def test_share_mount_chroot(self, temp_dir, skip_alert):
        skip_alert(r'opening.*failed')

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets/dir",
                "chroot": temp_dir + "/assets",
            },
            'routes/0/action',
        ), 'configure chroot mount default'

        assert self.get(url='/mount/')['status'] == 200, 'chroot'

        assert 'success' in self.conf(
            {
                "share": temp_dir + "/assets/dir",
                "chroot": temp_dir + "/assets",
                "traverse_mounts": False,
            },
            'routes/0/action',
        ), 'configure chroot mount disable'

        assert self.get(url='/mount/')['status'] == 403, 'chroot mount'
