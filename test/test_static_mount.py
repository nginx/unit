import os
import subprocess
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

prerequisites = {'features': {'chroot': True}, 'privileged_user': True}

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    os.makedirs(f'{temp_dir}/assets/dir/mount')
    os.makedirs(f'{temp_dir}/assets/dir/dir')
    os.makedirs(f'{temp_dir}/assets/mount')
    Path(f'{temp_dir}/assets/index.html').write_text('index', encoding='utf-8')
    Path(f'{temp_dir}/assets/dir/dir/file').write_text('file', encoding='utf-8')
    Path(f'{temp_dir}/assets/mount/index.html').write_text(
        'mount', encoding='utf-8'
    )

    try:
        subprocess.check_output(
            [
                "mount",
                "--bind",
                f'{temp_dir}/assets/mount',
                f'{temp_dir}/assets/dir/mount',
            ],
            stderr=subprocess.STDOUT,
        )

    except KeyboardInterrupt:
        raise

    except subprocess.CalledProcessError:
        pytest.fail("Can't run mount process.")

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f'{temp_dir}/assets/dir$uri'}}],
        }
    )

    yield

    try:
        subprocess.check_output(
            ["umount", "--lazy", f'{temp_dir}/assets/dir/mount'],
            stderr=subprocess.STDOUT,
        )

    except KeyboardInterrupt:
        raise

    except subprocess.CalledProcessError:
        pytest.fail("Can't run umount process.")


def test_static_mount(temp_dir, skip_alert):
    skip_alert(r'opening.*failed')

    resp = client.get(url='/mount/')
    assert resp['status'] == 200
    assert resp['body'] == 'mount'

    assert 'success' in client.conf(
        {"share": f'{temp_dir}/assets/dir$uri', "traverse_mounts": False},
        'routes/0/action',
    ), 'configure mount disable'

    assert client.get(url='/mount/')['status'] == 403

    assert 'success' in client.conf(
        {"share": f'{temp_dir}/assets/dir$uri', "traverse_mounts": True},
        'routes/0/action',
    ), 'configure mount enable'

    resp = client.get(url='/mount/')
    assert resp['status'] == 200
    assert resp['body'] == 'mount'


def test_static_mount_two_blocks(temp_dir, skip_alert):
    skip_alert(r'opening.*failed')

    os.symlink(f'{temp_dir}/assets/dir', f'{temp_dir}/assets/link')

    assert 'success' in client.conf(
        [
            {
                "match": {"method": "HEAD"},
                "action": {
                    "share": f'{temp_dir}/assets/dir$uri',
                    "traverse_mounts": False,
                },
            },
            {
                "match": {"method": "GET"},
                "action": {
                    "share": f'{temp_dir}/assets/dir$uri',
                    "traverse_mounts": True,
                },
            },
        ],
        'routes',
    ), 'configure two options'

    assert client.get(url='/mount/')['status'] == 200, 'block enabled'
    assert client.head(url='/mount/')['status'] == 403, 'block disabled'


def test_static_mount_chroot(temp_dir, skip_alert):
    skip_alert(r'opening.*failed')

    assert 'success' in client.conf(
        {
            "share": f'{temp_dir}/assets/dir$uri',
            "chroot": f'{temp_dir}/assets',
        },
        'routes/0/action',
    ), 'configure chroot mount default'

    assert client.get(url='/mount/')['status'] == 200, 'chroot'

    assert 'success' in client.conf(
        {
            "share": f'{temp_dir}/assets/dir$uri',
            "chroot": f'{temp_dir}/assets',
            "traverse_mounts": False,
        },
        'routes/0/action',
    ), 'configure chroot mount disable'

    assert client.get(url='/mount/')['status'] == 403, 'chroot mount'
