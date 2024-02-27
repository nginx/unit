import os
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

prerequisites = {'features': {'chroot': True}}

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    os.makedirs(f'{temp_dir}/assets/dir/dir')
    Path(f'{temp_dir}/assets/index.html').write_text(
        '0123456789', encoding='utf-8'
    )
    Path(f'{temp_dir}/assets/dir/file').write_text('blah', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f'{temp_dir}/assets$uri'}}],
        }
    )


def test_static_symlink(temp_dir, skip_alert):
    skip_alert(r'opening.*failed')

    os.symlink(f'{temp_dir}/assets/dir', f'{temp_dir}/assets/link')

    assert client.get(url='/dir')['status'] == 301, 'dir'
    assert client.get(url='/dir/file')['status'] == 200, 'file'
    assert client.get(url='/link')['status'] == 301, 'symlink dir'
    assert client.get(url='/link/file')['status'] == 200, 'symlink file'

    assert 'success' in client.conf(
        {"share": f'{temp_dir}/assets$uri', "follow_symlinks": False},
        'routes/0/action',
    ), 'configure symlink disable'

    assert client.get(url='/link/file')['status'] == 403, 'symlink disabled'

    assert 'success' in client.conf(
        {"share": f'{temp_dir}/assets$uri', "follow_symlinks": True},
        'routes/0/action',
    ), 'configure symlink enable'

    assert client.get(url='/link/file')['status'] == 200, 'symlink enabled'


def test_static_symlink_two_blocks(temp_dir, skip_alert):
    skip_alert(r'opening.*failed')

    os.symlink(f'{temp_dir}/assets/dir', f'{temp_dir}/assets/link')

    assert 'success' in client.conf(
        [
            {
                "match": {"method": "HEAD"},
                "action": {
                    "share": f'{temp_dir}/assets$uri',
                    "follow_symlinks": False,
                },
            },
            {
                "match": {"method": "GET"},
                "action": {
                    "share": f'{temp_dir}/assets$uri',
                    "follow_symlinks": True,
                },
            },
        ],
        'routes',
    ), 'configure two options'

    assert client.get(url='/link/file')['status'] == 200, 'block enabled'
    assert client.head(url='/link/file')['status'] == 403, 'block disabled'


def test_static_symlink_chroot(temp_dir, skip_alert):
    skip_alert(r'opening.*failed')

    os.symlink(f'{temp_dir}/assets/dir/file', f'{temp_dir}/assets/dir/dir/link')

    assert client.get(url='/dir/dir/link')['status'] == 200, 'default chroot'

    assert 'success' in client.conf(
        {
            "share": f'{temp_dir}/assets$uri',
            "chroot": f'{temp_dir}/assets/dir/dir',
        },
        'routes/0/action',
    ), 'configure chroot'

    assert client.get(url='/dir/dir/link')['status'] == 404, 'chroot'
