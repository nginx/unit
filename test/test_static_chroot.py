import os
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto
from unit.option import option

prerequisites = {'features': {'chroot': True}}

client = ApplicationProto()
test_path = f'/{os.path.relpath(Path(__file__))}'


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    Path(f'{temp_dir}/assets/dir').mkdir(parents=True)
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


def update_action(chroot, share=f'{option.temp_dir}/assets$uri'):
    return client.conf(
        {'chroot': chroot, 'share': share},
        'routes/0/action',
    )


def get_custom(uri, host):
    return client.get(url=uri, headers={'Host': host, 'Connection': 'close'})[
        'status'
    ]


def test_static_chroot(temp_dir):
    assert client.get(url='/dir/file')['status'] == 200, 'default chroot'
    assert client.get(url='/index.html')['status'] == 200, 'default chroot 2'

    assert 'success' in update_action(f'{temp_dir}/assets/dir')

    assert client.get(url='/dir/file')['status'] == 200, 'chroot'
    assert client.get(url='/index.html')['status'] == 403, 'chroot 403 2'
    assert client.get(url='/file')['status'] == 403, 'chroot 403'


def test_share_chroot_array(temp_dir):
    assert 'success' in update_action(
        f'{temp_dir}/assets/dir', ["/blah", f'{temp_dir}/assets$uri']
    )
    assert client.get(url='/dir/file')['status'] == 200, 'share array'

    assert 'success' in update_action(
        f'{temp_dir}/assets/$host',
        ['/blah', f'{temp_dir}/assets$uri'],
    )
    assert get_custom('/dir/file', 'dir') == 200, 'array variable'

    assert 'success' in update_action(
        f'{temp_dir}/assets/dir', ['/blah', '/blah2']
    )
    assert client.get()['status'] != 200, 'share array bad'


def test_static_chroot_permission(require, temp_dir):
    require({'privileged_user': False})

    os.chmod(f'{temp_dir}/assets/dir', 0o100)

    assert 'success' in update_action(
        f'{temp_dir}/assets/dir'
    ), 'configure chroot'

    assert client.get(url='/dir/file')['status'] == 200, 'chroot'


def test_static_chroot_empty():
    assert 'success' in update_action('')
    assert client.get(url='/dir/file')['status'] == 200, 'empty absolute'

    assert 'success' in update_action("", ".$uri")
    assert client.get(url=test_path)['status'] == 200, 'empty relative'


def test_static_chroot_relative(require):
    require({'privileged_user': False})

    assert 'success' in update_action('.')
    assert client.get(url='/dir/file')['status'] == 403, 'relative chroot'

    assert 'success' in client.conf({"share": ".$uri"}, 'routes/0/action')
    assert client.get(url=test_path)['status'] == 200, 'relative share'

    assert 'success' in update_action(".", ".$uri")
    assert client.get(url=test_path)['status'] == 200, 'relative'


def test_static_chroot_variables(temp_dir):
    assert 'success' in update_action(f'{temp_dir}/assets/$host')
    assert get_custom('/dir/file', 'dir') == 200

    assert 'success' in update_action(f'{temp_dir}/assets/${{host}}')
    assert get_custom('/dir/file', 'dir') == 200


def test_static_chroot_variables_buildin_start(temp_dir):
    assert 'success' in update_action(
        '$uri/assets/dir',
        f'{temp_dir}/assets/dir/$host',
    )
    assert get_custom(temp_dir, 'file') == 200


def test_static_chroot_variables_buildin_mid(temp_dir):
    assert 'success' in update_action(f'{temp_dir}/$host/dir')
    assert get_custom('/dir/file', 'assets') == 200


def test_static_chroot_variables_buildin_end(temp_dir):
    assert 'success' in update_action(f'{temp_dir}/assets/$host')
    assert get_custom('/dir/file', 'dir') == 200


def test_static_chroot_slash(temp_dir):
    assert 'success' in update_action(f'{temp_dir}/assets/dir/')
    assert client.get(url='/dir/file')['status'] == 200, 'slash end'
    assert client.get(url='/dirxfile')['status'] == 403, 'slash end bad'

    assert 'success' in update_action(f'{temp_dir}/assets/dir')
    assert client.get(url='/dir/file')['status'] == 200, 'no slash end'

    assert 'success' in update_action(f'{temp_dir}/assets/dir/')
    assert client.get(url='/dir/file')['status'] == 200, 'slash end 2'
    assert client.get(url='/dirxfile')['status'] == 403, 'slash end 2 bad'

    assert 'success' in update_action(
        f'{temp_dir}//assets////dir///', f'{temp_dir}///assets/////$uri'
    )
    assert client.get(url='/dir/file')['status'] == 200, 'multiple slashes'


def test_static_chroot_invalid(temp_dir):
    assert 'error' in client.conf(
        {"share": temp_dir, "chroot": True},
        'routes/0/action',
    ), 'configure chroot error'
    assert 'error' in client.conf(
        {"share": temp_dir, "symlinks": "True"},
        'routes/0/action',
    ), 'configure symlink error'
    assert 'error' in client.conf(
        {"share": temp_dir, "mount": "True"},
        'routes/0/action',
    ), 'configure mount error'

    assert 'error' in update_action(f'{temp_dir}/assets/d$r$uri')
    assert 'error' in update_action(f'{temp_dir}/assets/$$uri')
