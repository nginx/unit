import os
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    os.makedirs(f'{temp_dir}/assets/dir')
    os.makedirs(f'{temp_dir}/assets/d$r')
    Path(f'{temp_dir}/assets/index.html').write_text(
        '0123456789', encoding='utf-8'
    )
    Path(f'{temp_dir}/assets/dir/file').write_text('file', encoding='utf-8')
    Path(f'{temp_dir}/assets/d$r/file').write_text('d$r', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f'{temp_dir}/assets$uri'}}],
        }
    )


def update_share(share):
    if isinstance(share, list):
        return client.conf(share, 'routes/0/action/share')

    return client.conf(f'"{share}"', 'routes/0/action/share')


def test_static_variables(temp_dir):
    assert client.get(url='/index.html')['status'] == 200
    assert client.get(url='/d$r/file')['status'] == 200

    assert 'success' in update_share('$uri')
    assert client.get(url=f'{temp_dir}/assets/index.html')['status'] == 200

    assert 'success' in update_share(f'{temp_dir}/assets${{uri}}')
    assert client.get(url='/index.html')['status'] == 200


def test_static_variables_array(temp_dir):
    assert 'success' in update_share([f'{temp_dir}/assets$uri', '$uri'])

    assert client.get(url='/dir/file')['status'] == 200
    assert client.get(url=f'{temp_dir}/assets/index.html')['status'] == 200
    assert client.get(url='/blah')['status'] == 404

    assert 'success' in client.conf(
        {
            "share": [f'{temp_dir}/assets$uri', '$uri'],
            "fallback": {"return": 201},
        },
        'routes/0/action',
    )

    assert client.get(url='/dir/file')['status'] == 200
    assert client.get(url=f'{temp_dir}/assets/index.html')['status'] == 200
    assert client.get(url='/dir/blah')['status'] == 201


def test_static_variables_buildin_start(temp_dir):
    assert 'success' in update_share('$uri/assets/index.html')
    assert client.get(url=temp_dir)['status'] == 200


def test_static_variables_buildin_mid(temp_dir):
    assert 'success' in update_share(f'{temp_dir}$uri/index.html')
    assert client.get(url='/assets')['status'] == 200


def test_static_variables_buildin_end():
    assert client.get(url='/index.html')['status'] == 200


def test_static_variables_invalid(temp_dir):
    assert 'error' in update_share(f'{temp_dir}/assets/d$r$uri')
    assert 'error' in update_share(f'{temp_dir}/assets/$$uri')
    assert 'error' in update_share(
        [f'{temp_dir}/assets$uri', f'{temp_dir}/assets/dir', '$$uri']
    )
