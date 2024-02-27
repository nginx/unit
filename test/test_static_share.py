import os
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    os.makedirs(f'{temp_dir}/assets/dir')
    os.makedirs(f'{temp_dir}/assets/dir2')

    Path(f'{temp_dir}/assets/dir/file').write_text('1', encoding='utf-8')
    Path(f'{temp_dir}/assets/dir2/file2').write_text('2', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f'{temp_dir}/assets$uri'}}],
            "applications": {},
        }
    )


def action_update(conf):
    assert 'success' in client.conf(conf, 'routes/0/action')


def test_share_array(temp_dir):
    assert client.get(url='/dir/file')['body'] == '1'
    assert client.get(url='/dir2/file2')['body'] == '2'

    action_update({"share": [f'{temp_dir}/assets/dir$uri']})

    assert client.get(url='/file')['body'] == '1'
    assert client.get(url='/file2')['status'] == 404

    action_update(
        {
            "share": [
                f'{temp_dir}/assets/dir$uri',
                f'{temp_dir}/assets/dir2$uri',
            ]
        }
    )

    assert client.get(url='/file')['body'] == '1'
    assert client.get(url='/file2')['body'] == '2'

    action_update(
        {
            "share": [
                f'{temp_dir}/assets/dir2$uri',
                f'{temp_dir}/assets/dir3$uri',
            ]
        }
    )

    assert client.get(url='/file')['status'] == 404
    assert client.get(url='/file2')['body'] == '2'


def test_share_array_fallback():
    action_update({"share": ["/blah", "/blah2"], "fallback": {"return": 201}})

    assert client.get()['status'] == 201


def test_share_array_invalid():
    assert 'error' in client.conf({"share": []}, 'routes/0/action')
    assert 'error' in client.conf({"share": {}}, 'routes/0/action')
