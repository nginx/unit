import os
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    assets_dir = f'{temp_dir}/assets'
    os.makedirs(f'{assets_dir}/dir')
    Path(f'{assets_dir}/index.html').write_text('0123456789', encoding='utf-8')

    os.makedirs(f'{assets_dir}/403')
    os.chmod(f'{assets_dir}/403', 0o000)

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "routes"},
            },
            "routes": [{"action": {"share": f'{assets_dir}$uri'}}],
            "applications": {},
        }
    )

    yield

    try:
        os.chmod(f'{assets_dir}/403', 0o777)
    except FileNotFoundError:
        pass


def action_update(conf):
    assert 'success' in client.conf(conf, 'routes/0/action')


def test_static_fallback():
    action_update({"share": "/blah"})
    assert client.get()['status'] == 404, 'bad path no fallback'

    action_update({"share": "/blah", "fallback": {"return": 200}})

    resp = client.get()
    assert resp['status'] == 200, 'bad path fallback status'
    assert resp['body'] == '', 'bad path fallback'


def test_static_fallback_valid_path(temp_dir):
    action_update(
        {"share": f"{temp_dir}/assets$uri", "fallback": {"return": 200}}
    )
    resp = client.get()
    assert resp['status'] == 200, 'fallback status'
    assert resp['body'] == '0123456789', 'fallback'

    resp = client.get(url='/403/')
    assert resp['status'] == 200, 'fallback status 403'
    assert resp['body'] == '', 'fallback 403'

    resp = client.post()
    assert resp['status'] == 200, 'fallback status 405'
    assert resp['body'] == '', 'fallback 405'

    assert client.get(url='/dir')['status'] == 301, 'fallback status 301'


def test_static_fallback_nested():
    action_update(
        {
            "share": "/blah",
            "fallback": {
                "share": "/blah/blah",
                "fallback": {"return": 200},
            },
        }
    )

    resp = client.get()
    assert resp['status'] == 200, 'fallback nested status'
    assert resp['body'] == '', 'fallback nested'


def test_static_fallback_share(temp_dir):
    action_update(
        {
            "share": "/blah",
            "fallback": {"share": f"{temp_dir}/assets$uri"},
        }
    )

    resp = client.get()
    assert resp['status'] == 200, 'fallback share status'
    assert resp['body'] == '0123456789', 'fallback share'

    resp = client.head()
    assert resp['status'] == 200, 'fallback share status HEAD'
    assert resp['body'] == '', 'fallback share HEAD'

    assert client.get(url='/dir')['status'] == 301, 'fallback share status 301'


def test_static_fallback_proxy():
    assert 'success' in client.conf(
        [
            {
                "match": {"destination": "*:8081"},
                "action": {"return": 200},
            },
            {
                "action": {
                    "share": "/blah",
                    "fallback": {"proxy": "http://127.0.0.1:8081"},
                }
            },
        ],
        'routes',
    ), 'configure fallback proxy route'

    resp = client.get()
    assert resp['status'] == 200, 'fallback proxy status'
    assert resp['body'] == '', 'fallback proxy'


@pytest.mark.skip('not yet')
def test_static_fallback_proxy_loop(skip_alert):
    skip_alert(
        r'open.*/blah/index.html.*failed',
        r'accept.*failed',
        r'socket.*failed',
        r'new connections are not accepted',
    )

    action_update(
        {"share": "/blah", "fallback": {"proxy": "http://127.0.0.1:8080"}}
    )
    client.get(no_recv=True)

    assert 'success' in client.conf_delete('listeners/*:8081')
    client.get(read_timeout=1)


def test_static_fallback_invalid():
    def check_error(conf):
        assert 'error' in client.conf(conf, 'routes/0/action')

    check_error({"share": "/blah", "fallback": {}})
    check_error({"share": "/blah", "fallback": ""})
    check_error({"return": 200, "fallback": {"share": "/blah"}})
    check_error(
        {"proxy": "http://127.0.0.1:8081", "fallback": {"share": "/blah"}}
    )
    check_error({"fallback": {"share": "/blah"}})
