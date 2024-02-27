from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    Path(f'{temp_dir}/assets').mkdir()
    for ext in ['.xml', '.mp4', '.php', '', '.txt', '.html', '.png']:
        Path(f'{temp_dir}/assets/file{ext}').write_text(ext, encoding='utf-8')

    Path(f'{temp_dir}/assets/index.html').write_text('index', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "routes"},
            },
            "routes": [{"action": {"share": f'{temp_dir}/assets$uri'}}],
            "applications": {},
        }
    )


def action_update(conf):
    assert 'success' in client.conf(conf, 'routes/0/action')


def check_body(http_url, body):
    resp = client.get(url=http_url)
    assert resp['status'] == 200, 'status'
    assert resp['body'] == body, 'body'


def test_static_types_basic(temp_dir):
    action_update({"share": f'{temp_dir}/assets$uri'})
    check_body('/index.html', 'index')
    check_body('/file.xml', '.xml')

    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": "application/xml"}
    )
    check_body('/file.xml', '.xml')

    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": ["application/xml"]}
    )
    check_body('/file.xml', '.xml')

    action_update({"share": f'{temp_dir}/assets$uri', "types": [""]})
    assert client.get(url='/file.xml')['status'] == 403, 'no mtype'


def test_static_types_wildcard(temp_dir):
    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": ["application/*"]}
    )
    check_body('/file.xml', '.xml')
    assert client.get(url='/file.mp4')['status'] == 403, 'app * mtype mp4'

    action_update({"share": f'{temp_dir}/assets$uri', "types": ["video/*"]})
    assert client.get(url='/file.xml')['status'] == 403, 'video * mtype xml'
    check_body('/file.mp4', '.mp4')


def test_static_types_negation(temp_dir):
    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": ["!application/xml"]}
    )
    assert client.get(url='/file.xml')['status'] == 403, 'forbidden negation'
    check_body('/file.mp4', '.mp4')

    # sorting negation
    action_update(
        {
            "share": f'{temp_dir}/assets$uri',
            "types": ["!video/*", "image/png", "!image/jpg"],
        }
    )
    assert client.get(url='/file.mp4')['status'] == 403, 'negation sort mp4'
    check_body('/file.png', '.png')
    assert client.get(url='/file.jpg')['status'] == 403, 'negation sort jpg'


def test_static_types_regex(temp_dir):
    action_update(
        {
            "share": f'{temp_dir}/assets$uri',
            "types": ["~text/(html|plain)"],
        }
    )
    assert client.get(url='/file.php')['status'] == 403, 'regex fail'
    check_body('/file.html', '.html')
    check_body('/file.txt', '.txt')


def test_static_types_case(temp_dir):
    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": ["!APpliCaTiOn/xMl"]}
    )
    check_body('/file.mp4', '.mp4')
    assert (
        client.get(url='/file.xml')['status'] == 403
    ), 'mixed case xml negation'

    action_update({"share": f'{temp_dir}/assets$uri', "types": ["vIdEo/mp4"]})
    assert client.get(url='/file.mp4')['status'] == 200, 'mixed case'
    assert (
        client.get(url='/file.xml')['status'] == 403
    ), 'mixed case video negation'

    action_update({"share": f'{temp_dir}/assets$uri', "types": ["vIdEo/*"]})
    check_body('/file.mp4', '.mp4')
    assert (
        client.get(url='/file.xml')['status'] == 403
    ), 'mixed case video * negation'


def test_static_types_fallback(temp_dir):
    assert 'success' in client.conf(
        [
            {
                "match": {"destination": "*:8081"},
                "action": {"return": 200},
            },
            {
                "action": {
                    "share": f'{temp_dir}/assets$uri',
                    "types": ["!application/x-httpd-php"],
                    "fallback": {"proxy": "http://127.0.0.1:8081"},
                }
            },
        ],
        'routes',
    ), 'configure fallback proxy route'

    check_body('/file.php', '')
    check_body('/file.mp4', '.mp4')


def test_static_types_index(temp_dir):
    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": "application/xml"}
    )
    check_body('/', 'index')
    check_body('/file.xml', '.xml')
    assert client.get(url='/index.html')['status'] == 403, 'forbidden mtype'
    assert client.get(url='/file.mp4')['status'] == 403, 'forbidden mtype'


def test_static_types_custom_mime(temp_dir):
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f'{temp_dir}/assets$uri'}}],
            "applications": {},
            "settings": {
                "http": {"static": {"mime_types": {"test/mime-type": ["file"]}}}
            },
        }
    )

    action_update({"share": f'{temp_dir}/assets$uri', "types": [""]})
    assert client.get(url='/file')['status'] == 403, 'forbidden custom mime'

    action_update(
        {"share": f'{temp_dir}/assets$uri', "types": ["test/mime-type"]}
    )
    check_body('/file', '')
