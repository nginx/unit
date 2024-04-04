from pathlib import Path

import pytest

from unit.applications.lang.python import ApplicationPython
from unit.applications.proto import ApplicationProto
from unit.option import option

client = ApplicationProto()
client_python = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    path = Path(f'{temp_dir}/index.html')
    path.write_text('0123456789', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
            },
            "routes": [
                {
                    "action": {
                        "share": str(path),
                        "response_headers": {
                            "X-Foo": "foo",
                        },
                    }
                }
            ],
        }
    )


def action_update(conf):
    assert 'success' in client.conf(conf, 'routes/0/action')


def test_response_headers(temp_dir):
    resp = client.get()
    assert resp['status'] == 200, 'status 200'
    assert resp['headers']['X-Foo'] == 'foo', 'header 200'

    assert 'success' in client.conf(f'"{temp_dir}"', 'routes/0/action/share')

    resp = client.get()
    assert resp['status'] == 301, 'status 301'
    assert resp['headers']['X-Foo'] == 'foo', 'header 301'

    assert 'success' in client.conf('"/blah"', 'routes/0/action/share')

    resp = client.get()
    assert resp['status'] == 404, 'status 404'
    assert 'X-Foo' not in client.get()['headers'], 'header 404'


def test_response_last_action():
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes/first"},
            },
            "routes": {
                "first": [
                    {
                        "action": {
                            "pass": "routes/second",
                            "response_headers": {
                                "X-Foo": "foo",
                            },
                        }
                    }
                ],
                "second": [
                    {
                        "action": {"return": 200},
                    }
                ],
            },
            "applications": {},
        }
    )

    assert 'X-Foo' not in client.get()['headers']


def test_response_pass(require):
    require({'modules': {'python': 'any'}})

    assert 'success' in client_python.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
            },
            "routes": [
                {
                    "action": {
                        "pass": "applications/empty",
                        "response_headers": {
                            "X-Foo": "foo",
                        },
                    }
                },
            ],
            "applications": {
                "empty": {
                    "type": client_python.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{option.test_dir}/python/empty',
                    "working_directory": f'{option.test_dir}/python/empty',
                    "module": "wsgi",
                }
            },
        }
    )

    assert client.get()['headers']['X-Foo'] == 'foo'


def test_response_fallback():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "action": {
                        "share": "/blah",
                        "fallback": {
                            "return": 200,
                            "response_headers": {
                                "X-Foo": "foo",
                            },
                        },
                    }
                }
            ],
        }
    )

    assert client.get()['headers']['X-Foo'] == 'foo'


def test_response_headers_var():
    assert 'success' in client.conf(
        {
            "X-Foo": "$uri",
        },
        'routes/0/action/response_headers',
    )

    assert client.get()['headers']['X-Foo'] == '/'


def test_response_headers_remove():
    assert 'success' in client.conf(
        {"etag": None},
        'routes/0/action/response_headers',
    )

    assert 'ETag' not in client.get()['headers']


def test_response_headers_invalid(skip_alert):
    def check_invalid(conf):
        resp = client.conf(conf, 'routes/0/action/response_headers')
        assert 'error' in resp

        return resp

    resp = check_invalid({"X-Foo": "$u"})
    assert 'detail' in resp and 'Unknown variable' in resp['detail']
