import pytest
from packaging import version

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {
    'modules': {'python': lambda v: version.parse(v) >= version.parse('3.5')}
}

client = ApplicationPython(load_module='asgi')


@pytest.fixture(autouse=True)
def setup_method_fixture():
    path = f'{option.test_dir}/python/targets/'

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"uri": "/1"},
                    "action": {"pass": "applications/targets/1"},
                },
                {
                    "match": {"uri": "/2"},
                    "action": {"pass": "applications/targets/2"},
                },
            ],
            "applications": {
                "targets": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "working_directory": path,
                    "path": path,
                    "protocol": "asgi",
                    "targets": {
                        "1": {
                            "module": "asgi",
                            "callable": "application_200",
                        },
                        "2": {
                            "module": "asgi",
                            "callable": "application_201",
                        },
                    },
                }
            },
        }
    )


def conf_targets(targets):
    assert 'success' in client.conf(targets, 'applications/targets/targets')


def test_asgi_targets():
    assert client.get(url='/1')['status'] == 200
    assert client.get(url='/2')['status'] == 201


def test_asgi_targets_legacy():
    conf_targets(
        {
            "1": {"module": "asgi", "callable": "legacy_application_200"},
            "2": {"module": "asgi", "callable": "legacy_application_201"},
        }
    )

    assert client.get(url='/1')['status'] == 200
    assert client.get(url='/2')['status'] == 201


def test_asgi_targets_mix():
    conf_targets(
        {
            "1": {"module": "asgi", "callable": "application_200"},
            "2": {"module": "asgi", "callable": "legacy_application_201"},
        }
    )

    assert client.get(url='/1')['status'] == 200
    assert client.get(url='/2')['status'] == 201


def test_asgi_targets_broken(skip_alert):
    skip_alert(r'Python failed to get "blah" from module')

    conf_targets(
        {
            "1": {"module": "asgi", "callable": "application_200"},
            "2": {"module": "asgi", "callable": "blah"},
        }
    )

    assert client.get(url='/1')['status'] != 200


def test_asgi_targets_prefix():
    conf_targets(
        {
            "1": {
                "module": "asgi",
                "callable": "application_prefix",
                "prefix": "/1/",
            },
            "2": {
                "module": "asgi",
                "callable": "application_prefix",
                "prefix": "/api",
            },
        }
    )
    client.conf(
        [
            {
                "match": {"uri": "/1*"},
                "action": {"pass": "applications/targets/1"},
            },
            {
                "match": {"uri": "*"},
                "action": {"pass": "applications/targets/2"},
            },
        ],
        "routes",
    )

    def check_prefix(url, prefix):
        resp = client.get(url=url)
        assert resp['status'] == 200
        assert resp['headers']['prefix'] == prefix

    check_prefix('/1', '/1')
    check_prefix('/11', 'NULL')
    check_prefix('/1/', '/1')
    check_prefix('/', 'NULL')
    check_prefix('/ap', 'NULL')
    check_prefix('/api', '/api')
    check_prefix('/api/', '/api')
    check_prefix('/api/test/', '/api')
    check_prefix('/apis', 'NULL')
    check_prefix('/apis/', 'NULL')
