import os

from conftest import unit_stop
from packaging import version
from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {
    'modules': {'python': lambda v: version.parse(v) >= version.parse('3.5')}
}

client = ApplicationPython(load_module='asgi')


def assert_cookies(prefix):
    for name in ['startup', 'shutdown']:
        path = f'{option.test_dir}/python/lifespan/empty/{prefix}{name}'
        exists = os.path.isfile(path)
        if exists:
            os.remove(path)

        assert not exists, name

    path = f'{option.test_dir}/python/lifespan/empty/{prefix}version'

    with open(path, 'r') as f:
        version = f.read()

    os.remove(path)

    assert version == '3.0 2.0', 'version'


def setup_cookies(prefix):
    base_dir = f'{option.test_dir}/python/lifespan/empty'

    os.chmod(base_dir, 0o777)

    for name in ['startup', 'shutdown', 'version']:
        path = f'{option.test_dir}/python/lifespan/empty/{prefix}{name}'
        open(path, 'a').close()
        os.chmod(path, 0o777)


def test_asgi_lifespan():
    client.load('lifespan/empty')

    setup_cookies('')

    assert client.get()['status'] == 204

    unit_stop()

    assert_cookies('')


def test_asgi_lifespan_targets():
    path = f'{option.test_dir}/python/lifespan/empty'

    assert 'success' in client.conf(
        {
            "listeners": {"*:7080": {"pass": "routes"}},
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
                    "targets": {
                        "1": {"module": "asgi", "callable": "application"},
                        "2": {
                            "module": "asgi",
                            "callable": "application2",
                        },
                    },
                }
            },
        }
    )

    setup_cookies('')
    setup_cookies('app2_')

    assert client.get(url="/1")['status'] == 204
    assert client.get(url="/2")['status'] == 204

    unit_stop()

    assert_cookies('')
    assert_cookies('app2_')


def test_asgi_lifespan_failed(wait_for_record):
    client.load('lifespan/failed')

    assert client.get()['status'] == 503

    assert (
        wait_for_record(r'\[error\].*Application startup failed') is not None
    ), 'error message'
    assert wait_for_record(r'Exception blah') is not None, 'exception'


def test_asgi_lifespan_error(wait_for_record):
    client.load('lifespan/error')

    client.get()

    assert wait_for_record(r'Exception blah') is not None, 'exception'


def test_asgi_lifespan_error_auto(wait_for_record):
    client.load('lifespan/error_auto')

    client.get()

    assert wait_for_record(r'AssertionError') is not None, 'assertion'
