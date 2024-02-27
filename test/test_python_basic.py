from unit.control import Control

prerequisites = {'modules': {'python': 'any'}}

client = Control()

conf_app = {
    "app": {
        "type": "python",
        "processes": {"spare": 0},
        "path": "/app",
        "module": "wsgi",
    }
}

conf_basic = {
    "listeners": {"*:8080": {"pass": "applications/app"}},
    "applications": conf_app,
}


def test_python_get_empty():
    assert client.conf_get() == {'listeners': {}, 'applications': {}}
    assert client.conf_get('listeners') == {}
    assert client.conf_get('applications') == {}


def test_python_get_applications():
    client.conf(conf_app, 'applications')

    conf = client.conf_get()

    assert conf['listeners'] == {}, 'listeners'
    assert conf['applications'] == {
        "app": {
            "type": "python",
            "processes": {"spare": 0},
            "path": "/app",
            "module": "wsgi",
        }
    }, 'applications'

    assert client.conf_get('applications') == {
        "app": {
            "type": "python",
            "processes": {"spare": 0},
            "path": "/app",
            "module": "wsgi",
        }
    }, 'applications prefix'

    assert client.conf_get('applications/app') == {
        "type": "python",
        "processes": {"spare": 0},
        "path": "/app",
        "module": "wsgi",
    }, 'applications prefix 2'

    assert client.conf_get('applications/app/type') == 'python', 'type'
    assert client.conf_get('applications/app/processes/spare') == 0, 'spare'


def test_python_get_listeners():
    assert 'success' in client.conf(conf_basic)

    assert client.conf_get()['listeners'] == {
        "*:8080": {"pass": "applications/app"}
    }, 'listeners'

    assert client.conf_get('listeners') == {
        "*:8080": {"pass": "applications/app"}
    }, 'listeners prefix'

    assert client.conf_get('listeners/*:8080') == {
        "pass": "applications/app"
    }, 'listeners prefix 2'


def test_python_change_listener():
    assert 'success' in client.conf(conf_basic)
    assert 'success' in client.conf(
        {"*:8081": {"pass": "applications/app"}}, 'listeners'
    )

    assert client.conf_get('listeners') == {
        "*:8081": {"pass": "applications/app"}
    }, 'change listener'


def test_python_add_listener():
    assert 'success' in client.conf(conf_basic)
    assert 'success' in client.conf(
        {"pass": "applications/app"}, 'listeners/*:8082'
    )

    assert client.conf_get('listeners') == {
        "*:8080": {"pass": "applications/app"},
        "*:8082": {"pass": "applications/app"},
    }, 'add listener'


def test_python_change_application():
    assert 'success' in client.conf(conf_basic)

    assert 'success' in client.conf('30', 'applications/app/processes/max')
    assert (
        client.conf_get('applications/app/processes/max') == 30
    ), 'change application max'

    assert 'success' in client.conf('"/www"', 'applications/app/path')
    assert (
        client.conf_get('applications/app/path') == '/www'
    ), 'change application path'


def test_python_delete():
    assert 'success' in client.conf(conf_basic)

    assert 'error' in client.conf_delete('applications/app')
    assert 'success' in client.conf_delete('listeners/*:8080')
    assert 'success' in client.conf_delete('applications/app')
    assert 'error' in client.conf_delete('applications/app')


def test_python_delete_blocks():
    assert 'success' in client.conf(conf_basic)

    assert 'success' in client.conf_delete('listeners')
    assert 'success' in client.conf_delete('applications')

    assert 'success' in client.conf(conf_app, 'applications')
    assert 'success' in client.conf(
        {"*:8081": {"pass": "applications/app"}}, 'listeners'
    ), 'applications restore'
