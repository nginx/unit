from unit.control import Control

prerequisites = {'modules': {'php': 'any'}}

client = Control()

conf_app = {
    "app": {
        "type": "php",
        "processes": {"spare": 0},
        "root": "/app",
        "index": "index.php",
    }
}

conf_basic = {
    "listeners": {"*:8080": {"pass": "applications/app"}},
    "applications": conf_app,
}


def test_php_get_applications():
    assert 'success' in client.conf(conf_app, 'applications')

    conf = client.conf_get()

    assert conf['listeners'] == {}, 'listeners'
    assert conf['applications'] == {
        "app": {
            "type": "php",
            "processes": {"spare": 0},
            "root": "/app",
            "index": "index.php",
        }
    }, 'applications'

    assert client.conf_get('applications') == {
        "app": {
            "type": "php",
            "processes": {"spare": 0},
            "root": "/app",
            "index": "index.php",
        }
    }, 'applications prefix'

    assert client.conf_get('applications/app') == {
        "type": "php",
        "processes": {"spare": 0},
        "root": "/app",
        "index": "index.php",
    }, 'applications prefix 2'

    assert client.conf_get('applications/app/type') == 'php', 'type'
    assert (
        client.conf_get('applications/app/processes/spare') == 0
    ), 'spare processes'


def test_php_get_listeners():
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


def test_php_change_listener():
    assert 'success' in client.conf(conf_basic)
    assert 'success' in client.conf(
        {"*:8081": {"pass": "applications/app"}}, 'listeners'
    )

    assert client.conf_get('listeners') == {
        "*:8081": {"pass": "applications/app"}
    }, 'change listener'


def test_php_add_listener():
    assert 'success' in client.conf(conf_basic)
    assert 'success' in client.conf(
        {"pass": "applications/app"}, 'listeners/*:8082'
    )

    assert client.conf_get('listeners') == {
        "*:8080": {"pass": "applications/app"},
        "*:8082": {"pass": "applications/app"},
    }, 'add listener'


def test_php_change_application():
    assert 'success' in client.conf(conf_basic)

    assert 'success' in client.conf('30', 'applications/app/processes/max')
    assert (
        client.conf_get('applications/app/processes/max') == 30
    ), 'change application max'

    assert 'success' in client.conf('"/www"', 'applications/app/root')
    assert (
        client.conf_get('applications/app/root') == '/www'
    ), 'change application root'


def test_php_delete():
    assert 'success' in client.conf(conf_basic)

    assert 'error' in client.conf_delete('applications/app')
    assert 'success' in client.conf_delete('listeners/*:8080')
    assert 'success' in client.conf_delete('applications/app')
    assert 'error' in client.conf_delete('applications/app')


def test_php_delete_blocks():
    assert 'success' in client.conf(conf_basic)

    assert 'success' in client.conf_delete('listeners')
    assert 'success' in client.conf_delete('applications')

    assert 'success' in client.conf(conf_app, 'applications')
    assert 'success' in client.conf(
        {"*:8081": {"pass": "applications/app"}}, 'listeners'
    ), 'applications restore'
