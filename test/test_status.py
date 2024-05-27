import time

from unit.applications.lang.python import ApplicationPython
from unit.option import option
from unit.status import Status

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


def check_connections(accepted, active, idle, closed):
    assert Status.get('/connections') == {
        'accepted': accepted,
        'active': active,
        'idle': idle,
        'closed': closed,
    }


def app_default(name="empty", module="wsgi"):
    name_dir = f'{option.test_dir}/python/{name}'
    return {
        "type": client.get_application_type(),
        "processes": {"spare": 0},
        "path": name_dir,
        "working_directory": name_dir,
        "module": module,
    }


def test_status():
    assert 'error' in client.conf_delete('/status'), 'DELETE method'


def test_status_requests(skip_alert):
    skip_alert(r'Python failed to import module "blah"')

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "applications/empty"},
                "*:8082": {"pass": "applications/blah"},
            },
            "routes": [{"action": {"return": 200}}],
            "applications": {
                "empty": app_default(),
                "blah": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "module": "blah",
                },
            },
        },
    )

    Status.init()

    assert client.get()['status'] == 200
    assert Status.get('/requests/total') == 1, '2xx'

    assert client.get(port=8081)['status'] == 200
    assert Status.get('/requests/total') == 2, '2xx app'

    assert (
        client.get(headers={'Host': '/', 'Connection': 'close'})['status']
        == 400
    )
    assert Status.get('/requests/total') == 3, '4xx'

    assert client.get(port=8082)['status'] == 503
    assert Status.get('/requests/total') == 4, '5xx'

    client.http(
        b"""GET / HTTP/1.1
Host: localhost

GET / HTTP/1.1
Host: localhost
Connection: close

""",
        raw=True,
    )
    assert Status.get('/requests/total') == 6, 'pipeline'

    sock = client.get(port=8081, no_recv=True)

    time.sleep(1)

    assert Status.get('/requests/total') == 7, 'no receive'

    sock.close()


def test_status_connections():
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "applications/delayed"},
            },
            "routes": [{"action": {"return": 200}}],
            "applications": {
                "delayed": app_default("delayed"),
            },
        },
    )

    Status.init()

    # accepted, closed

    assert client.get()['status'] == 200
    check_connections(1, 0, 0, 1)

    # idle

    (_, sock) = client.get(
        headers={'Host': 'localhost', 'Connection': 'keep-alive'},
        start=True,
        read_timeout=1,
    )

    check_connections(2, 0, 1, 1)

    client.get(sock=sock)
    check_connections(2, 0, 0, 2)

    # active

    (_, sock) = client.get(
        headers={
            'Host': 'localhost',
            'X-Delay': '2',
            'Connection': 'close',
        },
        port=8081,
        start=True,
        read_timeout=1,
    )
    check_connections(3, 1, 0, 2)

    client.get(sock=sock)
    check_connections(3, 0, 0, 3)


def test_status_applications():
    def check_applications(expert):
        apps = list(client.conf_get('/status/applications').keys()).sort()
        assert apps == expert.sort()

    def check_application(name, running, starting, idle, active):
        assert Status.get(f'/applications/{name}') == {
            'processes': {
                'running': running,
                'starting': starting,
                'idle': idle,
            },
            'requests': {'active': active},
        }

    client.load('delayed')
    Status.init()

    check_applications(['delayed'])
    check_application('delayed', 0, 0, 0, 0)

    # idle

    assert client.get()['status'] == 200
    check_application('delayed', 1, 0, 1, 0)

    assert 'success' in client.conf('4', 'applications/delayed/processes')
    check_application('delayed', 4, 0, 4, 0)

    # active

    (_, sock) = client.get(
        headers={
            'Host': 'localhost',
            'X-Delay': '2',
            'Connection': 'close',
        },
        start=True,
        read_timeout=1,
    )
    check_application('delayed', 4, 0, 3, 1)
    sock.close()

    # starting

    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "applications/restart"},
                "*:8081": {"pass": "applications/delayed"},
            },
            "routes": [],
            "applications": {
                "restart": app_default("restart", "longstart"),
                "delayed": app_default("delayed"),
            },
        },
    )
    Status.init()

    check_applications(['delayed', 'restart'])
    check_application('restart', 0, 0, 0, 0)
    check_application('delayed', 0, 0, 0, 0)

    client.get(read_timeout=1)

    check_application('restart', 0, 1, 0, 1)
    check_application('delayed', 0, 0, 0, 0)


def test_status_proxy():
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "applications/empty"},
            },
            "routes": [
                {
                    "match": {"uri": "/"},
                    "action": {"proxy": "http://127.0.0.1:8081"},
                }
            ],
            "applications": {
                "empty": app_default(),
            },
        },
    )

    Status.init()

    assert client.get()['status'] == 200
    check_connections(2, 0, 0, 2)
    assert Status.get('/requests/total') == 2, 'proxy'
