import time

import pytest

from unit.applications.proto import ApplicationProto

client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"return": 200}}],
            "applications": {},
        }
    )


def clear_conf():
    assert 'success' in client.conf({"listeners": {}, "applications": {}})


def test_reconfigure():
    sock = client.http(
        b"""GET / HTTP/1.1
""",
        raw=True,
        no_recv=True,
    )

    clear_conf()

    resp = client.http(
        b"""Host: localhost
Connection: close

""",
        sock=sock,
        raw=True,
    )
    assert resp['status'] == 200, 'finish request'


def test_reconfigure_2():
    sock = client.http(b'', raw=True, no_recv=True)

    # Waiting for connection completion.
    # Delay should be more than TCP_DEFER_ACCEPT.
    time.sleep(1.5)

    clear_conf()

    assert client.get(sock=sock)['status'] == 408, 'request timeout'
