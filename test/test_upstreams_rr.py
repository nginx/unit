import os
import re

import pytest

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "upstreams/one"},
                "*:8090": {"pass": "upstreams/two"},
                "*:8081": {"pass": "routes/one"},
                "*:8082": {"pass": "routes/two"},
                "*:8083": {"pass": "routes/three"},
            },
            "upstreams": {
                "one": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
                "two": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
            },
            "routes": {
                "one": [{"action": {"return": 200}}],
                "two": [{"action": {"return": 201}}],
                "three": [{"action": {"return": 202}}],
            },
            "applications": {},
        },
    ), 'upstreams initial configuration'

    client.cpu_count = os.cpu_count()


def get_resps(req=100, port=8080):
    resps = [0]

    for _ in range(req):
        status = client.get(port=port)['status']
        if 200 > status or status > 209:
            continue

        ups = status % 10
        if ups > len(resps) - 1:
            resps.extend([0] * (ups - len(resps) + 1))

        resps[ups] += 1

    return resps


def get_resps_sc(req=100, port=8080):
    to_send = b"""GET / HTTP/1.1
Host: localhost

""" * (
        req - 1
    )

    to_send += b"""GET / HTTP/1.1
Host: localhost
Connection: close

"""

    resp = client.http(to_send, raw_resp=True, raw=True, port=port)
    status = re.findall(r'HTTP\/\d\.\d\s(\d\d\d)', resp)
    status = list(filter(lambda x: x[:2] == '20', status))
    ups = list(map(lambda x: int(x[-1]), status))

    resps = [0] * (max(ups) + 1)
    for _, up in enumerate(ups):
        resps[up] += 1

    return resps


def test_upstreams_rr_no_weight():
    resps = get_resps()
    assert sum(resps) == 100, 'no weight sum'
    assert abs(resps[0] - resps[1]) <= client.cpu_count, 'no weight'

    assert 'success' in client.conf_delete(
        'upstreams/one/servers/127.0.0.1:8081'
    ), 'no weight server remove'

    resps = get_resps(req=50)
    assert resps[1] == 50, 'no weight 2'

    assert 'success' in client.conf(
        {}, 'upstreams/one/servers/127.0.0.1:8081'
    ), 'no weight server revert'

    resps = get_resps()
    assert sum(resps) == 100, 'no weight 3 sum'
    assert abs(resps[0] - resps[1]) <= client.cpu_count, 'no weight 3'

    assert 'success' in client.conf(
        {}, 'upstreams/one/servers/127.0.0.1:8083'
    ), 'no weight server new'

    resps = get_resps()
    assert sum(resps) == 100, 'no weight 4 sum'
    assert max(resps) - min(resps) <= client.cpu_count, 'no weight 4'

    resps = get_resps_sc(req=30)
    assert resps[0] == 10, 'no weight 4 0'
    assert resps[1] == 10, 'no weight 4 1'
    assert resps[2] == 10, 'no weight 4 2'


def test_upstreams_rr_weight():
    assert 'success' in client.conf(
        {"weight": 3}, 'upstreams/one/servers/127.0.0.1:8081'
    ), 'configure weight'

    resps = get_resps_sc()
    assert resps[0] == 75, 'weight 3 0'
    assert resps[1] == 25, 'weight 3 1'

    assert 'success' in client.conf_delete(
        'upstreams/one/servers/127.0.0.1:8081/weight'
    ), 'configure weight remove'
    resps = get_resps_sc(req=10)
    assert resps[0] == 5, 'weight 0 0'
    assert resps[1] == 5, 'weight 0 1'

    assert 'success' in client.conf(
        '1', 'upstreams/one/servers/127.0.0.1:8081/weight'
    ), 'configure weight 1'

    resps = get_resps_sc()
    assert resps[0] == 50, 'weight 1 0'
    assert resps[1] == 50, 'weight 1 1'

    assert 'success' in client.conf(
        {
            "127.0.0.1:8081": {"weight": 3},
            "127.0.0.1:8083": {"weight": 2},
        },
        'upstreams/one/servers',
    ), 'configure weight 2'

    resps = get_resps_sc()
    assert resps[0] == 60, 'weight 2 0'
    assert resps[2] == 40, 'weight 2 1'


def test_upstreams_rr_weight_rational():
    def set_weights(w1, w2):
        assert 'success' in client.conf(
            {
                "127.0.0.1:8081": {"weight": w1},
                "127.0.0.1:8082": {"weight": w2},
            },
            'upstreams/one/servers',
        ), 'configure weights'

    def check_reqs(w1, w2, reqs=10):
        resps = get_resps_sc(req=reqs)
        assert resps[0] == reqs * w1 / (w1 + w2), 'weight 1'
        assert resps[1] == reqs * w2 / (w1 + w2), 'weight 2'

    def check_weights(w1, w2):
        set_weights(w1, w2)
        check_reqs(w1, w2)

    check_weights(0, 1)
    check_weights(0, 999999.0123456)
    check_weights(1, 9)
    check_weights(100000, 900000)
    check_weights(1, 0.25)
    check_weights(1, 0.25)
    check_weights(0.2, 0.8)
    check_weights(1, 1.5)
    check_weights(1e-3, 1e-3)
    check_weights(1e-20, 1e-20)
    check_weights(1e4, 1e4)
    check_weights(1000000, 1000000)

    set_weights(0.25, 0.25)
    assert 'success' in client.conf_delete(
        'upstreams/one/servers/127.0.0.1:8081/weight'
    ), 'delete weight'
    check_reqs(1, 0.25)

    assert 'success' in client.conf(
        {
            "127.0.0.1:8081": {"weight": 0.1},
            "127.0.0.1:8082": {"weight": 1},
            "127.0.0.1:8083": {"weight": 0.9},
        },
        'upstreams/one/servers',
    ), 'configure weights'
    resps = get_resps_sc(req=20)
    assert resps[0] == 1, 'weight 3 1'
    assert resps[1] == 10, 'weight 3 2'
    assert resps[2] == 9, 'weight 3 3'


def test_upstreams_rr_independent():
    def sum_resps(*args):
        sum_r = [0] * len(args[0])
        for arg in args:
            sum_r = [x + y for x, y in zip(sum_r, arg)]

        return sum_r

    resps = get_resps_sc(req=30, port=8090)
    assert resps[0] == 15, 'dep two before 0'
    assert resps[1] == 15, 'dep two before 1'

    resps = get_resps_sc(req=30)
    assert resps[0] == 15, 'dep one before 0'
    assert resps[1] == 15, 'dep one before 1'

    assert 'success' in client.conf(
        '2', 'upstreams/two/servers/127.0.0.1:8081/weight'
    ), 'configure dep weight'

    resps = get_resps_sc(req=30, port=8090)
    assert resps[0] == 20, 'dep two 0'
    assert resps[1] == 10, 'dep two 1'

    resps = get_resps_sc(req=30)
    assert resps[0] == 15, 'dep one 0'
    assert resps[1] == 15, 'dep one 1'

    assert 'success' in client.conf(
        '1', 'upstreams/two/servers/127.0.0.1:8081/weight'
    ), 'configure dep weight 1'

    r_one, r_two = [0, 0], [0, 0]
    for _ in range(10):
        r_one = sum_resps(r_one, get_resps(req=10))
        r_two = sum_resps(r_two, get_resps(req=10, port=8090))

    assert sum(r_one) == 100, 'dep one mix sum'
    assert abs(r_one[0] - r_one[1]) <= client.cpu_count, 'dep one mix'
    assert sum(r_two) == 100, 'dep two mix sum'
    assert abs(r_two[0] - r_two[1]) <= client.cpu_count, 'dep two mix'


def test_upstreams_rr_delay():
    delayed_dir = f'{option.test_dir}/python/delayed'
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "upstreams/one"},
                "*:8081": {"pass": "routes"},
                "*:8082": {"pass": "routes"},
            },
            "upstreams": {
                "one": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
            },
            "routes": [
                {
                    "match": {"destination": "*:8081"},
                    "action": {"pass": "applications/delayed"},
                },
                {
                    "match": {"destination": "*:8082"},
                    "action": {"return": 201},
                },
            ],
            "applications": {
                "delayed": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": delayed_dir,
                    "working_directory": delayed_dir,
                    "module": "wsgi",
                }
            },
        },
    ), 'upstreams initial configuration'

    req = 50

    socks = []
    for i in range(req):
        delay = 1 if i % 5 == 0 else 0
        sock = client.get(
            headers={
                'Host': 'localhost',
                'Content-Length': '0',
                'X-Delay': str(delay),
                'Connection': 'close',
            },
            no_recv=True,
        )
        socks.append(sock)

    resps = [0, 0]
    for i in range(req):
        resp = client.recvall(socks[i]).decode()
        socks[i].close()

        m = re.search(r'HTTP/1.1 20(\d)', resp)
        assert m is not None, 'status'
        resps[int(m.group(1))] += 1

    assert sum(resps) == req, 'delay sum'
    assert abs(resps[0] - resps[1]) <= client.cpu_count, 'delay'


def test_upstreams_rr_active_req():
    conns = 5
    socks = []
    socks2 = []

    for _ in range(conns):
        sock = client.get(no_recv=True)
        socks.append(sock)

        sock2 = client.http(
            b"""POST / HTTP/1.1
Host: localhost
Content-Length: 10
Connection: close

""",
            no_recv=True,
            raw=True,
        )
        socks2.append(sock2)

    # Send one more request and read response to make sure that previous
    # requests had enough time to reach server.

    assert client.get()['body'] == ''

    assert 'success' in client.conf(
        {"127.0.0.1:8083": {"weight": 2}},
        'upstreams/one/servers',
    ), 'active req new server'
    assert 'success' in client.conf_delete(
        'upstreams/one/servers/127.0.0.1:8083'
    ), 'active req server remove'
    assert 'success' in client.conf_delete(
        'listeners/*:8080'
    ), 'delete listener'
    assert 'success' in client.conf_delete(
        'upstreams/one'
    ), 'active req upstream remove'

    for i in range(conns):
        assert (
            client.http(b'', sock=socks[i], raw=True)['body'] == ''
        ), 'active req GET'

        assert (
            client.http(b"""0123456789""", sock=socks2[i], raw=True)['body']
            == ''
        ), 'active req POST'


def test_upstreams_rr_bad_server():
    assert 'success' in client.conf(
        {"weight": 1}, 'upstreams/one/servers/127.0.0.1:8084'
    ), 'configure bad server'

    resps = get_resps_sc(req=30)
    assert resps[0] == 10, 'bad server 0'
    assert resps[1] == 10, 'bad server 1'
    assert sum(resps) == 20, 'bad server sum'


def test_upstreams_rr_pipeline():
    resps = get_resps_sc()

    assert resps[0] == 50, 'pipeline 0'
    assert resps[1] == 50, 'pipeline 1'


def test_upstreams_rr_post():
    resps = [0, 0]
    for _ in range(50):
        resps[client.get()['status'] % 10] += 1
        resps[client.post(body='0123456789')['status'] % 10] += 1

    assert sum(resps) == 100, 'post sum'
    assert abs(resps[0] - resps[1]) <= client.cpu_count, 'post'


def test_upstreams_rr_unix(temp_dir):
    addr_0 = f'{temp_dir}/sock_0'
    addr_1 = f'{temp_dir}/sock_1'

    assert 'success' in client.conf(
        {
            "*:8080": {"pass": "upstreams/one"},
            f"unix:{addr_0}": {"pass": "routes/one"},
            f"unix:{addr_1}": {"pass": "routes/two"},
        },
        'listeners',
    ), 'configure listeners unix'

    assert 'success' in client.conf(
        {f"unix:{addr_0}": {}, f"unix:{addr_1}": {}},
        'upstreams/one/servers',
    ), 'configure servers unix'

    resps = get_resps_sc()

    assert resps[0] == 50, 'unix 0'
    assert resps[1] == 50, 'unix 1'


def test_upstreams_rr_ipv6():
    assert 'success' in client.conf(
        {
            "*:8080": {"pass": "upstreams/one"},
            "[::1]:8081": {"pass": "routes/one"},
            "[::1]:8082": {"pass": "routes/two"},
        },
        'listeners',
    ), 'configure listeners ipv6'

    assert 'success' in client.conf(
        {"[::1]:8081": {}, "[::1]:8082": {}}, 'upstreams/one/servers'
    ), 'configure servers ipv6'

    resps = get_resps_sc()

    assert resps[0] == 50, 'ipv6 0'
    assert resps[1] == 50, 'ipv6 1'


def test_upstreams_rr_servers_empty():
    assert 'success' in client.conf(
        {}, 'upstreams/one/servers'
    ), 'configure servers empty'
    assert client.get()['status'] == 502, 'servers empty'

    assert 'success' in client.conf(
        {"127.0.0.1:8081": {"weight": 0}}, 'upstreams/one/servers'
    ), 'configure servers empty one'
    assert client.get()['status'] == 502, 'servers empty one'
    assert 'success' in client.conf(
        {
            "127.0.0.1:8081": {"weight": 0},
            "127.0.0.1:8082": {"weight": 0},
        },
        'upstreams/one/servers',
    ), 'configure servers empty two'
    assert client.get()['status'] == 502, 'servers empty two'


def test_upstreams_rr_invalid():
    assert 'error' in client.conf({}, 'upstreams'), 'upstreams empty'
    assert 'error' in client.conf({}, 'upstreams/one'), 'named upstreams empty'
    assert 'error' in client.conf(
        {}, 'upstreams/one/servers/127.0.0.1'
    ), 'invalid address'
    assert 'error' in client.conf(
        {}, 'upstreams/one/servers/127.0.0.1:8081/blah'
    ), 'invalid server option'

    def check_weight(w):
        assert 'error' in client.conf(
            w, 'upstreams/one/servers/127.0.0.1:8081/weight'
        ), 'invalid weight option'

    check_weight({})
    check_weight('-1')
    check_weight('1.')
    check_weight('1.1.')
    check_weight('.')
    check_weight('.01234567890123')
    check_weight('1000001')
    check_weight('2e6')
