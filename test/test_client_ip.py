import pytest

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    client.load('client_ip')


def client_ip(options):
    assert 'success' in client.conf(
        {
            "127.0.0.1:8081": {
                "client_ip": options,
                "pass": "applications/client_ip",
            },
            "[::1]:8082": {
                "client_ip": options,
                "pass": "applications/client_ip",
            },
            f"unix:{option.temp_dir}/sock": {
                "client_ip": options,
                "pass": "applications/client_ip",
            },
        },
        'listeners',
    ), 'listeners configure'


def get_xff(xff, sock_type='ipv4'):
    address = {
        'ipv4': ('127.0.0.1', 8081),
        'ipv6': ('::1', 8082),
        'unix': (f'{option.temp_dir}/sock', None),
    }
    (addr, port) = address[sock_type]

    return client.get(
        sock_type=sock_type,
        addr=addr,
        port=port,
        headers={'Connection': 'close', 'X-Forwarded-For': xff},
    )['body']


def test_client_ip_single_ip():
    client_ip({'header': 'X-Forwarded-For', 'source': '123.123.123.123'})

    assert client.get(port=8081)['body'] == '127.0.0.1', 'ipv4 default'
    assert (
        client.get(sock_type='ipv6', port=8082)['body'] == '::1'
    ), 'ipv6 default'
    assert get_xff('1.1.1.1') == '127.0.0.1', 'bad source'
    assert get_xff('blah') == '127.0.0.1', 'bad header'
    assert get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6'

    client_ip({'header': 'X-Forwarded-For', 'source': '127.0.0.1'})

    assert client.get(port=8081)['body'] == '127.0.0.1', 'ipv4 default 2'
    assert (
        client.get(sock_type='ipv6', port=8082)['body'] == '::1'
    ), 'ipv6 default 2'
    assert get_xff('1.1.1.1') == '1.1.1.1', 'replace'
    assert get_xff('blah') == '127.0.0.1', 'bad header 2'
    assert get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6 2'

    client_ip({'header': 'X-Forwarded-For', 'source': '!127.0.0.1'})

    assert get_xff('1.1.1.1') == '127.0.0.1', 'bad source 3'
    assert get_xff('1.1.1.1', 'ipv6') == '1.1.1.1', 'replace 2'


def test_client_ip_ipv4():
    client_ip({'header': 'X-Forwarded-For', 'source': '127.0.0.1'})

    assert get_xff('8.8.8.8, 84.23.23.11') == '84.23.23.11', 'xff replace'
    assert (
        get_xff('8.8.8.8, 84.23.23.11, 127.0.0.1') == '127.0.0.1'
    ), 'xff replace 2'
    assert (
        get_xff(['8.8.8.8', '127.0.0.1, 10.0.1.1']) == '10.0.1.1'
    ), 'xff replace multi'


def test_client_ip_ipv6():
    client_ip({'header': 'X-Forwarded-For', 'source': '::1'})

    assert get_xff('1.1.1.1') == '127.0.0.1', 'bad source ipv4'

    for ip in [
        'f607:7403:1e4b:6c66:33b2:843f:2517:da27',
        '2001:db8:3c4d:15::1a2f:1a2b',
        '2001::3c4d:15:1a2f:1a2b',
        '::11.22.33.44',
    ]:
        assert get_xff(ip, 'ipv6') == ip, 'replace'


def test_client_ip_unix():
    client_ip({'header': 'X-Forwarded-For', 'source': 'unix'})

    assert get_xff('1.1.1.1') == '127.0.0.1', 'bad source ipv4'
    assert get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6'

    for ip in [
        '1.1.1.1',
        '::11.22.33.44',
    ]:
        assert get_xff(ip, 'unix') == ip, 'replace'


def test_client_ip_recursive():
    client_ip(
        {
            'header': 'X-Forwarded-For',
            'recursive': True,
            'source': ['127.0.0.1', '10.50.0.17', '10.5.2.1'],
        }
    )

    assert get_xff('1.1.1.1') == '1.1.1.1', 'xff chain'
    assert get_xff('1.1.1.1, 10.5.2.1') == '1.1.1.1', 'xff chain 2'
    assert get_xff('8.8.8.8, 1.1.1.1, 10.5.2.1') == '1.1.1.1', 'xff chain 3'
    assert (
        get_xff('10.50.0.17, 10.5.2.1, 10.5.2.1') == '10.50.0.17'
    ), 'xff chain 4'
    assert (
        get_xff(['8.8.8.8', '1.1.1.1, 127.0.0.1']) == '1.1.1.1'
    ), 'xff replace multi'
    assert (
        get_xff(['8.8.8.8', '1.1.1.1, 127.0.0.1', '10.5.2.1']) == '1.1.1.1'
    ), 'xff replace multi 2'
    assert (
        get_xff(['10.5.2.1', '10.50.0.17, 1.1.1.1', '10.5.2.1']) == '1.1.1.1'
    ), 'xff replace multi 3'
    assert (
        get_xff('8.8.8.8, 2001:db8:3c4d:15::1a2f:1a2b, 127.0.0.1')
        == '2001:db8:3c4d:15::1a2f:1a2b'
    ), 'xff chain ipv6'


def test_client_ip_case_insensitive():
    client_ip({'header': 'x-forwarded-for', 'source': '127.0.0.1'})

    assert get_xff('1.1.1.1') == '1.1.1.1', 'case insensitive'


def test_client_ip_empty_source():
    client_ip({'header': 'X-Forwarded-For', 'source': []})

    assert get_xff('1.1.1.1') == '127.0.0.1', 'empty source'


def test_client_ip_invalid():
    assert 'error' in client.conf(
        {
            "127.0.0.1:8081": {
                "client_ip": {"source": '127.0.0.1'},
                "pass": "applications/client_ip",
            }
        },
        'listeners',
    ), 'invalid header'

    def check_invalid_source(source):
        assert 'error' in client.conf(
            {
                "127.0.0.1:8081": {
                    "client_ip": {
                        "header": "X-Forwarded-For",
                        "source": source,
                    },
                    "pass": "applications/client_ip",
                }
            },
            'listeners',
        ), 'invalid source'

    check_invalid_source(None)
    check_invalid_source('a')
    check_invalid_source(['a'])
