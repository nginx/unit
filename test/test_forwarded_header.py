import pytest

from unit.applications.lang.python import ApplicationPython

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    client.load('forwarded_header')


def forwarded_header(forwarded):
    assert 'success' in client.conf(
        {
            "127.0.0.1:8081": {
                "forwarded": forwarded,
                "pass": "applications/forwarded_header",
            },
            "[::1]:8082": {
                "forwarded": forwarded,
                "pass": "applications/forwarded_header",
            },
        },
        'listeners',
    ), 'listeners configure'


def get_fwd(sock_type='ipv4', xff=None, xfp=None):
    port = 8081 if sock_type == 'ipv4' else 8082

    headers = {'Connection': 'close'}

    if xff is not None:
        headers['X-Forwarded-For'] = xff

    if xfp is not None:
        headers['X-Forwarded-Proto'] = xfp

    return client.get(sock_type=sock_type, port=port, headers=headers)[
        'headers'
    ]


def get_addr(*args, **kwargs):
    return get_fwd(*args, **kwargs)['Remote-Addr']


def get_scheme(*args, **kwargs):
    return get_fwd(*args, **kwargs)['Url-Scheme']


def test_forwarded_header_single_ip():
    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': '123.123.123.123',
        }
    )

    resp = get_fwd(xff='1.1.1.1', xfp='https')
    assert resp['Remote-Addr'] == '127.0.0.1', 'both headers addr'
    assert resp['Url-Scheme'] == 'http', 'both headers proto'

    assert get_addr() == '127.0.0.1', 'ipv4 default addr'
    assert get_addr('ipv6') == '::1', 'ipv6 default addr'
    assert get_addr(xff='1.1.1.1') == '127.0.0.1', 'bad source'
    assert get_addr(xff='blah') == '127.0.0.1', 'bad xff'
    assert get_addr('ipv6', '1.1.1.1') == '::1', 'bad source ipv6'

    assert get_scheme() == 'http', 'ipv4 default proto'
    assert get_scheme('ipv6') == 'http', 'ipv6 default proto'
    assert get_scheme(xfp='https') == 'http', 'bad proto'
    assert get_scheme(xfp='blah') == 'http', 'bad xfp'
    assert get_scheme('ipv6', xfp='https') == 'http', 'bad proto ipv6'

    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': '127.0.0.1',
        }
    )

    resp = get_fwd(xff='1.1.1.1', xfp='https')
    assert resp['Remote-Addr'] == '1.1.1.1', 'both headers addr 2'
    assert resp['Url-Scheme'] == 'https', 'both headers proto 2'

    assert get_addr() == '127.0.0.1', 'ipv4 default addr 2'
    assert get_addr('ipv6') == '::1', 'ipv6 default addr 2'
    assert get_addr(xff='1.1.1.1') == '1.1.1.1', 'xff replace'
    assert get_addr('ipv6', '1.1.1.1') == '::1', 'bad source ipv6 2'

    assert get_scheme() == 'http', 'ipv4 default proto 2'
    assert get_scheme('ipv6') == 'http', 'ipv6 default proto 2'
    assert get_scheme(xfp='https') == 'https', 'xfp replace'
    assert get_scheme(xfp='on') == 'https', 'xfp replace 2'
    assert get_scheme('ipv6', xfp='https') == 'http', 'bad proto ipv6 2'

    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': '!127.0.0.1',
        }
    )

    assert get_addr(xff='1.1.1.1') == '127.0.0.1', 'bad source 3'
    assert get_addr('ipv6', '1.1.1.1') == '1.1.1.1', 'xff replace 2'
    assert get_scheme(xfp='https') == 'http', 'bad proto 2'
    assert get_scheme('ipv6', xfp='https') == 'https', 'xfp replace 3'


def test_forwarded_header_ipv4():
    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': '127.0.0.1',
        }
    )

    assert get_addr(xff='8.8.8.8, 84.23.23.11') == '84.23.23.11', 'xff replace'
    assert (
        get_addr(xff='8.8.8.8, 84.23.23.11, 127.0.0.1') == '127.0.0.1'
    ), 'xff replace 2'
    assert (
        get_addr(xff=['8.8.8.8', '127.0.0.1, 10.0.1.1']) == '10.0.1.1'
    ), 'xff replace multi'

    assert get_scheme(xfp='http, https') == 'http', 'xfp replace'
    assert get_scheme(xfp='http, https, http') == 'http', 'xfp replace 2'
    assert (
        get_scheme(xfp=['http, https', 'http', 'https']) == 'http'
    ), 'xfp replace multi'


def test_forwarded_header_ipv6():
    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': '::1',
        }
    )

    assert get_addr(xff='1.1.1.1') == '127.0.0.1', 'bad source ipv4'

    for ip in [
        'f607:7403:1e4b:6c66:33b2:843f:2517:da27',
        '2001:db8:3c4d:15::1a2f:1a2b',
        '2001::3c4d:15:1a2f:1a2b',
        '::11.22.33.44',
    ]:
        assert get_addr('ipv6', ip) == ip, 'replace'

    assert get_scheme(xfp='https') == 'http', 'bad source ipv4'

    for proto in ['http', 'https']:
        assert get_scheme('ipv6', xfp=proto) == proto, 'replace'


def test_forwarded_header_recursive():
    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'recursive': True,
            'source': ['127.0.0.1', '10.50.0.17', '10.5.2.1'],
        }
    )

    assert get_addr(xff='1.1.1.1') == '1.1.1.1', 'xff chain'
    assert get_addr(xff='1.1.1.1, 10.5.2.1') == '1.1.1.1', 'xff chain 2'
    assert (
        get_addr(xff='8.8.8.8, 1.1.1.1, 10.5.2.1') == '1.1.1.1'
    ), 'xff chain 3'
    assert (
        get_addr(xff='10.50.0.17, 10.5.2.1, 10.5.2.1') == '10.50.0.17'
    ), 'xff chain 4'
    assert (
        get_addr(xff=['8.8.8.8', '1.1.1.1, 127.0.0.1']) == '1.1.1.1'
    ), 'xff replace multi'
    assert (
        get_addr(xff=['8.8.8.8', '1.1.1.1, 127.0.0.1', '10.5.2.1']) == '1.1.1.1'
    ), 'xff replace multi 2'
    assert (
        get_addr(xff=['10.5.2.1', '10.50.0.17, 1.1.1.1', '10.5.2.1'])
        == '1.1.1.1'
    ), 'xff replace multi 3'
    assert (
        get_addr(xff='8.8.8.8, 2001:db8:3c4d:15::1a2f:1a2b, 127.0.0.1')
        == '2001:db8:3c4d:15::1a2f:1a2b'
    ), 'xff chain ipv6'


def test_forwarded_header_case_insensitive():
    forwarded_header(
        {
            'client_ip': 'x-forwarded-for',
            'protocol': 'x-forwarded-proto',
            'source': '127.0.0.1',
        }
    )

    assert get_addr() == '127.0.0.1', 'ipv4 default addr'
    assert get_addr('ipv6') == '::1', 'ipv6 default addr'
    assert get_addr(xff='1.1.1.1') == '1.1.1.1', 'replace'

    assert get_scheme() == 'http', 'ipv4 default proto'
    assert get_scheme('ipv6') == 'http', 'ipv6 default proto'
    assert get_scheme(xfp='https') == 'https', 'replace 1'
    assert get_scheme(xfp='oN') == 'https', 'replace 2'


def test_forwarded_header_source_empty():
    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': [],
        }
    )

    assert get_addr(xff='1.1.1.1') == '127.0.0.1', 'empty source xff'
    assert get_scheme(xfp='https') == 'http', 'empty source xfp'


def test_forwarded_header_source_range():
    forwarded_header(
        {
            'client_ip': 'X-Forwarded-For',
            'protocol': 'X-Forwarded-Proto',
            'source': '127.0.0.0-127.0.0.1',
        }
    )

    assert get_addr(xff='1.1.1.1') == '1.1.1.1', 'source range'
    assert get_addr('ipv6', '1.1.1.1') == '::1', 'source range 2'


def test_forwarded_header_invalid():
    assert 'error' in client.conf(
        {
            "127.0.0.1:8081": {
                "forwarded": {"source": '127.0.0.1'},
                "pass": "applications/forwarded_header",
            }
        },
        'listeners',
    ), 'invalid forward'

    def check_invalid_source(source):
        assert 'error' in client.conf(
            {
                "127.0.0.1:8081": {
                    "forwarded": {
                        "client_ip": "X-Forwarded-For",
                        "source": source,
                    },
                    "pass": "applications/forwarded_header",
                }
            },
            'listeners',
        ), 'invalid source'

    check_invalid_source(None)
    check_invalid_source('a')
    check_invalid_source(['a'])
