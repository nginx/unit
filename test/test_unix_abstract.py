from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {
    'modules': {'python': 'any'},
    'features': {'unix_abstract': True},
}

client = ApplicationPython()


def test_unix_abstract_source():
    addr = '\0sock'

    def source(source):
        assert 'success' in client.conf(f'"{source}"', 'routes/0/match/source')

    assert 'success' in client.conf(
        {
            "listeners": {
                "127.0.0.1:8080": {"pass": "routes"},
                f"unix:@{addr[1:]}": {"pass": "routes"},
            },
            "routes": [
                {
                    "match": {"source": "!0.0.0.0/0"},
                    "action": {"return": 200},
                }
            ],
            "applications": {},
        }
    )

    assert client.get(sock_type='unix', addr=addr)['status'] == 200, 'neg ipv4'

    source("!::/0")
    assert client.get(sock_type='unix', addr=addr)['status'] == 200, 'neg ipv6'

    source("unix")
    assert client.get()['status'] == 404, 'ipv4'
    assert client.get(sock_type='unix', addr=addr)['status'] == 200, 'unix'


def test_unix_abstract_client_ip():
    def get_xff(xff, sock_type='ipv4'):
        address = {
            'ipv4': ('127.0.0.1', 8080),
            'ipv6': ('::1', 8081),
            'unix': ('\0sock', None),
        }
        (addr, port) = address[sock_type]

        return client.get(
            sock_type=sock_type,
            addr=addr,
            port=port,
            headers={'Connection': 'close', 'X-Forwarded-For': xff},
        )['body']

    client_ip_dir = f"{option.test_dir}/python/client_ip"
    assert 'success' in client.conf(
        {
            "listeners": {
                "127.0.0.1:8080": {
                    "client_ip": {
                        "header": "X-Forwarded-For",
                        "source": "unix",
                    },
                    "pass": "applications/client_ip",
                },
                "[::1]:8081": {
                    "client_ip": {
                        "header": "X-Forwarded-For",
                        "source": "unix",
                    },
                    "pass": "applications/client_ip",
                },
                "unix:@sock": {
                    "client_ip": {
                        "header": "X-Forwarded-For",
                        "source": "unix",
                    },
                    "pass": "applications/client_ip",
                },
            },
            "applications": {
                "client_ip": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": client_ip_dir,
                    "working_directory": client_ip_dir,
                    "module": "wsgi",
                }
            },
        }
    )

    assert get_xff('1.1.1.1') == '127.0.0.1', 'bad source ipv4'
    assert get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6'

    for ip in [
        '1.1.1.1',
        '::11.22.33.44',
    ]:
        assert get_xff(ip, 'unix') == ip, 'replace'
