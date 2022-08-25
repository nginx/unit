from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestUnixAbstract(TestApplicationPython):
    prerequisites = {
        'modules': {'python': 'any'},
        'features': ['unix_abstract'],
    }

    def test_unix_abstract_source(self):
        addr = '\0sock'

        def source(source):
            assert 'success' in self.conf(
                '"' + source + '"', 'routes/0/match/source'
            )

        assert 'success' in self.conf(
            {
                "listeners": {
                    "127.0.0.1:7080": {"pass": "routes"},
                    "unix:@" + addr[1:]: {"pass": "routes"},
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

        assert (
            self.get(sock_type='unix', addr=addr)['status'] == 200
        ), 'neg ipv4'

        source("!::/0")
        assert (
            self.get(sock_type='unix', addr=addr)['status'] == 200
        ), 'neg ipv6'

        source("unix")
        assert self.get()['status'] == 404, 'ipv4'
        assert self.get(sock_type='unix', addr=addr)['status'] == 200, 'unix'

    def test_unix_abstract_client_ip(self):
        def get_xff(xff, sock_type='ipv4'):
            address = {
                'ipv4': ('127.0.0.1', 7080),
                'ipv6': ('::1', 7081),
                'unix': ('\0sock', None),
            }
            (addr, port) = address[sock_type]

            return self.get(
                sock_type=sock_type,
                addr=addr,
                port=port,
                headers={'Connection': 'close', 'X-Forwarded-For': xff},
            )['body']

        assert 'success' in self.conf(
            {
                "listeners": {
                    "127.0.0.1:7080": {
                        "client_ip": {
                            "header": "X-Forwarded-For",
                            "source": "unix",
                        },
                        "pass": "applications/client_ip",
                    },
                    "[::1]:7081": {
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
                        "type": self.get_application_type(),
                        "processes": {"spare": 0},
                        "path": option.test_dir + "/python/client_ip",
                        "working_directory": option.test_dir
                        + "/python/client_ip",
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
