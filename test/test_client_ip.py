from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestClientIP(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def client_ip(self, options):
        assert 'success' in self.conf(
            {
                "127.0.0.1:7081": {
                    "client_ip": options,
                    "pass": "applications/client_ip",
                },
                "[::1]:7082": {
                    "client_ip": options,
                    "pass": "applications/client_ip",
                },
                "unix:"
                + option.temp_dir
                + "/sock": {
                    "client_ip": options,
                    "pass": "applications/client_ip",
                },
            },
            'listeners',
        ), 'listeners configure'

    def get_xff(self, xff, sock_type='ipv4'):
        address = {
            'ipv4': ('127.0.0.1', 7081),
            'ipv6': ('::1', 7082),
            'unix': (option.temp_dir + '/sock', None),
        }
        (addr, port) = address[sock_type]

        return self.get(
            sock_type=sock_type,
            addr=addr,
            port=port,
            headers={'Connection': 'close', 'X-Forwarded-For': xff},
        )['body']

    def setup_method(self):
        self.load('client_ip')

    def test_client_ip_single_ip(self):
        self.client_ip(
            {'header': 'X-Forwarded-For', 'source': '123.123.123.123'}
        )

        assert self.get(port=7081)['body'] == '127.0.0.1', 'ipv4 default'
        assert (
            self.get(sock_type='ipv6', port=7082)['body'] == '::1'
        ), 'ipv6 default'
        assert self.get_xff('1.1.1.1') == '127.0.0.1', 'bad source'
        assert self.get_xff('blah') == '127.0.0.1', 'bad header'
        assert self.get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6'

        self.client_ip({'header': 'X-Forwarded-For', 'source': '127.0.0.1'})

        assert self.get(port=7081)['body'] == '127.0.0.1', 'ipv4 default 2'
        assert (
            self.get(sock_type='ipv6', port=7082)['body'] == '::1'
        ), 'ipv6 default 2'
        assert self.get_xff('1.1.1.1') == '1.1.1.1', 'replace'
        assert self.get_xff('blah') == '127.0.0.1', 'bad header 2'
        assert self.get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6 2'

        self.client_ip({'header': 'X-Forwarded-For', 'source': '!127.0.0.1'})

        assert self.get_xff('1.1.1.1') == '127.0.0.1', 'bad source 3'
        assert self.get_xff('1.1.1.1', 'ipv6') == '1.1.1.1', 'replace 2'

    def test_client_ip_ipv4(self):
        self.client_ip({'header': 'X-Forwarded-For', 'source': '127.0.0.1'})

        assert (
            self.get_xff('8.8.8.8, 84.23.23.11') == '84.23.23.11'
        ), 'xff replace'
        assert (
            self.get_xff('8.8.8.8, 84.23.23.11, 127.0.0.1') == '127.0.0.1'
        ), 'xff replace 2'
        assert (
            self.get_xff(['8.8.8.8', '127.0.0.1, 10.0.1.1']) == '10.0.1.1'
        ), 'xff replace multi'

    def test_client_ip_ipv6(self):
        self.client_ip({'header': 'X-Forwarded-For', 'source': '::1'})

        assert self.get_xff('1.1.1.1') == '127.0.0.1', 'bad source ipv4'

        for ip in [
            'f607:7403:1e4b:6c66:33b2:843f:2517:da27',
            '2001:db8:3c4d:15::1a2f:1a2b',
            '2001::3c4d:15:1a2f:1a2b',
            '::11.22.33.44',
        ]:
            assert self.get_xff(ip, 'ipv6') == ip, 'replace'

    def test_client_ip_unix(self, temp_dir):
        self.client_ip({'header': 'X-Forwarded-For', 'source': 'unix'})

        assert self.get_xff('1.1.1.1') == '127.0.0.1', 'bad source ipv4'
        assert self.get_xff('1.1.1.1', 'ipv6') == '::1', 'bad source ipv6'

        for ip in [
            '1.1.1.1',
            '::11.22.33.44',
        ]:
            assert self.get_xff(ip, 'unix') == ip, 'replace'

    def test_client_ip_recursive(self):
        self.client_ip(
            {
                'header': 'X-Forwarded-For',
                'recursive': True,
                'source': ['127.0.0.1', '10.50.0.17', '10.5.2.1'],
            }
        )

        assert self.get_xff('1.1.1.1') == '1.1.1.1', 'xff chain'
        assert self.get_xff('1.1.1.1, 10.5.2.1') == '1.1.1.1', 'xff chain 2'
        assert (
            self.get_xff('8.8.8.8, 1.1.1.1, 10.5.2.1') == '1.1.1.1'
        ), 'xff chain 3'
        assert (
            self.get_xff('10.50.0.17, 10.5.2.1, 10.5.2.1') == '10.50.0.17'
        ), 'xff chain 4'
        assert (
            self.get_xff(['8.8.8.8', '1.1.1.1, 127.0.0.1']) == '1.1.1.1'
        ), 'xff replace multi'
        assert (
            self.get_xff(['8.8.8.8', '1.1.1.1, 127.0.0.1', '10.5.2.1'])
            == '1.1.1.1'
        ), 'xff replace multi 2'
        assert (
            self.get_xff(['10.5.2.1', '10.50.0.17, 1.1.1.1', '10.5.2.1'])
            == '1.1.1.1'
        ), 'xff replace multi 3'
        assert (
            self.get_xff('8.8.8.8, 2001:db8:3c4d:15::1a2f:1a2b, 127.0.0.1')
            == '2001:db8:3c4d:15::1a2f:1a2b'
        ), 'xff chain ipv6'

    def test_client_ip_case_insensitive(self):
        self.client_ip({'header': 'x-forwarded-for', 'source': '127.0.0.1'})

        assert self.get_xff('1.1.1.1') == '1.1.1.1', 'case insensitive'

    def test_client_ip_empty_source(self):
        self.client_ip({'header': 'X-Forwarded-For', 'source': []})

        assert self.get_xff('1.1.1.1') == '127.0.0.1', 'empty source'

    def test_client_ip_invalid(self):
        assert 'error' in self.conf(
            {
                "127.0.0.1:7081": {
                    "client_ip": {"source": '127.0.0.1'},
                    "pass": "applications/client_ip",
                }
            },
            'listeners',
        ), 'invalid header'

        def check_invalid_source(source):
            assert 'error' in self.conf(
                {
                    "127.0.0.1:7081": {
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
