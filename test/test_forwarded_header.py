from unit.applications.lang.python import TestApplicationPython


class TestForwardedHeader(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def forwarded_header(self, forwarded):
        assert 'success' in self.conf(
            {
                "127.0.0.1:7081": {
                    "forwarded": forwarded,
                    "pass": "applications/forwarded_header",
                },
                "[::1]:7082": {
                    "forwarded": forwarded,
                    "pass": "applications/forwarded_header",
                },
            },
            'listeners',
        ), 'listeners configure'

    def get_fwd(self, sock_type='ipv4', xff=None, xfp=None):
        port = 7081 if sock_type == 'ipv4' else 7082

        headers = {'Connection': 'close'}

        if xff is not None:
            headers['X-Forwarded-For'] = xff

        if xfp is not None:
            headers['X-Forwarded-Proto'] = xfp

        return self.get(sock_type=sock_type, port=port, headers=headers)[
            'headers'
        ]

    def get_addr(self, *args, **kwargs):
        return self.get_fwd(*args, **kwargs)['Remote-Addr']

    def get_scheme(self, *args, **kwargs):
        return self.get_fwd(*args, **kwargs)['Url-Scheme']

    def setup_method(self):
        self.load('forwarded_header')

    def test_forwarded_header_single_ip(self):
        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': '123.123.123.123',
            }
        )

        resp = self.get_fwd(xff='1.1.1.1', xfp='https')
        assert resp['Remote-Addr'] == '127.0.0.1', 'both headers addr'
        assert resp['Url-Scheme'] == 'http', 'both headers proto'

        assert self.get_addr() == '127.0.0.1', 'ipv4 default addr'
        assert self.get_addr('ipv6') == '::1', 'ipv6 default addr'
        assert self.get_addr(xff='1.1.1.1') == '127.0.0.1', 'bad source'
        assert self.get_addr(xff='blah') == '127.0.0.1', 'bad xff'
        assert self.get_addr('ipv6', '1.1.1.1') == '::1', 'bad source ipv6'

        assert self.get_scheme() == 'http', 'ipv4 default proto'
        assert self.get_scheme('ipv6') == 'http', 'ipv6 default proto'
        assert self.get_scheme(xfp='https') == 'http', 'bad proto'
        assert self.get_scheme(xfp='blah') == 'http', 'bad xfp'
        assert self.get_scheme('ipv6', xfp='https') == 'http', 'bad proto ipv6'

        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': '127.0.0.1',
            }
        )

        resp = self.get_fwd(xff='1.1.1.1', xfp='https')
        assert resp['Remote-Addr'] == '1.1.1.1', 'both headers addr 2'
        assert resp['Url-Scheme'] == 'https', 'both headers proto 2'

        assert self.get_addr() == '127.0.0.1', 'ipv4 default addr 2'
        assert self.get_addr('ipv6') == '::1', 'ipv6 default addr 2'
        assert self.get_addr(xff='1.1.1.1') == '1.1.1.1', 'xff replace'
        assert self.get_addr('ipv6', '1.1.1.1') == '::1', 'bad source ipv6 2'

        assert self.get_scheme() == 'http', 'ipv4 default proto 2'
        assert self.get_scheme('ipv6') == 'http', 'ipv6 default proto 2'
        assert self.get_scheme(xfp='https') == 'https', 'xfp replace'
        assert self.get_scheme(xfp='on') == 'https', 'xfp replace 2'
        assert (
            self.get_scheme('ipv6', xfp='https') == 'http'
        ), 'bad proto ipv6 2'

        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': '!127.0.0.1',
            }
        )

        assert self.get_addr(xff='1.1.1.1') == '127.0.0.1', 'bad source 3'
        assert self.get_addr('ipv6', '1.1.1.1') == '1.1.1.1', 'xff replace 2'
        assert self.get_scheme(xfp='https') == 'http', 'bad proto 2'
        assert self.get_scheme('ipv6', xfp='https') == 'https', 'xfp replace 3'

    def test_forwarded_header_ipv4(self):
        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': '127.0.0.1',
            }
        )

        assert (
            self.get_addr(xff='8.8.8.8, 84.23.23.11') == '84.23.23.11'
        ), 'xff replace'
        assert (
            self.get_addr(xff='8.8.8.8, 84.23.23.11, 127.0.0.1') == '127.0.0.1'
        ), 'xff replace 2'
        assert (
            self.get_addr(xff=['8.8.8.8', '127.0.0.1, 10.0.1.1']) == '10.0.1.1'
        ), 'xff replace multi'

        assert self.get_scheme(xfp='http, https') == 'http', 'xfp replace'
        assert (
            self.get_scheme(xfp='http, https, http') == 'http'
        ), 'xfp replace 2'
        assert (
            self.get_scheme(xfp=['http, https', 'http', 'https']) == 'http'
        ), 'xfp replace multi'

    def test_forwarded_header_ipv6(self):
        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': '::1',
            }
        )

        assert self.get_addr(xff='1.1.1.1') == '127.0.0.1', 'bad source ipv4'

        for ip in [
            'f607:7403:1e4b:6c66:33b2:843f:2517:da27',
            '2001:db8:3c4d:15::1a2f:1a2b',
            '2001::3c4d:15:1a2f:1a2b',
            '::11.22.33.44',
        ]:
            assert self.get_addr('ipv6', ip) == ip, 'replace'

        assert self.get_scheme(xfp='https') == 'http', 'bad source ipv4'

        for proto in ['http', 'https']:
            assert self.get_scheme('ipv6', xfp=proto) == proto, 'replace'

    def test_forwarded_header_recursive(self):
        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'recursive': True,
                'source': ['127.0.0.1', '10.50.0.17', '10.5.2.1'],
            }
        )

        assert self.get_addr(xff='1.1.1.1') == '1.1.1.1', 'xff chain'
        assert (
            self.get_addr(xff='1.1.1.1, 10.5.2.1') == '1.1.1.1'
        ), 'xff chain 2'
        assert (
            self.get_addr(xff='8.8.8.8, 1.1.1.1, 10.5.2.1') == '1.1.1.1'
        ), 'xff chain 3'
        assert (
            self.get_addr(xff='10.50.0.17, 10.5.2.1, 10.5.2.1') == '10.50.0.17'
        ), 'xff chain 4'
        assert (
            self.get_addr(xff=['8.8.8.8', '1.1.1.1, 127.0.0.1']) == '1.1.1.1'
        ), 'xff replace multi'
        assert (
            self.get_addr(xff=['8.8.8.8', '1.1.1.1, 127.0.0.1', '10.5.2.1'])
            == '1.1.1.1'
        ), 'xff replace multi 2'
        assert (
            self.get_addr(xff=['10.5.2.1', '10.50.0.17, 1.1.1.1', '10.5.2.1'])
            == '1.1.1.1'
        ), 'xff replace multi 3'
        assert (
            self.get_addr(
                xff='8.8.8.8, 2001:db8:3c4d:15::1a2f:1a2b, 127.0.0.1'
            )
            == '2001:db8:3c4d:15::1a2f:1a2b'
        ), 'xff chain ipv6'

    def test_forwarded_header_case_insensitive(self):
        self.forwarded_header(
            {
                'client_ip': 'x-forwarded-for',
                'protocol': 'x-forwarded-proto',
                'source': '127.0.0.1',
            }
        )

        assert self.get_addr() == '127.0.0.1', 'ipv4 default addr'
        assert self.get_addr('ipv6') == '::1', 'ipv6 default addr'
        assert self.get_addr(xff='1.1.1.1') == '1.1.1.1', 'replace'

        assert self.get_scheme() == 'http', 'ipv4 default proto'
        assert self.get_scheme('ipv6') == 'http', 'ipv6 default proto'
        assert self.get_scheme(xfp='https') == 'https', 'replace 1'
        assert self.get_scheme(xfp='oN') == 'https', 'replace 2'

    def test_forwarded_header_source_empty(self):
        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': [],
            }
        )

        assert self.get_addr(xff='1.1.1.1') == '127.0.0.1', 'empty source xff'
        assert self.get_scheme(xfp='https') == 'http', 'empty source xfp'

    def test_forwarded_header_source_range(self):
        self.forwarded_header(
            {
                'client_ip': 'X-Forwarded-For',
                'protocol': 'X-Forwarded-Proto',
                'source': '127.0.0.0-127.0.0.1',
            }
        )

        assert self.get_addr(xff='1.1.1.1') == '1.1.1.1', 'source range'
        assert self.get_addr('ipv6', '1.1.1.1') == '::1', 'source range 2'

    def test_forwarded_header_invalid(self):
        assert 'error' in self.conf(
            {
                "127.0.0.1:7081": {
                    "forwarded": {"source": '127.0.0.1'},
                    "pass": "applications/forwarded_header",
                }
            },
            'listeners',
        ), 'invalid forward'

        def check_invalid_source(source):
            assert 'error' in self.conf(
                {
                    "127.0.0.1:7081": {
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
