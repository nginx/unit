import pytest

from unit.applications.lang.python import TestApplicationPython


class TestHTTPHeader(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def test_http_header_value_leading_sp(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': ' ,',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value leading sp status'
        assert (
            resp['headers']['Custom-Header'] == ','
        ), 'value leading sp custom header'

    def test_http_header_value_leading_htab(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': '\t,',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value leading htab status'
        assert (
            resp['headers']['Custom-Header'] == ','
        ), 'value leading htab custom header'

    def test_http_header_value_trailing_sp(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': ', ',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value trailing sp status'
        assert (
            resp['headers']['Custom-Header'] == ','
        ), 'value trailing sp custom header'

    def test_http_header_value_trailing_htab(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': ',\t',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value trailing htab status'
        assert (
            resp['headers']['Custom-Header'] == ','
        ), 'value trailing htab custom header'

    def test_http_header_value_both_sp(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': ' , ',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value both sp status'
        assert (
            resp['headers']['Custom-Header'] == ','
        ), 'value both sp custom header'

    def test_http_header_value_both_htab(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': '\t,\t',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value both htab status'
        assert (
            resp['headers']['Custom-Header'] == ','
        ), 'value both htab custom header'

    def test_http_header_value_chars(self):
        self.load('custom_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Custom-Header': r'(),/:;<=>?@[\]{}\t !#$%&\'*+-.^_`|~',
                'Connection': 'close',
            }
        )

        assert resp['status'] == 200, 'value chars status'
        assert (
            resp['headers']['Custom-Header']
            == r'(),/:;<=>?@[\]{}\t !#$%&\'*+-.^_`|~'
        ), 'value chars custom header'

    def test_http_header_value_chars_edge(self):
        self.load('custom_header')

        resp = self.http(
            b"""GET / HTTP/1.1
Host: localhost
Custom-Header: \x20\xFF
Connection: close

""",
            raw=True,
            encoding='latin1',
        )

        assert resp['status'] == 200, 'value chars edge status'
        assert resp['headers']['Custom-Header'] == '\xFF', 'value chars edge'

    def test_http_header_value_chars_below(self):
        self.load('custom_header')

        resp = self.http(
            b"""GET / HTTP/1.1
Host: localhost
Custom-Header: \x1F
Connection: close

""",
            raw=True,
        )

        assert resp['status'] == 400, 'value chars below'

    def test_http_header_field_leading_sp(self):
        self.load('empty')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    ' Custom-Header': 'blah',
                    'Connection': 'close',
                }
            )['status']
            == 400
        ), 'field leading sp'

    def test_http_header_field_leading_htab(self):
        self.load('empty')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    '\tCustom-Header': 'blah',
                    'Connection': 'close',
                }
            )['status']
            == 400
        ), 'field leading htab'

    def test_http_header_field_trailing_sp(self):
        self.load('empty')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Custom-Header ': 'blah',
                    'Connection': 'close',
                }
            )['status']
            == 400
        ), 'field trailing sp'

    def test_http_header_field_trailing_htab(self):
        self.load('empty')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Custom-Header\t': 'blah',
                    'Connection': 'close',
                }
            )['status']
            == 400
        ), 'field trailing htab'

    def test_http_header_content_length_big(self):
        self.load('empty')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Length': str(2 ** 64),
                    'Connection': 'close',
                },
                body='X' * 1000,
            )['status']
            == 400
        ), 'Content-Length big'

    def test_http_header_content_length_negative(self):
        self.load('empty')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Length': '-100',
                    'Connection': 'close',
                },
                body='X' * 1000,
            )['status']
            == 400
        ), 'Content-Length negative'

    def test_http_header_content_length_text(self):
        self.load('empty')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Length': 'blah',
                    'Connection': 'close',
                },
                body='X' * 1000,
            )['status']
            == 400
        ), 'Content-Length text'

    def test_http_header_content_length_multiple_values(self):
        self.load('empty')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Length': '41, 42',
                    'Connection': 'close',
                },
                body='X' * 1000,
            )['status']
            == 400
        ), 'Content-Length multiple value'

    def test_http_header_content_length_multiple_fields(self):
        self.load('empty')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Length': ['41', '42'],
                    'Connection': 'close',
                },
                body='X' * 1000,
            )['status']
            == 400
        ), 'Content-Length multiple fields'

    @pytest.mark.skip('not yet')
    def test_http_header_host_absent(self):
        self.load('host')

        resp = self.get(headers={'Connection': 'close'})

        assert resp['status'] == 400, 'Host absent status'

    def test_http_header_host_empty(self):
        self.load('host')

        resp = self.get(headers={'Host': '', 'Connection': 'close'})

        assert resp['status'] == 200, 'Host empty status'
        assert resp['headers']['X-Server-Name'] != '', 'Host empty SERVER_NAME'

    def test_http_header_host_big(self):
        self.load('empty')

        assert (
            self.get(headers={'Host': 'X' * 10000, 'Connection': 'close'})[
                'status'
            ]
            == 431
        ), 'Host big'

    def test_http_header_host_port(self):
        self.load('host')

        resp = self.get(
            headers={'Host': 'exmaple.com:7080', 'Connection': 'close'}
        )

        assert resp['status'] == 200, 'Host port status'
        assert (
            resp['headers']['X-Server-Name'] == 'exmaple.com'
        ), 'Host port SERVER_NAME'
        assert (
            resp['headers']['X-Http-Host'] == 'exmaple.com:7080'
        ), 'Host port HTTP_HOST'

    def test_http_header_host_port_empty(self):
        self.load('host')

        resp = self.get(
            headers={'Host': 'exmaple.com:', 'Connection': 'close'}
        )

        assert resp['status'] == 200, 'Host port empty status'
        assert (
            resp['headers']['X-Server-Name'] == 'exmaple.com'
        ), 'Host port empty SERVER_NAME'
        assert (
            resp['headers']['X-Http-Host'] == 'exmaple.com:'
        ), 'Host port empty HTTP_HOST'

    def test_http_header_host_literal(self):
        self.load('host')

        resp = self.get(headers={'Host': '127.0.0.1', 'Connection': 'close'})

        assert resp['status'] == 200, 'Host literal status'
        assert (
            resp['headers']['X-Server-Name'] == '127.0.0.1'
        ), 'Host literal SERVER_NAME'

    def test_http_header_host_literal_ipv6(self):
        self.load('host')

        resp = self.get(headers={'Host': '[::1]:7080', 'Connection': 'close'})

        assert resp['status'] == 200, 'Host literal ipv6 status'
        assert (
            resp['headers']['X-Server-Name'] == '[::1]'
        ), 'Host literal ipv6 SERVER_NAME'
        assert (
            resp['headers']['X-Http-Host'] == '[::1]:7080'
        ), 'Host literal ipv6 HTTP_HOST'

    def test_http_header_host_trailing_period(self):
        self.load('host')

        resp = self.get(headers={'Host': '127.0.0.1.', 'Connection': 'close'})

        assert resp['status'] == 200, 'Host trailing period status'
        assert (
            resp['headers']['X-Server-Name'] == '127.0.0.1'
        ), 'Host trailing period SERVER_NAME'
        assert (
            resp['headers']['X-Http-Host'] == '127.0.0.1.'
        ), 'Host trailing period HTTP_HOST'

    def test_http_header_host_trailing_period_2(self):
        self.load('host')

        resp = self.get(
            headers={'Host': 'EXAMPLE.COM.', 'Connection': 'close'}
        )

        assert resp['status'] == 200, 'Host trailing period 2 status'
        assert (
            resp['headers']['X-Server-Name'] == 'example.com'
        ), 'Host trailing period 2 SERVER_NAME'
        assert (
            resp['headers']['X-Http-Host'] == 'EXAMPLE.COM.'
        ), 'Host trailing period 2 HTTP_HOST'

    def test_http_header_host_case_insensitive(self):
        self.load('host')

        resp = self.get(headers={'Host': 'EXAMPLE.COM', 'Connection': 'close'})

        assert resp['status'] == 200, 'Host case insensitive'
        assert (
            resp['headers']['X-Server-Name'] == 'example.com'
        ), 'Host case insensitive SERVER_NAME'

    def test_http_header_host_double_dot(self):
        self.load('empty')

        assert (
            self.get(headers={'Host': '127.0.0..1', 'Connection': 'close'})[
                'status'
            ]
            == 400
        ), 'Host double dot'

    def test_http_header_host_slash(self):
        self.load('empty')

        assert (
            self.get(headers={'Host': '/localhost', 'Connection': 'close'})[
                'status'
            ]
            == 400
        ), 'Host slash'

    def test_http_header_host_multiple_fields(self):
        self.load('empty')

        assert (
            self.get(
                headers={
                    'Host': ['localhost', 'example.com'],
                    'Connection': 'close',
                }
            )['status']
            == 400
        ), 'Host multiple fields'

    def test_http_discard_unsafe_fields(self):
        self.load('header_fields')

        def check_status(header):
            resp = self.get(
                headers={
                    'Host': 'localhost',
                    header: 'blah',
                    'Connection': 'close',
                }
            )

            assert resp['status'] == 200
            return resp

        resp = check_status("!Custom-Header")
        assert 'CUSTOM' not in resp['headers']['All-Headers']

        resp = check_status("Custom_Header")
        assert 'CUSTOM' not in resp['headers']['All-Headers']

        assert 'success' in self.conf(
            {'http': {'discard_unsafe_fields': False}}, 'settings',
        )

        resp = check_status("!#$%&'*+.^`|~Custom_Header")
        assert 'CUSTOM' in resp['headers']['All-Headers']

        assert 'success' in self.conf(
            {'http': {'discard_unsafe_fields': True}}, 'settings',
        )

        resp = check_status("!Custom-Header")
        assert 'CUSTOM' not in resp['headers']['All-Headers']

        resp = check_status("Custom_Header")
        assert 'CUSTOM' not in resp['headers']['All-Headers']
