import time

import pytest
from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestAccessLog(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def load(self, script):
        super().load(script)

        assert 'success' in self.conf(
            f'"{option.temp_dir}/access.log"', 'access_log'
        ), 'access_log configure'

    def set_format(self, format):
        assert 'success' in self.conf(
            {
                'path': f'{option.temp_dir}/access.log',
                'format': format,
            },
            'access_log',
        ), 'access_log format'

    def test_access_log_keepalive(self, wait_for_record):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        (_, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
            },
            start=True,
            body='01234',
            read_timeout=1,
        )

        assert (
            wait_for_record(r'"POST / HTTP/1.1" 200 5', 'access.log')
            is not None
        ), 'keepalive 1'

        _ = self.post(sock=sock, body='0123456789')

        assert (
            wait_for_record(r'"POST / HTTP/1.1" 200 10', 'access.log')
            is not None
        ), 'keepalive 2'

    def test_access_log_pipeline(self, wait_for_record):
        self.load('empty')

        self.http(
            b"""GET / HTTP/1.1
Host: localhost
Referer: Referer-1

GET / HTTP/1.1
Host: localhost
Referer: Referer-2

GET / HTTP/1.1
Host: localhost
Referer: Referer-3
Connection: close

""",
            raw_resp=True,
            raw=True,
        )

        assert (
            wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "Referer-1" "-"', 'access.log'
            )
            is not None
        ), 'pipeline 1'
        assert (
            wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "Referer-2" "-"', 'access.log'
            )
            is not None
        ), 'pipeline 2'
        assert (
            wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "Referer-3" "-"', 'access.log'
            )
            is not None
        ), 'pipeline 3'

    def test_access_log_ipv6(self, wait_for_record):
        self.load('empty')

        assert 'success' in self.conf(
            {"[::1]:7080": {"pass": "applications/empty"}}, 'listeners'
        )

        self.get(sock_type='ipv6')

        assert (
            wait_for_record(
                r'::1 - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"', 'access.log'
            )
            is not None
        ), 'ipv6'

    def test_access_log_unix(self, temp_dir, wait_for_record):
        self.load('empty')

        addr = f'{temp_dir}/sock'

        assert 'success' in self.conf(
            {f'unix:{addr}': {"pass": "applications/empty"}}, 'listeners'
        )

        self.get(sock_type='unix', addr=addr)

        assert (
            wait_for_record(
                r'unix: - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"', 'access.log'
            )
            is not None
        ), 'unix'

    def test_access_log_referer(self, wait_for_record):
        self.load('empty')

        self.get(
            headers={
                'Host': 'localhost',
                'Referer': 'referer-value',
                'Connection': 'close',
            }
        )

        assert (
            wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "referer-value" "-"', 'access.log'
            )
            is not None
        ), 'referer'

    def test_access_log_user_agent(self, wait_for_record):
        self.load('empty')

        self.get(
            headers={
                'Host': 'localhost',
                'User-Agent': 'user-agent-value',
                'Connection': 'close',
            }
        )

        assert (
            wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "-" "user-agent-value"', 'access.log'
            )
            is not None
        ), 'user agent'

    def test_access_log_http10(self, wait_for_record):
        self.load('empty')

        self.get(http_10=True)

        assert (
            wait_for_record(r'"GET / HTTP/1.0" 200 0 "-" "-"', 'access.log')
            is not None
        ), 'http 1.0'

    def test_access_log_partial(self, wait_for_record):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        _ = self.http(b"""GE""", raw=True, read_timeout=1)

        time.sleep(1)

        assert (
            wait_for_record(r'"-" 400 0 "-" "-"', 'access.log') is not None
        ), 'partial'

    def test_access_log_partial_2(self, wait_for_record):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        self.http(b"""GET /\n""", raw=True)

        assert (
            wait_for_record(r'"-" 400 \d+ "-" "-"', 'access.log') is not None
        ), 'partial 2'

    def test_access_log_partial_3(self, wait_for_record):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        _ = self.http(b"""GET / HTTP/1.1""", raw=True, read_timeout=1)

        time.sleep(1)

        assert (
            wait_for_record(r'"-" 400 0 "-" "-"', 'access.log') is not None
        ), 'partial 3'

    def test_access_log_partial_4(self, wait_for_record):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        _ = self.http(b"""GET / HTTP/1.1\n""", raw=True, read_timeout=1)

        time.sleep(1)

        assert (
            wait_for_record(r'"-" 400 0 "-" "-"', 'access.log') is not None
        ), 'partial 4'

    @pytest.mark.skip('not yet')
    def test_access_log_partial_5(self, wait_for_record):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        self.get(headers={'Connection': 'close'})

        assert (
            wait_for_record(r'"GET / HTTP/1.1" 400 \d+ "-" "-"', 'access.log')
            is not None
        ), 'partial 5'

    def test_access_log_get_parameters(self, wait_for_record):
        self.load('empty')

        self.get(url='/?blah&var=val')

        assert (
            wait_for_record(
                r'"GET /\?blah&var=val HTTP/1.1" 200 0 "-" "-"', 'access.log'
            )
            is not None
        ), 'get parameters'

    def test_access_log_delete(self, search_in_file):
        self.load('empty')

        assert 'success' in self.conf_delete('access_log')

        self.get(url='/delete')

        assert search_in_file(r'/delete', 'access.log') is None, 'delete'

    def test_access_log_change(self, temp_dir, wait_for_record):
        self.load('empty')

        self.get()

        assert 'success' in self.conf(f'"{temp_dir}/new.log"', 'access_log')

        self.get()

        assert (
            wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', 'new.log')
            is not None
        ), 'change'

    def test_access_log_format(self, wait_for_record):
        self.load('empty')

        def check_format(format, expect, url='/'):
            self.set_format(format)

            assert self.get(url=url)['status'] == 200
            assert wait_for_record(expect, 'access.log') is not None, 'found'

        format = 'BLAH\t0123456789'
        check_format(format, format)
        check_format('$uri $status $uri $status', '/ 200 / 200')

    def test_access_log_variables(self, wait_for_record):
        self.load('mirror')

        # $body_bytes_sent

        self.set_format('$uri $body_bytes_sent')
        body = '0123456789' * 50
        self.post(url='/bbs', body=body, read_timeout=1)
        assert (
            wait_for_record(fr'^\/bbs {len(body)}$', 'access.log') is not None
        ), '$body_bytes_sent'

    def test_access_log_incorrect(self, temp_dir, skip_alert):
        skip_alert(r'failed to apply new conf')

        assert 'error' in self.conf(
            f'{temp_dir}/blah/access.log',
            'access_log/path',
        ), 'access_log path incorrect'

        assert 'error' in self.conf(
            {
                'path': f'{temp_dir}/access.log',
                'format': '$remote_add',
            },
            'access_log',
        ), 'access_log format incorrect'
