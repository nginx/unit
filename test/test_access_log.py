import time

import pytest
from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestAccessLog(TestApplicationPython):
    prerequisites = {'modules': {'python': 'any'}}

    def load(self, script):
        super().load(script)

        assert 'success' in self.conf(
            '"' + option.temp_dir + '/access.log"', 'access_log'
        ), 'access_log configure'

    def wait_for_record(self, pattern, name='access.log'):
        return super().wait_for_record(pattern, name)

    def test_access_log_keepalive(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html',
            },
            start=True,
            body='01234',
            read_timeout=1,
        )

        assert (
            self.wait_for_record(r'"POST / HTTP/1.1" 200 5') is not None
        ), 'keepalive 1'

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            sock=sock,
            body='0123456789',
        )

        assert (
            self.wait_for_record(r'"POST / HTTP/1.1" 200 10') is not None
        ), 'keepalive 2'

    def test_access_log_pipeline(self):
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
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-1" "-"')
            is not None
        ), 'pipeline 1'
        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-2" "-"')
            is not None
        ), 'pipeline 2'
        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-3" "-"')
            is not None
        ), 'pipeline 3'

    def test_access_log_ipv6(self):
        self.load('empty')

        assert 'success' in self.conf(
            {"[::1]:7080": {"pass": "applications/empty"}}, 'listeners'
        )

        self.get(sock_type='ipv6')

        assert (
            self.wait_for_record(
                r'::1 - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"'
            )
            is not None
        ), 'ipv6'

    def test_access_log_unix(self):
        self.load('empty')

        addr = option.temp_dir + '/sock'

        assert 'success' in self.conf(
            {"unix:" + addr: {"pass": "applications/empty"}}, 'listeners'
        )

        self.get(sock_type='unix', addr=addr)

        assert (
            self.wait_for_record(
                r'unix: - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"'
            )
            is not None
        ), 'unix'

    def test_access_log_referer(self):
        self.load('empty')

        self.get(
            headers={
                'Host': 'localhost',
                'Referer': 'referer-value',
                'Connection': 'close',
            }
        )

        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "referer-value" "-"')
            is not None
        ), 'referer'

    def test_access_log_user_agent(self):
        self.load('empty')

        self.get(
            headers={
                'Host': 'localhost',
                'User-Agent': 'user-agent-value',
                'Connection': 'close',
            }
        )

        assert (
            self.wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "-" "user-agent-value"'
            )
            is not None
        ), 'user agent'

    def test_access_log_http10(self):
        self.load('empty')

        self.get(http_10=True)

        assert (
            self.wait_for_record(r'"GET / HTTP/1.0" 200 0 "-" "-"') is not None
        ), 'http 1.0'

    def test_access_log_partial(self):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        resp = self.http(b"""GE""", raw=True, read_timeout=1)

        time.sleep(1)

        assert (
            self.wait_for_record(r'"GE" 400 0 "-" "-"') is not None
        ), 'partial'

    def test_access_log_partial_2(self):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        self.http(b"""GET /\n""", raw=True)

        assert (
            self.wait_for_record(r'"GET /" 400 \d+ "-" "-"') is not None
        ), 'partial 2'

    def test_access_log_partial_3(self):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        resp = self.http(b"""GET / HTTP/1.1""", raw=True, read_timeout=1)

        time.sleep(1)

        assert (
            self.wait_for_record(r'"GET /" 400 0 "-" "-"') is not None
        ), 'partial 3'

    def test_access_log_partial_4(self):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        resp = self.http(b"""GET / HTTP/1.1\n""", raw=True, read_timeout=1)

        time.sleep(1)

        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 400 0 "-" "-"') is not None
        ), 'partial 4'

    @pytest.mark.skip('not yet')
    def test_access_log_partial_5(self):
        self.load('empty')

        assert self.post()['status'] == 200, 'init'

        self.get(headers={'Connection': 'close'})

        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 400 \d+ "-" "-"')
            is not None
        ), 'partial 5'

    def test_access_log_get_parameters(self):
        self.load('empty')

        self.get(url='/?blah&var=val')

        assert (
            self.wait_for_record(
                r'"GET /\?blah&var=val HTTP/1.1" 200 0 "-" "-"'
            )
            is not None
        ), 'get parameters'

    def test_access_log_delete(self):
        self.load('empty')

        assert 'success' in self.conf_delete('access_log')

        self.get(url='/delete')

        assert self.search_in_log(r'/delete', 'access.log') is None, 'delete'

    def test_access_log_change(self, temp_dir):
        self.load('empty')

        self.get()

        assert 'success' in self.conf(
            '"' + option.temp_dir + '/new.log"', 'access_log'
        )

        self.get()

        assert (
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', 'new.log')
            is not None
        ), 'change'
