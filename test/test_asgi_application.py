import re
import time
from distutils.version import LooseVersion

import pytest

from unit.applications.lang.python import TestApplicationPython
from unit.option import option


class TestASGIApplication(TestApplicationPython):
    prerequisites = {
        'modules': {'python': lambda v: LooseVersion(v) >= LooseVersion('3.5')}
    }
    load_module = 'asgi'

    def findall(self, pattern):
        with open(option.temp_dir + '/unit.log', 'r', errors='ignore') as f:
            return re.findall(pattern, f.read())

    def test_asgi_application_variables(self):
        self.load('variables')

        body = 'Test body string.'

        resp = self.http(
            b"""POST / HTTP/1.1
Host: localhost
Content-Length: %d
Custom-Header: blah
Custom-hEader: Blah
Content-Type: text/html
Connection: close
custom-header: BLAH

%s"""
            % (len(body), body.encode()),
            raw=True,
        )

        assert resp['status'] == 200, 'status'
        headers = resp['headers']
        header_server = headers.pop('Server')
        assert re.search(r'Unit/[\d\.]+', header_server), 'server header'

        date = headers.pop('Date')
        assert date[-4:] == ' GMT', 'date header timezone'
        assert (
            abs(self.date_to_sec_epoch(date) - self.sec_epoch()) < 5
        ), 'date header'

        assert headers == {
            'Connection': 'close',
            'content-length': str(len(body)),
            'content-type': 'text/html',
            'request-method': 'POST',
            'request-uri': '/',
            'http-host': 'localhost',
            'http-version': '1.1',
            'custom-header': 'blah, Blah, BLAH',
            'asgi-version': '3.0',
            'asgi-spec-version': '2.1',
            'scheme': 'http',
        }, 'headers'
        assert resp['body'] == body, 'body'

    def test_asgi_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        assert (
            resp['headers']['query-string'] == 'var1=val1&var2=val2'
        ), 'query-string header'

    def test_asgi_application_query_string_space(self):
        self.load('query_string')

        resp = self.get(url='/ ?var1=val1&var2=val2')
        assert (
            resp['headers']['query-string'] == 'var1=val1&var2=val2'
        ), 'query-string space'

        resp = self.get(url='/ %20?var1=val1&var2=val2')
        assert (
            resp['headers']['query-string'] == 'var1=val1&var2=val2'
        ), 'query-string space 2'

        resp = self.get(url='/ %20 ?var1=val1&var2=val2')
        assert (
            resp['headers']['query-string'] == 'var1=val1&var2=val2'
        ), 'query-string space 3'

        resp = self.get(url='/blah %20 blah? var1= val1 & var2=val2')
        assert (
            resp['headers']['query-string'] == ' var1= val1 & var2=val2'
        ), 'query-string space 4'

    def test_asgi_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        assert resp['status'] == 200, 'query string empty status'
        assert resp['headers']['query-string'] == '', 'query string empty'

    def test_asgi_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        assert resp['status'] == 200, 'query string absent status'
        assert resp['headers']['query-string'] == '', 'query string absent'

    @pytest.mark.skip('not yet')
    def test_asgi_application_server_port(self):
        self.load('server_port')

        assert (
            self.get()['headers']['Server-Port'] == '7080'
        ), 'Server-Port header'

    @pytest.mark.skip('not yet')
    def test_asgi_application_working_directory_invalid(self):
        self.load('empty')

        assert 'success' in self.conf(
            '"/blah"', 'applications/empty/working_directory'
        ), 'configure invalid working_directory'

        assert self.get()['status'] == 500, 'status'

    def test_asgi_application_204_transfer_encoding(self):
        self.load('204_no_content')

        assert (
            'Transfer-Encoding' not in self.get()['headers']
        ), '204 header transfer encoding'

    def test_asgi_application_shm_ack_handle(self):
        # Minimum possible limit
        shm_limit = 10 * 1024 * 1024

        self.load('mirror', limits={"shm": shm_limit})

        # Should exceed shm_limit
        max_body_size = 12 * 1024 * 1024

        assert 'success' in self.conf(
            '{"http":{"max_body_size": ' + str(max_body_size) + ' }}',
            'settings',
        )

        assert self.get()['status'] == 200, 'init'

        body = '0123456789AB' * 1024 * 1024  # 12 Mb
        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            body=body,
            read_buffer_size=1024 * 1024,
        )

        assert resp['body'] == body, 'keep-alive 1'

    def test_asgi_keepalive_body(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        body = '0123456789' * 500
        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html',
            },
            start=True,
            body=body,
            read_timeout=1,
        )

        assert resp['body'] == body, 'keep-alive 1'

        body = '0123456789'
        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            sock=sock,
            body=body,
        )

        assert resp['body'] == body, 'keep-alive 2'

    def test_asgi_keepalive_reconfigure(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        body = '0123456789'
        conns = 3
        socks = []

        for i in range(conns):
            (resp, sock) = self.post(
                headers={
                    'Host': 'localhost',
                    'Connection': 'keep-alive',
                    'Content-Type': 'text/html',
                },
                start=True,
                body=body,
                read_timeout=1,
            )

            assert resp['body'] == body, 'keep-alive open'

            self.load('mirror', processes=i + 1)

            socks.append(sock)

        for i in range(conns):
            (resp, sock) = self.post(
                headers={
                    'Host': 'localhost',
                    'Connection': 'keep-alive',
                    'Content-Type': 'text/html',
                },
                start=True,
                sock=socks[i],
                body=body,
                read_timeout=1,
            )

            assert resp['body'] == body, 'keep-alive request'

            self.load('mirror', processes=i + 1)

        for i in range(conns):
            resp = self.post(
                headers={
                    'Host': 'localhost',
                    'Connection': 'close',
                    'Content-Type': 'text/html',
                },
                sock=socks[i],
                body=body,
            )

            assert resp['body'] == body, 'keep-alive close'

            self.load('mirror', processes=i + 1)

    def test_asgi_keepalive_reconfigure_2(self):
        self.load('mirror')

        assert self.get()['status'] == 200, 'init'

        body = '0123456789'

        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'keep-alive',
                'Content-Type': 'text/html',
            },
            start=True,
            body=body,
            read_timeout=1,
        )

        assert resp['body'] == body, 'reconfigure 2 keep-alive 1'

        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        (resp, sock) = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            start=True,
            sock=sock,
            body=body,
        )

        assert resp['status'] == 200, 'reconfigure 2 keep-alive 2'
        assert resp['body'] == '', 'reconfigure 2 keep-alive 2 body'

        assert 'success' in self.conf(
            {"listeners": {}, "applications": {}}
        ), 'reconfigure 2 clear configuration'

        resp = self.get(sock=sock)

        assert resp == {}, 'reconfigure 2 keep-alive 3'

    def test_asgi_keepalive_reconfigure_3(self):
        self.load('empty')

        assert self.get()['status'] == 200, 'init'

        (_, sock) = self.http(
            b"""GET / HTTP/1.1
""",
            start=True,
            raw=True,
            no_recv=True,
        )

        assert self.get()['status'] == 200

        assert 'success' in self.conf(
            {"listeners": {}, "applications": {}}
        ), 'reconfigure 3 clear configuration'

        resp = self.http(
            b"""Host: localhost
Connection: close

""",
            sock=sock,
            raw=True,
        )

        assert resp['status'] == 200, 'reconfigure 3'

    def test_asgi_process_switch(self):
        self.load('delayed', processes=2)

        self.get(
            headers={
                'Host': 'localhost',
                'Content-Length': '0',
                'X-Delay': '5',
                'Connection': 'close',
            },
            no_recv=True,
        )

        headers_delay_1 = {
            'Connection': 'close',
            'Host': 'localhost',
            'Content-Length': '0',
            'X-Delay': '1',
        }

        self.get(headers=headers_delay_1, no_recv=True)

        time.sleep(0.5)

        for _ in range(10):
            self.get(headers=headers_delay_1, no_recv=True)

        self.get(headers=headers_delay_1)

    def test_asgi_application_loading_error(self, skip_alert):
        skip_alert(r'Python failed to import module "blah"')

        self.load('empty', module="blah")

        assert self.get()['status'] == 503, 'loading error'

    def test_asgi_application_threading(self):
        """wait_for_record() timeouts after 5s while every thread works at
        least 3s.  So without releasing GIL test should fail.
        """

        self.load('threading')

        for _ in range(10):
            self.get(no_recv=True)

        assert (
            self.wait_for_record(r'\(5\) Thread: 100', wait=50) is not None
        ), 'last thread finished'

    def test_asgi_application_threads(self):
        self.load('threads', threads=2)

        socks = []

        for i in range(2):
            (_, sock) = self.get(
                headers={
                    'Host': 'localhost',
                    'X-Delay': '3',
                    'Connection': 'close',
                },
                no_recv=True,
                start=True,
            )

            socks.append(sock)

            time.sleep(1.0)  # required to avoid greedy request reading

        threads = set()

        for sock in socks:
            resp = self.recvall(sock).decode('utf-8')

            self.log_in(resp)

            resp = self._resp_to_dict(resp)

            assert resp['status'] == 200, 'status'

            threads.add(resp['headers']['x-thread'])

            sock.close()

        assert len(socks) == len(threads), 'threads differs'

    def test_asgi_application_legacy(self):
        self.load('legacy')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Content-Length': '0',
                'Connection': 'close',
            },
        )

        assert resp['status'] == 200, 'status'

    def test_asgi_application_legacy_force(self):
        self.load('legacy_force', protocol='asgi')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'Content-Length': '0',
                'Connection': 'close',
            },
        )

        assert resp['status'] == 200, 'status'
