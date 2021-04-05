import re

import pytest

from unit.applications.lang.perl import TestApplicationPerl


class TestPerlApplication(TestApplicationPerl):
    prerequisites = {'modules': {'perl': 'all'}}

    def test_perl_application(self):
        self.load('variables')

        body = 'Test body string.'

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Content-Type': 'text/html',
                'Custom-Header': 'blah',
                'Connection': 'close',
            },
            body=body,
        )

        assert resp['status'] == 200, 'status'
        headers = resp['headers']
        header_server = headers.pop('Server')
        assert re.search(r'Unit/[\d\.]+', header_server), 'server header'
        assert (
            headers.pop('Server-Software') == header_server
        ), 'server software header'

        date = headers.pop('Date')
        assert date[-4:] == ' GMT', 'date header timezone'
        assert (
            abs(self.date_to_sec_epoch(date) - self.sec_epoch()) < 5
        ), 'date header'

        assert headers == {
            'Connection': 'close',
            'Content-Length': str(len(body)),
            'Content-Type': 'text/html',
            'Request-Method': 'POST',
            'Request-Uri': '/',
            'Http-Host': 'localhost',
            'Server-Protocol': 'HTTP/1.1',
            'Custom-Header': 'blah',
            'Psgi-Version': '11',
            'Psgi-Url-Scheme': 'http',
            'Psgi-Multithread': '',
            'Psgi-Multiprocess': '1',
            'Psgi-Run-Once': '',
            'Psgi-Nonblocking': '',
            'Psgi-Streaming': '1',
        }, 'headers'
        assert resp['body'] == body, 'body'

    def test_perl_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'Query-String header'

    def test_perl_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        assert resp['status'] == 200, 'query string empty status'
        assert resp['headers']['Query-String'] == '', 'query string empty'

    def test_perl_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        assert resp['status'] == 200, 'query string absent status'
        assert resp['headers']['Query-String'] == '', 'query string absent'

    @pytest.mark.skip('not yet')
    def test_perl_application_server_port(self):
        self.load('server_port')

        assert (
            self.get()['headers']['Server-Port'] == '7080'
        ), 'Server-Port header'

    def test_perl_application_input_read_empty(self):
        self.load('input_read_empty')

        assert self.get()['body'] == '', 'read empty'

    def test_perl_application_input_read_parts(self):
        self.load('input_read_parts')

        assert (
            self.post(body='0123456789')['body'] == '0123456789'
        ), 'input read parts'

    @pytest.mark.skip('not yet')
    def test_perl_application_input_read_offset(self):
        self.load('input_read_offset')

        assert self.post(body='0123456789')['body'] == '4567', 'read offset'

    def test_perl_application_input_copy(self):
        self.load('input_copy')

        body = '0123456789'
        assert self.post(body=body)['body'] == body, 'input copy'

    def test_perl_application_errors_print(self):
        self.load('errors_print')

        assert self.get()['body'] == '1', 'errors result'

        assert (
            self.wait_for_record(r'\[error\].+Error in application')
            is not None
        ), 'errors print'

    def test_perl_application_header_equal_names(self):
        self.load('header_equal_names')

        assert self.get()['headers']['Set-Cookie'] == [
            'tc=one,two,three',
            'tc=four,five,six',
        ], 'header equal names'

    def test_perl_application_header_pairs(self):
        self.load('header_pairs')

        assert self.get()['headers']['blah'] == 'blah', 'header pairs'

    def test_perl_application_body_empty(self):
        self.load('body_empty')

        assert self.get()['body'] == '', 'body empty'

    def test_perl_application_body_array(self):
        self.load('body_array')

        assert self.get()['body'] == '0123456789', 'body array'

    def test_perl_application_body_large(self):
        self.load('variables')

        body = '0123456789' * 1000

        resp = self.post(body=body)['body']

        assert resp == body, 'body large'

    def test_perl_application_body_io_empty(self):
        self.load('body_io_empty')

        assert self.get()['status'] == 200, 'body io empty'

    def test_perl_application_body_io_file(self):
        self.load('body_io_file')

        assert self.get()['body'] == 'body\n', 'body io file'

    @pytest.mark.skip('not yet')
    def test_perl_application_syntax_error(self, skip_alert):
        skip_alert(r'PSGI: Failed to parse script')
        self.load('syntax_error')

        assert self.get()['status'] == 500, 'syntax error'

    def test_perl_keepalive_body(self):
        self.load('variables')

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

    def test_perl_body_io_fake(self):
        self.load('body_io_fake')

        assert self.get()['body'] == '21', 'body io fake'

        assert (
            self.wait_for_record(r'\[error\].+IOFake getline\(\) \$\/ is \d+')
            is not None
        ), 'body io fake $/ value'

        assert (
            self.wait_for_record(r'\[error\].+IOFake close\(\) called')
            is not None
        ), 'body io fake close'

    def test_perl_delayed_response(self):
        self.load('delayed_response')

        resp = self.get()

        assert resp['status'] == 200, 'status'
        assert resp['body'] == 'Hello World!', 'body'

    def test_perl_streaming_body(self):
        self.load('streaming_body')

        resp = self.get()

        assert resp['status'] == 200, 'status'
        assert resp['body'] == 'Hello World!', 'body'

    def test_perl_application_threads(self):
        self.load('threads')

        assert 'success' in self.conf(
            '4', 'applications/threads/threads'
        ), 'configure 4 threads'

        socks = []

        for i in range(4):
            (_, sock) = self.get(
                headers={
                    'Host': 'localhost',
                    'X-Delay': '2',
                    'Connection': 'close',
                },
                no_recv=True,
                start=True,
            )

            socks.append(sock)

        threads = set()

        for sock in socks:
            resp = self.recvall(sock).decode('utf-8')

            self.log_in(resp)

            resp = self._resp_to_dict(resp)

            assert resp['status'] == 200, 'status'

            threads.add(resp['headers']['X-Thread'])

            assert resp['headers']['Psgi-Multithread'] == '1', 'multithread'

            sock.close()

        assert len(socks) == len(threads), 'threads differs'
