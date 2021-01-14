import re

import pytest
from unit.applications.lang.ruby import TestApplicationRuby


class TestRubyApplication(TestApplicationRuby):
    prerequisites = {'modules': {'ruby': 'all'}}

    def test_ruby_application(self):
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
            'Rack-Version': '13',
            'Rack-Url-Scheme': 'http',
            'Rack-Multithread': 'false',
            'Rack-Multiprocess': 'true',
            'Rack-Run-Once': 'false',
            'Rack-Hijack-Q': 'false',
            'Rack-Hijack': '',
            'Rack-Hijack-IO': '',
        }, 'headers'
        assert resp['body'] == body, 'body'

    def test_ruby_application_query_string(self):
        self.load('query_string')

        resp = self.get(url='/?var1=val1&var2=val2')

        assert (
            resp['headers']['Query-String'] == 'var1=val1&var2=val2'
        ), 'Query-String header'

    def test_ruby_application_query_string_empty(self):
        self.load('query_string')

        resp = self.get(url='/?')

        assert resp['status'] == 200, 'query string empty status'
        assert resp['headers']['Query-String'] == '', 'query string empty'

    def test_ruby_application_query_string_absent(self):
        self.load('query_string')

        resp = self.get()

        assert resp['status'] == 200, 'query string absent status'
        assert resp['headers']['Query-String'] == '', 'query string absent'

    @pytest.mark.skip('not yet')
    def test_ruby_application_server_port(self):
        self.load('server_port')

        assert (
            self.get()['headers']['Server-Port'] == '7080'
        ), 'Server-Port header'

    def test_ruby_application_status_int(self):
        self.load('status_int')

        assert self.get()['status'] == 200, 'status int'

    def test_ruby_application_input_read_empty(self):
        self.load('input_read_empty')

        assert self.get()['body'] == '', 'read empty'

    def test_ruby_application_input_read_parts(self):
        self.load('input_read_parts')

        assert (
            self.post(body='0123456789')['body'] == '012345678'
        ), 'input read parts'

    def test_ruby_application_input_read_buffer(self):
        self.load('input_read_buffer')

        assert (
            self.post(body='0123456789')['body'] == '0123456789'
        ), 'input read buffer'

    def test_ruby_application_input_read_buffer_not_empty(self):
        self.load('input_read_buffer_not_empty')

        assert (
            self.post(body='0123456789')['body'] == '0123456789'
        ), 'input read buffer not empty'

    def test_ruby_application_input_gets(self):
        self.load('input_gets')

        body = '0123456789'

        assert self.post(body=body)['body'] == body, 'input gets'

    def test_ruby_application_input_gets_2(self):
        self.load('input_gets')

        assert (
            self.post(body='01234\n56789\n')['body'] == '01234\n'
        ), 'input gets 2'

    def test_ruby_application_input_gets_all(self):
        self.load('input_gets_all')

        body = '\n01234\n56789\n\n'

        assert self.post(body=body)['body'] == body, 'input gets all'

    def test_ruby_application_input_each(self):
        self.load('input_each')

        body = '\n01234\n56789\n\n'

        assert self.post(body=body)['body'] == body, 'input each'

    @pytest.mark.skip('not yet')
    def test_ruby_application_input_rewind(self):
        self.load('input_rewind')

        body = '0123456789'

        assert self.post(body=body)['body'] == body, 'input rewind'

    @pytest.mark.skip('not yet')
    def test_ruby_application_syntax_error(self, skip_alert):
        skip_alert(
            r'Failed to parse rack script',
            r'syntax error',
            r'new_from_string',
            r'parse_file',
        )
        self.load('syntax_error')

        assert self.get()['status'] == 500, 'syntax error'

    def test_ruby_application_errors_puts(self):
        self.load('errors_puts')

        self.get()

        assert (
            self.wait_for_record(r'\[error\].+Error in application')
            is not None
        ), 'errors puts'

    def test_ruby_application_errors_puts_int(self):
        self.load('errors_puts_int')

        self.get()

        assert (
            self.wait_for_record(r'\[error\].+1234567890') is not None
        ), 'errors puts int'

    def test_ruby_application_errors_write(self):
        self.load('errors_write')

        self.get()

        assert (
            self.wait_for_record(r'\[error\].+Error in application')
            is not None
        ), 'errors write'

    def test_ruby_application_errors_write_to_s_custom(self):
        self.load('errors_write_to_s_custom')

        assert self.get()['status'] == 200, 'errors write to_s custom'

    def test_ruby_application_errors_write_int(self):
        self.load('errors_write_int')

        self.get()


        assert (
            self.wait_for_record(r'\[error\].+1234567890') is not None
        ), 'errors write int'

    def test_ruby_application_at_exit(self):
        self.load('at_exit')

        self.get()

        assert 'success' in self.conf({"listeners": {}, "applications": {}})

        assert (
            self.wait_for_record(r'\[error\].+At exit called\.') is not None
        ), 'at exit'

    def test_ruby_application_header_custom(self):
        self.load('header_custom')

        resp = self.post(body="\ntc=one,two\ntc=three,four,\n\n")

        assert resp['headers']['Custom-Header'] == [
            '',
            'tc=one,two',
            'tc=three,four,',
            '',
            '',
        ], 'header custom'

    @pytest.mark.skip('not yet')
    def test_ruby_application_header_custom_non_printable(self):
        self.load('header_custom')

        assert (
            self.post(body='\b')['status'] == 500
        ), 'header custom non printable'

    def test_ruby_application_header_status(self):
        self.load('header_status')

        assert self.get()['status'] == 200, 'header status'

    @pytest.mark.skip('not yet')
    def test_ruby_application_header_rack(self):
        self.load('header_rack')

        assert self.get()['status'] == 500, 'header rack'

    def test_ruby_application_body_empty(self):
        self.load('body_empty')

        assert self.get()['body'] == '', 'body empty'

    def test_ruby_application_body_array(self):
        self.load('body_array')

        assert self.get()['body'] == '0123456789', 'body array'

    def test_ruby_application_body_large(self):
        self.load('mirror')

        body = '0123456789' * 1000

        assert self.post(body=body)['body'] == body, 'body large'

    @pytest.mark.skip('not yet')
    def test_ruby_application_body_each_error(self):
        self.load('body_each_error')

        assert self.get()['status'] == 500, 'body each error status'

        assert (
            self.wait_for_record(r'\[error\].+Failed to run ruby script')
            is not None
        ), 'body each error'

    def test_ruby_application_body_file(self):
        self.load('body_file')

        assert self.get()['body'] == 'body\n', 'body file'

    def test_ruby_keepalive_body(self):
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

    def test_ruby_application_constants(self):
        self.load('constants')

        resp = self.get()

        assert resp['status'] == 200, 'status'

        headers = resp['headers']
        assert len(headers['X-Copyright']) > 0, 'RUBY_COPYRIGHT'
        assert len(headers['X-Description']) > 0, 'RUBY_DESCRIPTION'
        assert len(headers['X-Engine']) > 0, 'RUBY_ENGINE'
        assert len(headers['X-Engine-Version']) > 0, 'RUBY_ENGINE_VERSION'
        assert len(headers['X-Patchlevel']) > 0, 'RUBY_PATCHLEVEL'
        assert len(headers['X-Platform']) > 0, 'RUBY_PLATFORM'
        assert len(headers['X-Release-Date']) > 0, 'RUBY_RELEASE_DATE'
        assert len(headers['X-Revision']) > 0, 'RUBY_REVISION'
        assert len(headers['X-Version']) > 0, 'RUBY_VERSION'

    def test_ruby_application_threads(self):
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

            assert resp['headers']['Rack-Multithread'] == 'true', 'multithread'

            sock.close()

        assert len(socks) == len(threads), 'threads differs'
