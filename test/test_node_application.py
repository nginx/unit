import re

import pytest

from unit.applications.lang.node import TestApplicationNode
from unit.utils import waitforfiles


class TestNodeApplication(TestApplicationNode):
    prerequisites = {'modules': {'node': 'all'}}

    def test_node_application_basic(self):
        self.load('basic')

        resp = self.get()
        assert resp['headers']['Content-Type'] == 'text/plain', 'basic header'
        assert resp['body'] == 'Hello World\n', 'basic body'

    def test_node_application_seq(self):
        self.load('basic')

        assert self.get()['status'] == 200, 'seq'
        assert self.get()['status'] == 200, 'seq 2'

    def test_node_application_variables(self):
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

        date = headers.pop('Date')
        assert date[-4:] == ' GMT', 'date header timezone'
        assert (
            abs(self.date_to_sec_epoch(date) - self.sec_epoch()) < 5
        ), 'date header'

        raw_headers = headers.pop('Request-Raw-Headers')
        assert re.search(
            r'^(?:Host|localhost|Content-Type|'
            r'text\/html|Custom-Header|blah|Content-Length|17|Connection|'
            r'close|,)+$',
            raw_headers,
        ), 'raw headers'

        assert headers == {
            'Connection': 'close',
            'Content-Length': str(len(body)),
            'Content-Type': 'text/html',
            'Request-Method': 'POST',
            'Request-Uri': '/',
            'Http-Host': 'localhost',
            'Server-Protocol': 'HTTP/1.1',
            'Custom-Header': 'blah',
        }, 'headers'
        assert resp['body'] == body, 'body'

    def test_node_application_get_variables(self):
        self.load('get_variables')

        resp = self.get(url='/?var1=val1&var2=&var3')
        assert resp['headers']['X-Var-1'] == 'val1', 'GET variables'
        assert resp['headers']['X-Var-2'] == '', 'GET variables 2'
        assert resp['headers']['X-Var-3'] == '', 'GET variables 3'

    def test_node_application_post_variables(self):
        self.load('post_variables')

        resp = self.post(
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': 'localhost',
                'Connection': 'close',
            },
            body='var1=val1&var2=&var3',
        )

        assert resp['headers']['X-Var-1'] == 'val1', 'POST variables'
        assert resp['headers']['X-Var-2'] == '', 'POST variables 2'
        assert resp['headers']['X-Var-3'] == '', 'POST variables 3'

    def test_node_application_404(self):
        self.load('404')

        resp = self.get()

        assert resp['status'] == 404, '404 status'
        assert re.search(
            r'<title>404 Not Found</title>', resp['body']
        ), '404 body'

    def test_node_keepalive_body(self):
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

        assert resp['body'] == '0123456789' * 500, 'keep-alive 1'

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

    def test_node_application_write_buffer(self):
        self.load('write_buffer')

        assert self.get()['body'] == 'buffer', 'write buffer'

    def test_node_application_write_callback(self, temp_dir):
        self.load('write_callback')

        assert self.get()['body'] == 'helloworld', 'write callback order'
        assert waitforfiles(temp_dir + '/node/callback'), 'write callback'

    def test_node_application_write_before_write_head(self):
        self.load('write_before_write_head')

        assert self.get()['status'] == 200, 'write before writeHead'

    def test_node_application_double_end(self):
        self.load('double_end')

        assert self.get()['status'] == 200, 'double end'
        assert self.get()['status'] == 200, 'double end 2'

    def test_node_application_write_return(self):
        self.load('write_return')

        assert self.get()['body'] == 'bodytrue', 'write return'

    def test_node_application_remove_header(self):
        self.load('remove_header')

        resp = self.get(
            headers={
                'Host': 'localhost',
                'X-Remove': 'X-Header',
                'Connection': 'close',
            }
        )
        assert resp['headers']['Was-Header'] == 'true', 'was header'
        assert resp['headers']['Has-Header'] == 'false', 'has header'
        assert not ('X-Header' in resp['headers']), 'remove header'

    def test_node_application_remove_header_nonexisting(self):
        self.load('remove_header')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Remove': 'blah',
                    'Connection': 'close',
                }
            )['headers']['Has-Header']
            == 'true'
        ), 'remove header nonexisting'

    def test_node_application_update_header(self):
        self.load('update_header')

        assert self.get()['headers']['X-Header'] == 'new', 'update header'

    def test_node_application_set_header_array(self):
        self.load('set_header_array')

        assert self.get()['headers']['Set-Cookie'] == [
            'tc=one,two,three',
            'tc=four,five,six',
        ], 'set header array'

    @pytest.mark.skip('not yet')
    def test_node_application_status_message(self):
        self.load('status_message')

        assert re.search(
            r'200 blah', self.get(raw_resp=True)
        ), 'status message'

    def test_node_application_get_header_type(self):
        self.load('get_header_type')

        assert self.get()['headers']['X-Type'] == 'number', 'get header type'

    def test_node_application_header_name_case(self):
        self.load('header_name_case')

        headers = self.get()['headers']

        assert headers['X-HEADER'] == '3', 'header value'
        assert 'X-Header' not in headers, 'insensitive'
        assert 'X-header' not in headers, 'insensitive 2'

    def test_node_application_promise_handler_write_after_end(self):
        self.load('promise_handler')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Type': 'text/html',
                    'X-Write-Call': '1',
                    'Connection': 'close',
                },
                body='callback',
            )['status']
            == 200
        ), 'promise handler request write after end'

    def test_node_application_promise_end(self, temp_dir):
        self.load('promise_end')

        assert (
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Type': 'text/html',
                    'Connection': 'close',
                },
                body='end',
            )['status']
            == 200
        ), 'promise end request'
        assert waitforfiles(temp_dir + '/node/callback'), 'promise end'

    @pytest.mark.skip('not yet')
    def test_node_application_header_name_valid(self):
        self.load('header_name_valid')

        assert 'status' not in self.get(), 'header name valid'

    def test_node_application_header_value_object(self):
        self.load('header_value_object')

        assert 'X-Header' in self.get()['headers'], 'header value object'

    def test_node_application_get_header_names(self):
        self.load('get_header_names')

        assert self.get()['headers']['X-Names'] == [
            'date',
            'x-header',
        ], 'get header names'

    def test_node_application_has_header(self):
        self.load('has_header')

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Header': 'length',
                    'Connection': 'close',
                }
            )['headers']['X-Has-Header']
            == 'false'
        ), 'has header length'

        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'X-Header': 'Date',
                    'Connection': 'close',
                }
            )['headers']['X-Has-Header']
            == 'false'
        ), 'has header date'

    def test_node_application_write_multiple(self):
        self.load('write_multiple')

        assert self.get()['body'] == 'writewrite2end', 'write multiple'
