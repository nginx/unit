import re
import time

import pytest
from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestVariables(TestApplicationProto):
    @pytest.fixture(autouse=True)
    def setup_method_fixture(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"return": 200}}],
            },
        ), 'configure routes'

    def set_format(self, format):
        assert 'success' in self.conf(
            {
                'path': f'{option.temp_dir}/access.log',
                'format': format,
            },
            'access_log',
        ), 'access_log format'

    def test_variables_dollar(self):
        assert 'success' in self.conf("301", 'routes/0/action/return')

        def check_dollar(location, expect):
            assert 'success' in self.conf(
                f'"{location}"',
                'routes/0/action/location',
            )
            assert self.get()['headers']['Location'] == expect

        check_dollar(
            'https://${host}${uri}path${dollar}dollar',
            'https://localhost/path$dollar',
        )
        check_dollar('path$dollar${dollar}', 'path$$')

    def test_variables_request_time(self, wait_for_record):
        self.set_format('$uri $request_time')

        sock = self.http(b'', raw=True, no_recv=True)

        time.sleep(1)

        assert self.get(url='/r_time_1', sock=sock)['status'] == 200
        assert wait_for_record(r'\/r_time_1 0\.\d{3}', 'access.log') is not None

        sock = self.http(
            b"""G""",
            no_recv=True,
            raw=True,
        )

        time.sleep(2)

        self.http(
            b"""ET /r_time_2 HTTP/1.1
Host: localhost
Connection: close

""",
            sock=sock,
            raw=True,
        )
        assert (
            wait_for_record(r'\/r_time_2 [1-9]\.\d{3}', 'access.log')
            is not None
        )

    def test_variables_method(self, search_in_file, wait_for_record):
        self.set_format('$method')

        reg = r'^GET$'
        assert search_in_file(reg, 'access.log') is None
        assert self.get()['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None, 'method GET'

        reg = r'^POST$'
        assert search_in_file(reg, 'access.log') is None
        assert self.post()['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None, 'method POST'

    def test_variables_request_uri(self, search_in_file, wait_for_record):
        self.set_format('$request_uri')

        def check_request_uri(req_uri):
            reg = fr'^{re.escape(req_uri)}$'

            assert search_in_file(reg, 'access.log') is None
            assert self.get(url=req_uri)['status'] == 200
            assert wait_for_record(reg, 'access.log') is not None

        check_request_uri('/3')
        check_request_uri('/4*')
        check_request_uri('/4%2A')
        check_request_uri('/9?q#a')

    def test_variables_uri(self, search_in_file, wait_for_record):
        self.set_format('$uri')

        def check_uri(uri, expect=None):
            expect = uri if expect is None else expect
            reg = fr'^{re.escape(expect)}$'

            assert search_in_file(reg, 'access.log') is None
            assert self.get(url=uri)['status'] == 200
            assert wait_for_record(reg, 'access.log') is not None

        check_uri('/3')
        check_uri('/4*')
        check_uri('/5%2A', '/5*')
        check_uri('/9?q#a', '/9')

    def test_variables_host(self, search_in_file, wait_for_record):
        self.set_format('$host')

        def check_host(host, expect=None):
            expect = host if expect is None else expect
            reg = fr'^{re.escape(expect)}$'

            assert search_in_file(reg, 'access.log') is None
            assert (
                self.get(headers={'Host': host, 'Connection': 'close'})[
                    'status'
                ]
                == 200
            )
            assert wait_for_record(reg, 'access.log') is not None

        check_host('localhost')
        check_host('localhost1.', 'localhost1')
        check_host('localhost2:7080', 'localhost2')
        check_host('.localhost')
        check_host('www.localhost')

    def test_variables_remote_addr(self, search_in_file, wait_for_record):
        self.set_format('$remote_addr')

        assert self.get()['status'] == 200
        assert wait_for_record(r'^127\.0\.0\.1$', 'access.log') is not None

        assert 'success' in self.conf(
            {"[::1]:7080": {"pass": "routes"}}, 'listeners'
        )

        reg = r'^::1$'
        assert search_in_file(reg, 'access.log') is None
        assert self.get(sock_type='ipv6')['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None

    def test_variables_time_local(
        self, date_to_sec_epoch, search_in_file, wait_for_record
    ):
        self.set_format('$uri $time_local $uri')

        assert search_in_file(r'/time_local', 'access.log') is None
        assert self.get(url='/time_local')['status'] == 200
        assert (
            wait_for_record(r'/time_local', 'access.log') is not None
        ), 'time log'
        date = search_in_file(
            r'^\/time_local (.*) \/time_local$', 'access.log'
        )[1]
        assert (
            abs(
                date_to_sec_epoch(date, '%d/%b/%Y:%X %z')
                - time.mktime(time.localtime())
            )
            < 5
        ), '$time_local'

    def test_variables_request_line(self, search_in_file, wait_for_record):
        self.set_format('$request_line')

        reg = r'^GET \/r_line HTTP\/1\.1$'
        assert search_in_file(reg, 'access.log') is None
        assert self.get(url='/r_line')['status'] == 200
        assert wait_for_record(reg, 'access.log') is not None

    def test_variables_status(self, search_in_file, wait_for_record):
        self.set_format('$status')

        assert 'success' in self.conf("418", 'routes/0/action/return')

        reg = r'^418$'
        assert search_in_file(reg, 'access.log') is None
        assert self.get()['status'] == 418
        assert wait_for_record(reg, 'access.log') is not None

    def test_variables_header_referer(self, search_in_file, wait_for_record):
        self.set_format('$method $header_referer')

        def check_referer(referer):
            reg = fr'^GET {re.escape(referer)}$'

            assert search_in_file(reg, 'access.log') is None
            assert (
                self.get(
                    headers={
                        'Host': 'localhost',
                        'Connection': 'close',
                        'Referer': referer,
                    }
                )['status']
                == 200
            )
            assert wait_for_record(reg, 'access.log') is not None

        check_referer('referer-value')
        check_referer('')
        check_referer('no')

    def test_variables_header_user_agent(self, search_in_file, wait_for_record):
        self.set_format('$method $header_user_agent')

        def check_user_agent(user_agent):
            reg = fr'^GET {re.escape(user_agent)}$'

            assert search_in_file(reg, 'access.log') is None
            assert (
                self.get(
                    headers={
                        'Host': 'localhost',
                        'Connection': 'close',
                        'User-Agent': user_agent,
                    }
                )['status']
                == 200
            )
            assert wait_for_record(reg, 'access.log') is not None

        check_user_agent('MSIE')
        check_user_agent('')
        check_user_agent('no')

    def test_variables_many(self, search_in_file, wait_for_record):
        def check_vars(uri, expect):
            reg = fr'^{re.escape(expect)}$'

            assert search_in_file(reg, 'access.log') is None
            assert self.get(url=uri)['status'] == 200
            assert wait_for_record(reg, 'access.log') is not None

        self.set_format('$uri$method')
        check_vars('/1', '/1GET')

        self.set_format('${uri}${method}')
        check_vars('/2', '/2GET')

        self.set_format('${uri}$method')
        check_vars('/3', '/3GET')

        self.set_format('$method$method')
        check_vars('/', 'GETGET')

    def test_variables_dynamic(self, wait_for_record):
        self.set_format('$header_foo$cookie_foo$arg_foo')

        assert (
            self.get(
                url='/?foo=h',
                headers={'Foo': 'b', 'Cookie': 'foo=la', 'Connection': 'close'},
            )['status']
            == 200
        )
        assert wait_for_record(r'^blah$', 'access.log') is not None

    def test_variables_dynamic_arguments(self, search_in_file, wait_for_record):
        def check_arg(url, expect=None):
            expect = url if expect is None else expect
            reg = fr'^{re.escape(expect)}$'

            assert search_in_file(reg, 'access.log') is None
            assert self.get(url=url)['status'] == 200
            assert wait_for_record(reg, 'access.log') is not None

        def check_no_arg(url):
            assert self.get(url=url)['status'] == 200
            assert search_in_file(r'^0$', 'access.log') is None

        self.set_format('$arg_foo_bar')
        check_arg('/?foo_bar=1', '1')
        check_arg('/?foo_b%61r=2', '2')
        check_arg('/?bar&foo_bar=3&foo', '3')
        check_arg('/?foo_bar=l&foo_bar=4', '4')
        check_no_arg('/')
        check_no_arg('/?foo_bar=')
        check_no_arg('/?Foo_bar=0')
        check_no_arg('/?foo-bar=0')
        check_no_arg('/?foo_bar=0&foo_bar=l')

        self.set_format('$arg_foo_b%61r')
        check_no_arg('/?foo_b=0')
        check_no_arg('/?foo_bar=0')

        self.set_format('$arg_f!~')
        check_no_arg('/?f=0')
        check_no_arg('/?f!~=0')

    def test_variables_dynamic_headers(self, search_in_file, wait_for_record):
        def check_header(header, value):
            reg = fr'^{value}$'

            assert search_in_file(reg, 'access.log') is None
            assert (
                self.get(headers={header: value, 'Connection': 'close'})[
                    'status'
                ]
                == 200
            )
            assert wait_for_record(reg, 'access.log') is not None

        def check_no_header(header):
            assert (
                self.get(headers={header: '0', 'Connection': 'close'})['status']
                == 200
            )
            assert search_in_file(r'^0$', 'access.log') is None

        self.set_format('$header_foo_bar')
        check_header('foo-bar', '1')
        check_header('Foo-Bar', '2')
        check_no_header('foo_bar')
        check_no_header('foobar')

        self.set_format('$header_Foo_Bar')
        check_header('Foo-Bar', '4')
        check_header('foo-bar', '5')
        check_no_header('foo_bar')
        check_no_header('foobar')

    def test_variables_dynamic_cookies(self, search_in_file, wait_for_record):
        def check_no_cookie(cookie):
            assert (
                self.get(
                    headers={
                        'Host': 'localhost',
                        'Cookie': cookie,
                        'Connection': 'close',
                    },
                )['status']
                == 200
            )
            assert search_in_file(r'^0$', 'access.log') is None

        self.set_format('$cookie_foo_bar')

        reg = r'^1$'
        assert search_in_file(reg, 'access.log') is None
        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foo_bar=1',
                    'Connection': 'close',
                },
            )['status']
            == 200
        )
        assert wait_for_record(reg, 'access.log') is not None

        check_no_cookie('fOo_bar=0')
        check_no_cookie('foo_bar=')

    def test_variables_invalid(self, temp_dir):
        def check_variables(format):
            assert 'error' in self.conf(
                {
                    'path': f'{temp_dir}/access.log',
                    'format': format,
                },
                'access_log',
            ), 'access_log format'

        check_variables("$")
        check_variables("${")
        check_variables("${}")
        check_variables("$ur")
        check_variables("$uri$$host")
        check_variables("$uriblah")
        check_variables("${uri")
        check_variables("${{uri}")
        check_variables("$ar")
        check_variables("$arg")
        check_variables("$arg_")
        check_variables("$cookie")
        check_variables("$cookie_")
        check_variables("$header")
        check_variables("$header_")
