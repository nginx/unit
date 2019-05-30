import os
import re
import time
import unittest
from subprocess import call
from unit.applications.lang.python import TestApplicationPython


class TestAccessLog(TestApplicationPython):
    prerequisites = ['python']

    def load(self, script):
        super().load(script)

        self.conf('"' + self.testdir + '/access.log"', 'access_log')

    def wait_for_record(self, pattern, name='access.log'):
        return super().wait_for_record(pattern, name)

    def test_access_log_keepalive(self):
        self.load('mirror')

        self.assertEqual(self.get()['status'], 200, 'init')

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

        self.assertIsNotNone(
            self.wait_for_record(r'"POST / HTTP/1.1" 200 5'), 'keepalive 1'
        )

        resp = self.post(
            headers={
                'Host': 'localhost',
                'Connection': 'close',
                'Content-Type': 'text/html',
            },
            sock=sock,
            body='0123456789',
        )

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"POST / HTTP/1.1" 200 10'), 'keepalive 2'
        )

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

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-1" "-"'),
            'pipeline 1',
        )
        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-2" "-"'),
            'pipeline 2',
        )
        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "Referer-3" "-"'),
            'pipeline 3',
        )

    def test_access_log_ipv6(self):
        self.load('empty')

        self.conf({"[::1]:7080": {"pass": "applications/empty"}}, 'listeners')

        self.get(sock_type='ipv6')

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(
                r'::1 - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"'
            ),
            'ipv6',
        )

    def test_access_log_unix(self):
        self.load('empty')

        addr = self.testdir + '/sock'

        self.conf({"unix:" + addr: {"pass": "applications/empty"}}, 'listeners')

        self.get(sock_type='unix', addr=addr)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(
                r'unix: - - \[.+\] "GET / HTTP/1.1" 200 0 "-" "-"'
            ),
            'unix',
        )

    def test_access_log_referer(self):
        self.load('empty')

        self.get(
            headers={
                'Host': 'localhost',
                'Referer': 'referer-value',
                'Connection': 'close',
            }
        )

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "referer-value" "-"'
            ),
            'referer',
        )

    def test_access_log_user_agent(self):
        self.load('empty')

        self.get(
            headers={
                'Host': 'localhost',
                'User-Agent': 'user-agent-value',
                'Connection': 'close',
            }
        )

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(
                r'"GET / HTTP/1.1" 200 0 "-" "user-agent-value"'
            ),
            'user agent',
        )

    def test_access_log_http10(self):
        self.load('empty')

        self.get(http_10=True)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.0" 200 0 "-" "-"'), 'http 1.0'
        )

    def test_access_log_partial(self):
        self.load('empty')

        self.assertEqual(self.post()['status'], 200, 'init')

        resp = self.http(b"""GE""", raw=True, read_timeout=5)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GE" 400 0 "-" "-"'), 'partial'
        )

    def test_access_log_partial_2(self):
        self.load('empty')

        self.assertEqual(self.post()['status'], 200, 'init')

        self.http(b"""GET /\n""", raw=True)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET /" 400 \d+ "-" "-"'), 'partial 2'
        )

    def test_access_log_partial_3(self):
        self.load('empty')

        self.assertEqual(self.post()['status'], 200, 'init')

        resp = self.http(b"""GET / HTTP/1.1""", raw=True, read_timeout=5)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET /" 400 0 "-" "-"'), 'partial 3'
        )

    def test_access_log_partial_4(self):
        self.load('empty')

        self.assertEqual(self.post()['status'], 200, 'init')

        resp = self.http(b"""GET / HTTP/1.1\n""", raw=True, read_timeout=5)

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 400 0 "-" "-"'),
            'partial 4',
        )

    @unittest.skip('not yet')
    def test_access_log_partial_5(self):
        self.load('empty')

        self.assertEqual(self.post()['status'], 200, 'init')

        self.get(headers={'Connection': 'close'})

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 400 \d+ "-" "-"'),
            'partial 5',
        )

    def test_access_log_get_parameters(self):
        self.load('empty')

        self.get(url='/?blah&var=val')

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(
                r'"GET /\?blah&var=val HTTP/1.1" 200 0 "-" "-"'
            ),
            'get parameters',
        )

    def test_access_log_delete(self):
        self.load('empty')

        self.conf_delete('access_log')

        self.get(url='/delete')

        self.stop()

        self.assertIsNone(
            self.search_in_log(r'/delete', 'access.log'), 'delete'
        )

    def test_access_log_change(self):
        self.load('empty')

        self.get()

        self.conf('"' + self.testdir + '/new.log"', 'access_log')

        self.get()

        self.stop()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', 'new.log'),
            'change',
        )

    def test_access_log_reopen(self):
        self.load('empty')

        log_path = self.testdir + '/access.log'

        self.assertTrue(self.waitforfiles(log_path), 'open')

        log_path_new = self.testdir + '/new.log'

        os.rename(log_path, log_path_new)

        self.get()

        self.assertIsNotNone(
            self.wait_for_record(r'"GET / HTTP/1.1" 200 0 "-" "-"', 'new.log'),
            'rename new',
        )
        self.assertFalse(os.path.isfile(log_path), 'rename old')

        with open(self.testdir + '/unit.pid', 'r') as f:
            pid = f.read().rstrip()

        call(['kill', '-s', 'USR1', pid])

        self.assertTrue(self.waitforfiles(log_path), 'reopen')

        self.get(url='/usr1')

        self.assertIsNotNone(
            self.wait_for_record(r'"GET /usr1 HTTP/1.1" 200 0 "-" "-"'),
            'reopen 2',
        )
        self.assertIsNone(
            self.search_in_log(r'/usr1', 'new.log'), 'rename new 2'
        )


if __name__ == '__main__':
    TestAccessLog.main()
