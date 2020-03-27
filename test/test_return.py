import re
import unittest
from unit.applications.proto import TestApplicationProto


class TestReturn(TestApplicationProto):
    prerequisites = {}

    def setUp(self):
        super().setUp()

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        )

    def get_resps_sc(self, req=10):
        to_send = b"""GET / HTTP/1.1
Host: localhost

""" * (
            req - 1
        )

        to_send += b"""GET / HTTP/1.1
Host: localhost
Connection: close

"""

        return self.http(to_send, raw_resp=True, raw=True)

    def test_return(self):
        resp = self.get()
        self.assertEqual(resp['status'], 200)
        self.assertIn('Server', resp['headers'])
        self.assertIn('Date', resp['headers'])
        self.assertEqual(resp['headers']['Content-Length'], '0')
        self.assertEqual(resp['headers']['Connection'], 'close')
        self.assertEqual(resp['body'], '', 'body')

        resp = self.post(body='blah')
        self.assertEqual(resp['status'], 200)
        self.assertEqual(resp['body'], '', 'body')

        resp = self.get_resps_sc()
        self.assertEqual(len(re.findall('200 OK', resp)), 10)
        self.assertEqual(len(re.findall('Connection:', resp)), 1)
        self.assertEqual(len(re.findall('Connection: close', resp)), 1)

        resp = self.get(http_10=True)
        self.assertEqual(resp['status'], 200)
        self.assertIn('Server', resp['headers'])
        self.assertIn('Date', resp['headers'])
        self.assertEqual(resp['headers']['Content-Length'], '0')
        self.assertNotIn('Connection', resp['headers'])
        self.assertEqual(resp['body'], '', 'body')

    def test_return_update(self):
        self.assertIn('success', self.conf('0', 'routes/0/action/return'))

        resp = self.get()
        self.assertEqual(resp['status'], 0)
        self.assertEqual(resp['body'], '')

        self.assertIn('success', self.conf('404', 'routes/0/action/return'))

        resp = self.get()
        self.assertEqual(resp['status'], 404)
        self.assertNotEqual(resp['body'], '')

        self.assertIn('success', self.conf('598', 'routes/0/action/return'))

        resp = self.get()
        self.assertEqual(resp['status'], 598)
        self.assertNotEqual(resp['body'], '')

        self.assertIn('success', self.conf('999', 'routes/0/action/return'))

        resp = self.get()
        self.assertEqual(resp['status'], 999)
        self.assertEqual(resp['body'], '')

    def test_return_invalid(self):
        def check_error(conf):
            self.assertIn('error', self.conf(conf, 'routes/0/action'))

        check_error({"return": "200"})
        check_error({"return": []})
        check_error({"return": 80.})
        check_error({"return": 1000})
        check_error({"return": 200, "share": "/blah"})

        self.assertIn(
            'error', self.conf('001', 'routes/0/action/return'), 'leading zero'
        )


if __name__ == '__main__':
    TestReturn.main()
