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

    def test_return_location(self):
        reserved = ":/?#[]@!$&'()*+,;="
        unreserved = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                      "0123456789-._~")
        unsafe = " \"%<>\\^`{|}"
        unsafe_enc = "%20%22%25%3C%3E%5C%5E%60%7B%7C%7D"

        def check_location(location, expect=None):
            if expect is None:
                expect = location

            self.assertIn(
                'success',
                self.conf(
                    {"return": 301, "location": location}, 'routes/0/action'
                ),
                'configure location'
            )

            self.assertEqual(self.get()['headers']['Location'], expect)

        # FAIL: can't specify empty header value.
        # check_location("")

        check_location(reserved)

        # After first "?" all other "?" encoded.
        check_location("/?" + reserved, "/?:/%3F#[]@!$&'()*+,;=")
        check_location("???", "?%3F%3F")

        # After first "#" all other "?" or "#" encoded.
        check_location("/#" + reserved, "/#:/%3F%23[]@!$&'()*+,;=")
        check_location("##?#?", "#%23%3F%23%3F")

        # After first "?" next "#" not encoded.
        check_location("/?#" + reserved, "/?#:/%3F%23[]@!$&'()*+,;=")
        check_location("??##", "?%3F#%23")
        check_location("/?##?", "/?#%23%3F")

        # Unreserved never encoded.
        check_location(unreserved)
        check_location("/" + unreserved + "?" + unreserved + "#" + unreserved)

        # Unsafe always encoded.
        check_location(unsafe, unsafe_enc)
        check_location("?" + unsafe, "?" + unsafe_enc)
        check_location("#" + unsafe, "#" + unsafe_enc)

        # %00-%20 and %7F-%FF always encoded.
        check_location(u"\u0000\u0018\u001F\u0020\u0021", "%00%18%1F%20!")
        check_location(u"\u007F\u0080н\u20BD", "%7F%C2%80%D0%BD%E2%82%BD")

        # Encoded string detection.  If at least one char need to be encoded
        # then whole string will be encoded.
        check_location("%20")
        check_location("/%20?%20#%20")
        check_location(" %20", "%20%2520")
        check_location("%20 ", "%2520%20")
        check_location("/%20?%20#%20 ", "/%2520?%2520#%2520%20")

    def test_return_location_edit(self):
        self.assertIn(
            'success',
            self.conf(
                {"return": 302, "location": "blah"}, 'routes/0/action'
            ),
            'configure init location'
        )
        self.assertEqual(self.get()['headers']['Location'], 'blah')

        self.assertIn(
            'success',
            self.conf_delete('routes/0/action/location'),
            'location delete'
        )
        self.assertNotIn('Location', self.get()['headers'])

        self.assertIn(
            'success',
            self.conf('"blah"', 'routes/0/action/location'),
            'location restore'
        )
        self.assertEqual(self.get()['headers']['Location'], 'blah')

        self.assertIn(
            'error',
            self.conf_post('"blah"', 'routes/0/action/location'),
            'location method not allowed'
        )
        self.assertEqual(self.get()['headers']['Location'], 'blah')

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

        check_error({"return": 301, "location": 0})
        check_error({"return": 301, "location": []})


if __name__ == '__main__':
    TestReturn.main()
