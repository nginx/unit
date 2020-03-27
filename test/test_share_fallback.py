import os
import unittest
from unit.applications.proto import TestApplicationProto


class TestStatic(TestApplicationProto):
    prerequisites = {}

    def setUp(self):
        super().setUp()

        os.makedirs(self.testdir + '/assets/dir')
        with open(self.testdir + '/assets/index.html', 'w') as index:
            index.write('0123456789')

        os.makedirs(self.testdir + '/assets/403')
        os.chmod(self.testdir + '/assets/403', 0o000)

        self._load_conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes"},
                    "*:7081": {"pass": "routes"},
                },
                "routes": [{"action": {"share": self.testdir + "/assets"}}],
                "applications": {},
            }
        )

    def tearDown(self):
        os.chmod(self.testdir + '/assets/403', 0o777)

        super().tearDown()

    def action_update(self, conf):
        self.assertIn('success', self.conf(conf, 'routes/0/action'))

    def test_fallback(self):
        self.action_update({"share": "/blah"})
        self.assertEqual(self.get()['status'], 404, 'bad path no fallback')

        self.action_update({"share": "/blah", "fallback": {"return": 200}})

        resp = self.get()
        self.assertEqual(resp['status'], 200, 'bad path fallback status')
        self.assertEqual(resp['body'], '', 'bad path fallback')

    def test_fallback_valid_path(self):
        self.action_update(
            {"share": self.testdir + "/assets", "fallback": {"return": 200}}
        )
        resp = self.get()
        self.assertEqual(resp['status'], 200, 'fallback status')
        self.assertEqual(resp['body'], '0123456789', 'fallback')

        resp = self.get(url='/403/')
        self.assertEqual(resp['status'], 200, 'fallback status 403')
        self.assertEqual(resp['body'], '', 'fallback 403')

        resp = self.post()
        self.assertEqual(resp['status'], 200, 'fallback status 405')
        self.assertEqual(resp['body'], '', 'fallback 405')

        self.assertEqual(
            self.get(url='/dir')['status'], 301, 'fallback status 301'
        )

    def test_fallback_nested(self):
        self.action_update(
            {
                "share": "/blah",
                "fallback": {
                    "share": "/blah/blah",
                    "fallback": {"return": 200},
                },
            }
        )

        resp = self.get()
        self.assertEqual(resp['status'], 200, 'fallback nested status')
        self.assertEqual(resp['body'], '', 'fallback nested')

    def test_fallback_share(self):
        self.action_update(
            {
                "share": "/blah",
                "fallback": {"share": self.testdir + "/assets"},
            }
        )

        resp = self.get()
        self.assertEqual(resp['status'], 200, 'fallback share status')
        self.assertEqual(resp['body'], '0123456789', 'fallback share')

        resp = self.head()
        self.assertEqual(resp['status'], 200, 'fallback share status HEAD')
        self.assertEqual(resp['body'], '', 'fallback share HEAD')

        self.assertEqual(
            self.get(url='/dir')['status'], 301, 'fallback share status 301'
        )

    def test_fallback_proxy(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"destination": "*:7081"},
                        "action": {"return": 200},
                    },
                    {
                        "action": {
                            "share": "/blah",
                            "fallback": {"proxy": "http://127.0.0.1:7081"},
                        }
                    },
                ],
                'routes',
            ),
            'configure fallback proxy route',
        )

        resp = self.get()
        self.assertEqual(resp['status'], 200, 'fallback proxy status')
        self.assertEqual(resp['body'], '', 'fallback proxy')

    @unittest.skip('not yet')
    def test_fallback_proxy_cycle(self):
        self.action_update(
            {
                "share": "/blah",
                "fallback": {"proxy": "http://127.0.0.1:7080"},
            }
        )
        self.assertNotEqual(self.get()['status'], 200, 'fallback cycle')

        self.assertIn('success', self.conf_delete('listeners/*:7081'))
        self.assertNotEqual(self.get()['status'], 200, 'fallback cycle 2')

    def test_fallback_invalid(self):
        def check_error(conf):
            self.assertIn('error', self.conf(conf, 'routes/0/action'))

        check_error({"share": "/blah", "fallback": {}})
        check_error({"share": "/blah", "fallback": ""})
        check_error({"return": 200, "fallback": {"share": "/blah"}})
        check_error(
            {"proxy": "http://127.0.0.1:7081", "fallback": {"share": "/blah"}}
        )
        check_error({"fallback": {"share": "/blah"}})


if __name__ == '__main__':
    TestStatic.main()
