import os
import unittest
from unit.applications.lang.python import TestApplicationPython


class TestStatic(TestApplicationPython):
    prerequisites = {'modules': ['python']}

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
                    "*:7081": {"pass": "applications/empty"},
                },
                "routes": [{"action": {"share": self.testdir + "/assets"}}],
                "applications": {
                    "empty": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": self.current_dir + "/python/empty",
                        "working_directory": self.current_dir
                        + "/python/empty",
                        "module": "wsgi",
                    }
                },
            }
        )

    def tearDown(self):
        os.chmod(self.testdir + '/assets/403', 0o777)

        super().tearDown()

    def test_fallback(self):
        self.assertIn(
            'success',
            self.conf({"share": "/blah"}, 'routes/0/action'),
            'configure bad path no fallback',
        )
        self.assertEqual(self.get()['status'], 404, 'bad path no fallback')

        self.assertIn(
            'success',
            self.conf(
                {"share": "/blah", "fallback": {"pass": "applications/empty"}},
                'routes/0/action',
            ),
            'configure bad path fallback',
        )
        resp = self.get()
        self.assertEqual(resp['status'], 200, 'bad path fallback status')
        self.assertEqual(resp['body'], '', 'bad path fallback')

    def test_fallback_valid_path(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "share": self.testdir + "/assets",
                    "fallback": {"pass": "applications/empty"},
                },
                'routes/0/action',
            ),
            'configure fallback',
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
        self.assertIn(
            'success',
            self.conf(
                {
                    "share": "/blah",
                    "fallback": {
                        "share": "/blah/blah",
                        "fallback": {"pass": "applications/empty"},
                    },
                },
                'routes/0/action',
            ),
            'configure fallback nested',
        )
        resp = self.get()
        self.assertEqual(resp['status'], 200, 'fallback nested status')
        self.assertEqual(resp['body'], '', 'fallback nested')

    def test_fallback_share(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "share": "/blah",
                    "fallback": {"share": self.testdir + "/assets"},
                },
                'routes/0/action',
            ),
            'configure fallback share',
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
                {
                    "share": "/blah",
                    "fallback": {"proxy": "http://127.0.0.1:7081"},
                },
                'routes/0/action',
            ),
            'configure fallback proxy',
        )
        resp = self.get()
        self.assertEqual(resp['status'], 200, 'fallback proxy status')
        self.assertEqual(resp['body'], '', 'fallback proxy')

    @unittest.skip('not yet')
    def test_fallback_proxy_cycle(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "share": "/blah",
                    "fallback": {"proxy": "http://127.0.0.1:7080"},
                },
                'routes/0/action',
            ),
            'configure fallback cycle',
        )
        self.assertNotEqual(self.get()['status'], 200, 'fallback cycle')

        self.assertIn(
            'success', self.conf_delete('listeners/*:7081'), 'delete listener'
        )
        self.assertNotEqual(self.get()['status'], 200, 'fallback cycle 2')

    def test_fallback_invalid(self):
        self.assertIn(
            'error',
            self.conf({"share": "/blah", "fallback": {}}, 'routes/0/action'),
            'configure fallback empty',
        )
        self.assertIn(
            'error',
            self.conf({"share": "/blah", "fallback": ""}, 'routes/0/action'),
            'configure fallback not object',
        )
        self.assertIn(
            'error',
            self.conf(
                {
                    "proxy": "http://127.0.0.1:7081",
                    "fallback": {"share": "/blah"},
                },
                'routes/0/action',
            ),
            'configure fallback proxy invalid',
        )
        self.assertIn(
            'error',
            self.conf(
                {
                    "pass": "applications/empty",
                    "fallback": {"share": "/blah"},
                },
                'routes/0/action',
            ),
            'configure fallback pass invalid',
        )
        self.assertIn(
            'error',
            self.conf({"fallback": {"share": "/blah"}}, 'routes/0/action'),
            'configure fallback only',
        )


if __name__ == '__main__':
    TestStatic.main()
