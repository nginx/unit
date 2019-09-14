from unit.applications.tls import TestApplicationTLS


class TestRoutingTLS(TestApplicationTLS):
    prerequisites = {'modules': ['python', 'openssl']}

    def test_routes_match_scheme(self):
        self.certificate()

        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "routes"},
                        "*:7081": {
                            "pass": "routes",
                            "tls": {"certificate": 'default'},
                        },
                    },
                    "routes": [
                        {
                            "match": {"scheme": "http"},
                            "action": {"pass": "applications/empty"},
                        },
                        {
                            "match": {"scheme": "https"},
                            "action": {"pass": "applications/204_no_content"},
                        },
                    ],
                    "applications": {
                        "empty": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + "/python/empty",
                            "module": "wsgi",
                        },
                        "204_no_content": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir
                            + "/python/204_no_content",
                            "module": "wsgi",
                        },
                    },
                }
            ),
            'scheme configure',
        )

        self.assertEqual(self.get()['status'], 200, 'scheme http')
        self.assertEqual(
            self.get_ssl(port=7081)['status'], 204, 'scheme https'
        )


if __name__ == '__main__':
    TestRoutingTLS.main()
