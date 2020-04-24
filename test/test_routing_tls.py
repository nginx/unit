from unit.applications.tls import TestApplicationTLS


class TestRoutingTLS(TestApplicationTLS):
    prerequisites = {'modules': {'openssl': 'any'}}

    def test_routes_match_scheme_tls(self):
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
                            "action": {"return": 200},
                        },
                        {
                            "match": {"scheme": "https"},
                            "action": {"return": 201},
                        },
                    ],
                    "applications": {},
                }
            ),
            'scheme configure',
        )

        self.assertEqual(self.get()['status'], 200, 'http')
        self.assertEqual(self.get_ssl(port=7081)['status'], 201, 'https')


if __name__ == '__main__':
    TestRoutingTLS.main()
