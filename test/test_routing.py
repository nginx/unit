import unittest
from unit.applications.proto import TestApplicationProto


class TestRouting(TestApplicationProto):
    prerequisites = ['python']

    def setUp(self):
        super().setUp()

        self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {
                        "match": {"method": "GET"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                "applications": {
                    "empty": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": self.current_dir + '/python/empty',
                        "working_directory": self.current_dir
                        + '/python/empty',
                        "module": "wsgi",
                    },
                    "mirror": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": self.current_dir + '/python/mirror',
                        "working_directory": self.current_dir
                        + '/python/mirror',
                        "module": "wsgi",
                    },
                },
            }
        )

    def test_routes_match_method_positive(self):
        self.assertEqual(self.get()['status'], 200, 'method positive GET')
        self.assertEqual(self.post()['status'], 404, 'method positive POST')

    def test_routes_match_method_positive_many(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": ["GET", "POST"]},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method positive many configure',
        )

        self.assertEqual(self.get()['status'], 200, 'method positive many GET')
        self.assertEqual(
            self.post()['status'], 200, 'method positive many POST'
        )
        self.assertEqual(
            self.delete()['status'], 404, 'method positive many DELETE'
        )

    def test_routes_match_method_negative(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "!GET"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method negative configure',
        )

        self.assertEqual(self.get()['status'], 404, 'method negative GET')
        self.assertEqual(self.post()['status'], 200, 'method negative POST')

    def test_routes_match_method_negative_many(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": ["!GET", "!POST"]},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method negative many configure',
        )

        self.assertEqual(self.get()['status'], 404, 'method negative many GET')
        self.assertEqual(
            self.post()['status'], 404, 'method negative many POST'
        )
        self.assertEqual(
            self.delete()['status'], 200, 'method negative many DELETE'
        )

    def test_routes_match_method_wildcard_left(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "*ET"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method wildcard left configure',
        )

        self.assertEqual(self.get()['status'], 200, 'method wildcard left GET')
        self.assertEqual(
            self.post()['status'], 404, 'method wildcard left POST'
        )

    def test_routes_match_method_wildcard_right(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "GE*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method wildcard right configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'method wildcard right GET'
        )
        self.assertEqual(
            self.post()['status'], 404, 'method wildcard right POST'
        )

    def test_routes_match_method_wildcard_left_right(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "*GET*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method wildcard left right configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'method wildcard right GET'
        )
        self.assertEqual(
            self.post()['status'], 404, 'method wildcard right POST'
        )

    def test_routes_match_method_wildcard(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method wildcard configure',
        )

        self.assertEqual(self.get()['status'], 200, 'method wildcard')

    def test_routes_match_invalid(self):
        self.assertIn(
            'error',
            self.conf(
                [
                    {
                        "match": {"method": "**"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'wildcard invalid',
        )

        self.assertIn(
            'error',
            self.conf(
                [
                    {
                        "match": {"method": "blah**"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'wildcard invalid 2',
        )

        self.assertIn(
            'error',
            self.conf(
                [
                    {
                        "match": {"host": "*blah*blah"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'wildcard invalid 3',
        )

        self.assertIn(
            'error',
            self.conf(
                [
                    {
                        "match": {"host": "blah*blah*blah"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'wildcard invalid 4',
        )

        self.assertIn(
            'error',
            self.conf(
                [
                    {
                        "match": {"host": "blah*blah*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'wildcard invalid 5',
        )

    def test_routes_match_wildcard_middle(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "ex*le"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'host wildcard middle configure',
        )

        self.assertEqual(
            self.get(headers={'Host': 'example', 'Connection': 'close'})[
                'status'
            ],
            200,
            'host wildcard middle',
        )

        self.assertEqual(
            self.get(headers={'Host': 'www.example', 'Connection': 'close'})[
                'status'
            ],
            404,
            'host wildcard middle 2',
        )

        self.assertEqual(
            self.get(headers={'Host': 'example.com', 'Connection': 'close'})[
                'status'
            ],
            404,
            'host wildcard middle 3',
        )

        self.assertEqual(
            self.get(headers={'Host': 'exampl', 'Connection': 'close'})[
                'status'
            ],
            404,
            'host wildcard middle 4',
        )

    def test_routes_match_method_case_insensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "get"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'method case insensitive configure',
        )

        self.assertEqual(self.get()['status'], 200, 'method case insensitive')

    def test_routes_match_wildcard_left_case_insensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "*et"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match wildcard case insensitive'
        )

    def test_routes_match_wildcard_middle_case_insensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "g*t"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match wildcard case insensitive'
        )

    def test_routes_match_wildcard_right_case_insensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "get*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match wildcard case insensitive'
        )

    def test_routes_match_wildcard_substring_case_insensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "*et*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard substring case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'],
            200,
            'match wildcard substring case insensitive',
        )

    def test_routes_match_wildcard_left_case_sensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "*blah"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard left case sensitive configure',
        )

        self.assertEqual(
            self.get(url='/blah')['status'],
            200,
            'match wildcard left case sensitive /blah',
        )

        self.assertEqual(
            self.get(url='/BLAH')['status'],
            404,
            'match wildcard left case sensitive /BLAH',
        )

    def test_routes_match_wildcard_middle_case_sensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "/b*h"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard middle case sensitive configure',
        )

        self.assertEqual(
            self.get(url='/blah')['status'],
            200,
            'match wildcard middle case sensitive /blah',
        )

        self.assertEqual(
            self.get(url='/BLAH')['status'],
            404,
            'match wildcard middle case sensitive /BLAH',
        )

    def test_routes_match_wildcard_right_case_sensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "/bla*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard right case sensitive configure',
        )

        self.assertEqual(
            self.get(url='/blah')['status'],
            200,
            'match wildcard right case sensitive /blah',
        )

        self.assertEqual(
            self.get(url='/BLAH')['status'],
            404,
            'match wildcard right case sensitive /BLAH',
        )

    def test_routes_match_wildcard_substring_case_sensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "*bla*"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match wildcard substring case sensitive configure',
        )

        self.assertEqual(
            self.get(url='/blah')['status'],
            200,
            'match wildcard substring case sensitive /blah',
        )

        self.assertEqual(
            self.get(url='/BLAH')['status'],
            404,
            'match wildcard substring case sensitive /BLAH',
        )

    def test_routes_absent(self):
        self.conf(
            {
                "listeners": {"*:7081": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": self.current_dir + '/python/empty',
                        "working_directory": self.current_dir
                        + '/python/empty',
                        "module": "wsgi",
                    }
                },
            }
        )

        self.assertEqual(self.get(port=7081)['status'], 200, 'routes absent')

    def test_routes_pass_invalid(self):
        self.assertIn(
            'error',
            self.conf({"pass": "routes/blah"}, 'listeners/*:7080'),
            'routes invalid',
        )

    def test_route_empty(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes/main"}},
                    "routes": {"main": []},
                    "applications": {
                        "empty": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + '/python/empty',
                            "working_directory": self.current_dir
                            + '/python/empty',
                            "module": "wsgi",
                        },
                        "mirror": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + '/python/mirror',
                            "working_directory": self.current_dir
                            + '/python/mirror',
                            "module": "wsgi",
                        },
                    },
                }
            ),
            'route empty configure',
        )

        self.assertEqual(self.get()['status'], 404, 'route empty')

    def test_routes_route_empty(self):
        self.assertIn(
            'success',
            self.conf({}, 'listeners'),
            'routes empty listeners configure',
        )

        self.assertIn(
            'success', self.conf({}, 'routes'), 'routes empty configure'
        )

    def test_routes_route_match_absent(self):
        self.assertIn(
            'success',
            self.conf([{"action": {"pass": "applications/empty"}}], 'routes'),
            'route match absent configure',
        )

        self.assertEqual(self.get()['status'], 200, 'route match absent')

    def test_routes_route_action_absent(self):
        self.skip_alerts.append(r'failed to apply new conf')

        self.assertIn(
            'error',
            self.conf([{"match": {"method": "GET"}}], 'routes'),
            'route pass absent configure',
        )

    def test_routes_route_pass_absent(self):
        self.skip_alerts.append(r'failed to apply new conf')

        self.assertIn(
            'error',
            self.conf([{"match": {"method": "GET"}, "action": {}}], 'routes'),
            'route pass absent configure',
        )

    def test_routes_rules_two(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "GET"},
                        "action": {"pass": "applications/empty"},
                    },
                    {
                        "match": {"method": "POST"},
                        "action": {"pass": "applications/mirror"},
                    },
                ],
                'routes',
            ),
            'rules two configure',
        )

        self.assertEqual(self.get()['status'], 200, 'rules two match first')
        self.assertEqual(
            self.post(
                headers={
                    'Host': 'localhost',
                    'Content-Type': 'text/html',
                    'Connection': 'close',
                },
                body='X',
            )['status'],
            200,
            'rules two match second',
        )

    def test_routes_two(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes/first"}},
                    "routes": {
                        "first": [
                            {
                                "match": {"method": "GET"},
                                "action": {"pass": "routes/second"},
                            }
                        ],
                        "second": [
                            {
                                "match": {"host": "localhost"},
                                "action": {"pass": "applications/empty"},
                            }
                        ],
                    },
                    "applications": {
                        "empty": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + '/python/empty',
                            "working_directory": self.current_dir
                            + '/python/empty',
                            "module": "wsgi",
                        }
                    },
                }
            ),
            'routes two configure',
        )

        self.assertEqual(self.get()['status'], 200, 'routes two')

    def test_routes_match_host_positive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "localhost"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host positive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match host positive localhost'
        )

        self.assertEqual(
            self.get(headers={'Host': 'localhost.', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host positive trailing dot',
        )

        self.assertEqual(
            self.get(headers={'Host': 'www.localhost', 'Connection': 'close'})[
                'status'
            ],
            404,
            'match host positive www.localhost',
        )

        self.assertEqual(
            self.get(headers={'Host': 'localhost1', 'Connection': 'close'})[
                'status'
            ],
            404,
            'match host positive localhost1',
        )

        self.assertEqual(
            self.get(headers={'Host': 'example.com', 'Connection': 'close'})[
                'status'
            ],
            404,
            'match host positive example.com',
        )

    @unittest.skip('not yet')
    def test_routes_match_host_absent(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "localhost"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host absent configure',
        )

        self.assertEqual(
            self.get(headers={'Connection': 'close'})['status'],
            400,
            'match host absent',
        )

    def test_routes_match_host_ipv4(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "127.0.0.1"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host ipv4 configure',
        )

        self.assertEqual(
            self.get(headers={'Host': '127.0.0.1', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host ipv4',
        )

    def test_routes_match_host_ipv6(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "[::1]"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host ipv6 configure',
        )

        self.assertEqual(
            self.get(headers={'Host': '[::1]', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host ipv6',
        )

        self.assertEqual(
            self.get(headers={'Host': '[::1]:7080', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host ipv6 port',
        )

    def test_routes_match_host_positive_many(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": ["localhost", "example.com"]},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host positive many configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match host positive many localhost'
        )

        self.assertEqual(
            self.get(headers={'Host': 'example.com', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host positive many example.com',
        )

    def test_routes_match_host_positive_and_negative(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {
                            "host": ["*example.com", "!www.example.com"]
                        },
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host positive and negative configure',
        )

        self.assertEqual(
            self.get()['status'],
            404,
            'match host positive and negative localhost',
        )

        self.assertEqual(
            self.get(headers={'Host': 'example.com', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host positive and negative example.com',
        )

        self.assertEqual(
            self.get(
                headers={'Host': 'www.example.com', 'Connection': 'close'}
            )['status'],
            404,
            'match host positive and negative www.example.com',
        )

        self.assertEqual(
            self.get(
                headers={'Host': '!www.example.com', 'Connection': 'close'}
            )['status'],
            200,
            'match host positive and negative !www.example.com',
        )

    def test_routes_match_host_positive_and_negative_wildcard(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": ["*example*", "!www.example*"]},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host positive and negative wildcard configure',
        )

        self.assertEqual(
            self.get(headers={'Host': 'example.com', 'Connection': 'close'})[
                'status'
            ],
            200,
            'match host positive and negative wildcard example.com',
        )

        self.assertEqual(
            self.get(
                headers={'Host': 'www.example.com', 'Connection': 'close'}
            )['status'],
            404,
            'match host positive and negative wildcard www.example.com',
        )

    def test_routes_match_host_case_insensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "Example.com"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'host case insensitive configure',
        )

        self.assertEqual(
            self.get(headers={'Host': 'example.com', 'Connection': 'close'})[
                'status'
            ],
            200,
            'host case insensitive example.com',
        )

        self.assertEqual(
            self.get(headers={'Host': 'EXAMPLE.COM', 'Connection': 'close'})[
                'status'
            ],
            200,
            'host case insensitive EXAMPLE.COM',
        )

    def test_routes_match_host_port(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": "example.com"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host port configure',
        )

        self.assertEqual(
            self.get(
                headers={'Host': 'example.com:7080', 'Connection': 'close'}
            )['status'],
            200,
            'match host port',
        )

    def test_routes_match_host_empty(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"host": ""},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match host empty configure',
        )

        self.assertEqual(
            self.get(headers={'Host': '', 'Connection': 'close'})['status'],
            200,
            'match host empty',
        )
        self.assertEqual(
            self.get(http_10=True, headers={})['status'],
            200,
            'match host empty 2',
        )
        self.assertEqual(self.get()['status'], 404, 'match host empty 3')

    def test_routes_match_uri_positive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "/"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match uri positive configure',
        )

        self.assertEqual(self.get()['status'], 200, 'match uri positive')
        self.assertEqual(
            self.get(url='/blah')['status'], 404, 'match uri positive blah'
        )
        self.assertEqual(
            self.get(url='/#blah')['status'], 200, 'match uri positive #blah'
        )
        self.assertEqual(
            self.get(url='/?var')['status'], 200, 'match uri params'
        )
        self.assertEqual(
            self.get(url='//')['status'], 200, 'match uri adjacent slashes'
        )
        self.assertEqual(
            self.get(url='/blah/../')['status'], 200, 'match uri relative path'
        )
        self.assertEqual(
            self.get(url='/./')['status'], 200, 'match uri relative path'
        )

    def test_routes_match_uri_case_sensitive(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "/BLAH"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match uri case sensitive configure',
        )

        self.assertEqual(
            self.get(url='/blah')['status'],
            404,
            'match uri case sensitive blah',
        )
        self.assertEqual(
            self.get(url='/BlaH')['status'],
            404,
            'match uri case sensitive BlaH',
        )
        self.assertEqual(
            self.get(url='/BLAH')['status'],
            200,
            'match uri case sensitive BLAH',
        )

    def test_routes_match_uri_normalize(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": "/blah"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match uri normalize configure',
        )

        self.assertEqual(
            self.get(url='/%62%6c%61%68')['status'], 200, 'match uri normalize'
        )

    def test_routes_match_empty_array(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"uri": []},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match empty array configure',
        )

        self.assertEqual(
            self.get(url='/blah')['status'],
            200,
            'match empty array',
        )

    def test_routes_reconfigure(self):
        self.assertIn('success', self.conf([], 'routes'), 'routes redefine')
        self.assertEqual(self.get()['status'], 404, 'routes redefine request')

        self.assertIn(
            'success',
            self.conf([{"action": {"pass": "applications/empty"}}], 'routes'),
            'routes redefine 2',
        )
        self.assertEqual(
            self.get()['status'], 200, 'routes redefine request 2'
        )

        self.assertIn('success', self.conf([], 'routes'), 'routes redefine 3')
        self.assertEqual(
            self.get()['status'], 404, 'routes redefine request 3'
        )

        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes/main"}},
                    "routes": {
                        "main": [{"action": {"pass": "applications/empty"}}]
                    },
                    "applications": {
                        "empty": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + '/python/empty',
                            "working_directory": self.current_dir
                            + '/python/empty',
                            "module": "wsgi",
                        }
                    },
                }
            ),
            'routes redefine 4',
        )
        self.assertEqual(
            self.get()['status'], 200, 'routes redefine request 4'
        )

        self.assertIn(
            'success', self.conf_delete('routes/main/0'), 'routes redefine 5'
        )
        self.assertEqual(
            self.get()['status'], 404, 'routes redefine request 5'
        )

        self.assertIn(
            'success',
            self.conf_post(
                {"action": {"pass": "applications/empty"}}, 'routes/main'
            ),
            'routes redefine 6',
        )
        self.assertEqual(
            self.get()['status'], 200, 'routes redefine request 6'
        )

        self.assertIn(
            'error',
            self.conf(
                {"action": {"pass": "applications/empty"}}, 'routes/main/2'
            ),
            'routes redefine 7',
        )
        self.assertIn(
            'success',
            self.conf(
                {"action": {"pass": "applications/empty"}}, 'routes/main/1'
            ),
            'routes redefine 8',
        )

        self.assertEqual(
            len(self.conf_get('routes/main')), 2, 'routes redefine conf 8'
        )
        self.assertEqual(
            self.get()['status'], 200, 'routes redefine request 8'
        )

    def test_routes_edit(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": "GET"},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'routes edit configure',
        )

        self.assertEqual(self.get()['status'], 200, 'routes edit GET')
        self.assertEqual(self.post()['status'], 404, 'routes edit POST')

        self.assertIn(
            'success',
            self.conf_post(
                {
                    "match": {"method": "POST"},
                    "action": {"pass": "applications/empty"},
                },
                'routes',
            ),
            'routes edit configure 2',
        )
        self.assertEqual(
            'GET',
            self.conf_get('routes/0/match/method'),
            'routes edit configure 2 check',
        )
        self.assertEqual(
            'POST',
            self.conf_get('routes/1/match/method'),
            'routes edit configure 2 check 2',
        )

        self.assertEqual(self.get()['status'], 200, 'routes edit GET 2')
        self.assertEqual(self.post()['status'], 200, 'routes edit POST 2')

        self.assertIn(
            'success',
            self.conf_delete('routes/0'),
            'routes edit configure 3',
        )

        self.assertEqual(self.get()['status'], 404, 'routes edit GET 3')
        self.assertEqual(self.post()['status'], 200, 'routes edit POST 3')

        self.assertIn(
            'error',
            self.conf_delete('routes/1'),
            'routes edit configure invalid',
        )
        self.assertIn(
            'error',
            self.conf_delete('routes/-1'),
            'routes edit configure invalid 2',
        )
        self.assertIn(
            'error',
            self.conf_delete('routes/blah'),
            'routes edit configure invalid 3',
        )

        self.assertEqual(self.get()['status'], 404, 'routes edit GET 4')
        self.assertEqual(self.post()['status'], 200, 'routes edit POST 4')

        self.assertIn(
            'success',
            self.conf_delete('routes/0'),
            'routes edit configure 5',
        )

        self.assertEqual(self.get()['status'], 404, 'routes edit GET 5')
        self.assertEqual(self.post()['status'], 404, 'routes edit POST 5')

        self.assertIn(
            'success',
            self.conf_post(
                {
                    "match": {"method": "POST"},
                    "action": {"pass": "applications/empty"},
                },
                'routes',
            ),
            'routes edit configure 6',
        )

        self.assertEqual(self.get()['status'], 404, 'routes edit GET 6')
        self.assertEqual(self.post()['status'], 200, 'routes edit POST 6')

        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {"*:7080": {"pass": "routes/main"}},
                    "routes": {
                        "main": [{"action": {"pass": "applications/empty"}}]
                    },
                    "applications": {
                        "empty": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": self.current_dir + '/python/empty',
                            "working_directory": self.current_dir
                            + '/python/empty',
                            "module": "wsgi",
                        }
                    },
                }
            ),
            'route edit configure 7',
        )

        self.assertIn(
            'error',
            self.conf_delete('routes/0'),
            'routes edit configure invalid 4',
        )
        self.assertIn(
            'error',
            self.conf_delete('routes/main'),
            'routes edit configure invalid 5',
        )

        self.assertEqual(self.get()['status'], 200, 'routes edit GET 7')

        self.assertIn(
            'success',
            self.conf_delete('listeners/*:7080'),
            'route edit configure 8',
        )
        self.assertIn(
            'success',
            self.conf_delete('routes/main'),
            'route edit configure 9',
        )

    def test_match_edit(self):
        self.skip_alerts.append(r'failed to apply new conf')

        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {"method": ["GET", "POST"]},
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'match edit configure',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET')
        self.assertEqual(self.post()['status'], 200, 'match edit POST')
        self.assertEqual(self.put()['status'], 404, 'match edit PUT')

        self.assertIn(
            'success',
            self.conf_post('\"PUT\"', 'routes/0/match/method'),
            'match edit configure 2',
        )
        self.assertListEqual(
            ['GET', 'POST', 'PUT'],
            self.conf_get('routes/0/match/method'),
            'match edit configure 2 check',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 2')
        self.assertEqual(self.post()['status'], 200, 'match edit POST 2')
        self.assertEqual(self.put()['status'], 200, 'match edit PUT 2')

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/method/1'),
            'match edit configure 3',
        )
        self.assertListEqual(
            ['GET', 'PUT'],
            self.conf_get('routes/0/match/method'),
            'match edit configure 3 check',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 3')
        self.assertEqual(self.post()['status'], 404, 'match edit POST 3')
        self.assertEqual(self.put()['status'], 200, 'match edit PUT 3')

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/method/1'),
            'match edit configure 4',
        )
        self.assertListEqual(
            ['GET'],
            self.conf_get('routes/0/match/method'),
            'match edit configure 4 check',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 4')
        self.assertEqual(self.post()['status'], 404, 'match edit POST 4')
        self.assertEqual(self.put()['status'], 404, 'match edit PUT 4')

        self.assertIn(
            'error',
            self.conf_delete('routes/0/match/method/1'),
            'match edit configure invalid',
        )
        self.assertIn(
            'error',
            self.conf_delete('routes/0/match/method/-1'),
            'match edit configure invalid 2',
        )
        self.assertIn(
            'error',
            self.conf_delete('routes/0/match/method/blah'),
            'match edit configure invalid 3',
        )
        self.assertListEqual(
            ['GET'],
            self.conf_get('routes/0/match/method'),
            'match edit configure 5 check',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 5')
        self.assertEqual(self.post()['status'], 404, 'match edit POST 5')
        self.assertEqual(self.put()['status'], 404, 'match edit PUT 5')

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/method/0'),
            'match edit configure 6',
        )
        self.assertListEqual(
            [],
            self.conf_get('routes/0/match/method'),
            'match edit configure 6 check',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 6')
        self.assertEqual(self.post()['status'], 200, 'match edit POST 6')
        self.assertEqual(self.put()['status'], 200, 'match edit PUT 6')

        self.assertIn(
            'success',
            self.conf('"GET"', 'routes/0/match/method'),
            'match edit configure 7',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 7')
        self.assertEqual(self.post()['status'], 404, 'match edit POST 7')
        self.assertEqual(self.put()['status'], 404, 'match edit PUT 7')

        self.assertIn(
            'error',
            self.conf_delete('routes/0/match/method/0'),
            'match edit configure invalid 5',
        )
        self.assertIn(
            'error',
            self.conf({}, 'routes/0/action'),
            'match edit configure invalid 6',
        )

        self.assertIn(
            'success',
            self.conf({}, 'routes/0/match'),
            'match edit configure 8',
        )

        self.assertEqual(self.get()['status'], 200, 'match edit GET 8')

    def test_routes_match_rules(self):
        self.assertIn(
            'success',
            self.conf(
                [
                    {
                        "match": {
                            "method": "GET",
                            "host": "localhost",
                            "uri": "/",
                        },
                        "action": {"pass": "applications/empty"},
                    }
                ],
                'routes',
            ),
            'routes match rules configure',
        )

        self.assertEqual(self.get()['status'], 200, 'routes match rules')

    def test_routes_loop(self):
        self.assertIn(
            'success',
            self.conf(
                [{"match": {"uri": "/"}, "action": {"pass": "routes"}}],
                'routes',
            ),
            'routes loop configure',
        )

        self.assertEqual(self.get()['status'], 500, 'routes loop')


if __name__ == '__main__':
    TestRouting.main()
