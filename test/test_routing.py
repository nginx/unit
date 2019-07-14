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

    def route(self, route):
        return self.conf([route], 'routes')

    def test_routes_match_method_positive(self):
        self.assertEqual(self.get()['status'], 200, 'method positive GET')
        self.assertEqual(self.post()['status'], 404, 'method positive POST')

    def test_routes_match_method_positive_many(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"method": ["GET", "POST"]},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "!GET"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'method negative configure',
        )

        self.assertEqual(self.get()['status'], 404, 'method negative GET')
        self.assertEqual(self.post()['status'], 200, 'method negative POST')

    def test_routes_match_method_negative_many(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"method": ["!GET", "!POST"]},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "*ET"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "GE*"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "*GET*"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "*"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'method wildcard configure',
        )

        self.assertEqual(self.get()['status'], 200, 'method wildcard')

    def test_routes_match_invalid(self):
        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"method": "**"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'wildcard invalid',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"method": "blah**"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'wildcard invalid 2',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"host": "*blah*blah"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'wildcard invalid 3',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"host": "blah*blah*blah"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'wildcard invalid 4',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"host": "blah*blah*"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'wildcard invalid 5',
        )

    def test_routes_match_wildcard_middle(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"host": "ex*le"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "get"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'method case insensitive configure',
        )

        self.assertEqual(self.get()['status'], 200, 'method case insensitive')

    def test_routes_match_wildcard_left_case_insensitive(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"method": "*et"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match wildcard case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match wildcard case insensitive'
        )

    def test_routes_match_wildcard_middle_case_insensitive(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"method": "g*t"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match wildcard case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match wildcard case insensitive'
        )

    def test_routes_match_wildcard_right_case_insensitive(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"method": "get*"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match wildcard case insensitive configure',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match wildcard case insensitive'
        )

    def test_routes_match_wildcard_substring_case_insensitive(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"method": "*et*"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "*blah"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "/b*h"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "/bla*"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "*bla*"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": "localhost"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": "localhost"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": "127.0.0.1"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": "[::1]"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": ["localhost", "example.com"]},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": ["*example.com", "!www.example.com"]},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": ["*example*", "!www.example*"]},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": "Example.com"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": "example.com"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"host": ""},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "/"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "/BLAH"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"uri": "/blah"},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match uri normalize configure',
        )

        self.assertEqual(
            self.get(url='/%62%6c%61%68')['status'], 200, 'match uri normalize'
        )

    def test_routes_match_empty_array(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"uri": []},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": "GET"},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {"method": ["GET", "POST"]},
                    "action": {"pass": "applications/empty"},
                }
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
            self.route(
                {
                    "match": {
                        "method": "GET",
                        "host": "localhost",
                        "uri": "/",
                    },
                    "action": {"pass": "applications/empty"},
                }
            ),
            'routes match rules configure',
        )

        self.assertEqual(self.get()['status'], 200, 'routes match rules')

    def test_routes_loop(self):
        self.assertIn(
            'success',
            self.route({"match": {"uri": "/"}, "action": {"pass": "routes"}}),
            'routes loop configure',
        )

        self.assertEqual(self.get()['status'], 500, 'routes loop')

    def test_routes_match_headers(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {"host": "localhost"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers configure',
        )

        self.assertEqual(self.get()['status'], 200, 'match headers')
        self.assertEqual(
            self.get(
                headers={
                    "Host": "Localhost",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers case insensitive',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost.com",
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers exact',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "llocalhost",
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers exact 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "host",
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers exact 3',
        )

    def test_routes_match_headers_multiple(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {
                        "headers": {"host": "localhost", "x-blah": "test"}
                    },
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers multiple configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match headers multiple')

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "test",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers multiple 2',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "",
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers multiple 3',
        )

    def test_routes_match_headers_multiple_values(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {"x-blah": "test"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers multiple values configure',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "test", "test"],
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers multiple values',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "blah", "test"],
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers multiple values 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "", "test"],
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers multiple values 3',
        )

    def test_routes_match_headers_multiple_rules(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {"x-blah": ["test", "blah"]}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers multiple rules configure',
        )

        self.assertEqual(
            self.get()['status'], 404, 'match headers multiple rules'
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "test",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers multiple rules 2',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "blah",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers multiple rules 3',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "blah", "test"],
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers multiple rules 4',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["blah", ""],
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers multiple rules 5',
        )

    def test_routes_match_headers_case_insensitive(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {"X-BLAH": "TEST"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers case insensitive configure',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-blah": "test",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers case insensitive',
        )

    def test_routes_match_headers_invalid(self):
        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"headers": ["blah"]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers invalid',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"headers": {"foo": ["bar", {}]}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers invalid 2',
        )

    def test_routes_match_headers_empty_rule(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {"host": ""}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers empty rule configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match headers empty rule')

        self.assertEqual(
            self.get(headers={"Host": "", "Connection": "close"})['status'],
            200,
            'match headers empty rule 2',
        )

    def test_routes_match_headers_rule_field_empty(self):
        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"headers": {"": "blah"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers rule field empty configure',
        )

    def test_routes_match_headers_empty(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers empty configure',
        )

        self.assertEqual(self.get()['status'], 200, 'match headers empty')

        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": []},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers array empty configure 2',
        )

        self.assertEqual(
            self.get()['status'], 200, 'match headers array empty 2'
        )

    def test_routes_match_headers_rule_array_empty(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"headers": {"blah": []}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers rule array empty configure',
        )

        self.assertEqual(
            self.get()['status'], 404, 'match headers rule array empty'
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "blah": "foo",
                    "Connection": "close",
                }
            )['status'], 200, 'match headers rule array empty 2'
        )

    def test_routes_match_headers_array(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {
                        "headers": [
                            {"x-header1": "foo*"},
                            {"x-header2": "bar"},
                            {"x-header3": ["foo", "bar"]},
                            {"x-header1": "bar", "x-header4": "foo"},
                        ]
                    },
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match headers array configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match headers array')
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header1": "foo123",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers array 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header2": "bar",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers array 3',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header3": "bar",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers array 4',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header1": "bar",
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers array 5',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header1": "bar",
                    "x-header4": "foo",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers array 6',
        )

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/headers/1'),
            'match headers array configure 2',
        )

        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header2": "bar",
                    "Connection": "close",
                }
            )['status'],
            404,
            'match headers array 7',
        )
        self.assertEqual(
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header3": "foo",
                    "Connection": "close",
                }
            )['status'],
            200,
            'match headers array 8',
        )

    def test_routes_match_arguments(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {"foo": "bar"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match arguments')
        self.assertEqual(
            self.get(url='/?foo=bar')['status'], 200, 'match arguments 2'
        )

        self.assertEqual(
            self.get(url='/?Foo=bar')['status'],
            404,
            'match arguments case sensitive',
        )
        self.assertEqual(
            self.get(url='/?foo=Bar')['status'],
            404,
            'match arguments case sensitive 2',
        )
        self.assertEqual(
            self.get(url='/?foo=bar1')['status'],
            404,
            'match arguments exact',
        )
        self.assertEqual(
            self.get(url='/?1foo=bar')['status'],
            404,
            'match arguments exact 2',
        )

    def test_routes_match_arguments_empty(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments empty configure',
        )

        self.assertEqual(self.get()['status'], 200, 'match arguments empty')

        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": []},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments empty configure 2',
        )

        self.assertEqual(self.get()['status'], 200, 'match arguments empty 2')

    def test_routes_match_arguments_invalid(self):
        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"arguments": ["var"]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments invalid',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"arguments": [{"var1": {}}]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments invalid 2',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"arguments": {"": "bar"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments invalid 3',
        )

    @unittest.skip('not yet')
    def test_routes_match_arguments_space(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {"foo": "bar "}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments space configure',
        )

        self.assertEqual(
            self.get(url='/?foo=bar &')['status'],
            200,
            'match arguments space',
        )
        self.assertEqual(
            self.get(url='/?foo=bar+&')['status'],
            200,
            'match arguments space 2',
        ) # FAIL
        self.assertEqual(
            self.get(url='/?foo=bar%20&')['status'],
            200,
            'match arguments space 3',
        ) # FAIL

    @unittest.skip('not yet')
    def test_routes_match_arguments_plus(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": [{"foo": "bar+"}]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments plus configure',
        )

        self.assertEqual(
            self.get(url='/?foo=bar+&')['status'],
            200,
            'match arguments plus',
        )
        self.assertEqual(
            self.get(url='/?foo=bar%2B&')['status'],
            200,
            'match arguments plus 2',
        ) # FAIL

    @unittest.skip('not yet')
    def test_routes_match_arguments_hex(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": [{"foo": "bar"}]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments hex configure',
        )

        self.assertEqual(
            self.get(url='/?%66%6F%6f=%62%61%72&')['status'],
            200,
            'match arguments hex',
        ) # FAIL

    def test_routes_match_arguments_chars(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {"foo": "-._()[],;"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments chars configure',
        )

        self.assertEqual(
            self.get(url='/?foo=-._()[],;')['status'],
            200,
            'match arguments chars',
        )

    def test_routes_match_arguments_complex(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {"foo": ""}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments complex configure',
        )

        self.assertEqual(
            self.get(url='/?foo')['status'],
            200,
            'match arguments complex',
        )
        self.assertEqual(
            self.get(url='/?blah=blah&foo=')['status'],
            200,
            'match arguments complex 2',
        )
        self.assertEqual(
            self.get(url='/?&&&foo&&&')['status'],
            200,
            'match arguments complex 3',
        )
        self.assertEqual(
            self.get(url='/?foo&foo=bar&foo')['status'],
            404,
            'match arguments complex 4',
        )
        self.assertEqual(
            self.get(url='/?foo=&foo')['status'],
            200,
            'match arguments complex 5',
        )
        self.assertEqual(
            self.get(url='/?&=&foo&==&')['status'],
            200,
            'match arguments complex 6',
        )
        self.assertEqual(
            self.get(url='/?&=&bar&==&')['status'],
            404,
            'match arguments complex 7',
        )

    def test_routes_match_arguments_multiple(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {"foo": "bar", "blah": "test"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments multiple configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match arguments multiple')

        self.assertEqual(
            self.get(url='/?foo=bar&blah=test')['status'],
            200,
            'match arguments multiple 2',
        )

        self.assertEqual(
            self.get(url='/?foo=bar&blah')['status'],
            404,
            'match arguments multiple 3',
        )

    def test_routes_match_arguments_multiple_rules(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"arguments": {"foo": ["bar", "blah"]}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments multiple rules configure',
        )

        self.assertEqual(
            self.get()['status'], 404, 'match arguments multiple rules'
        )

        self.assertEqual(
            self.get(url='/?foo=bar')['status'],
            200,
            'match arguments multiple rules 2',
        )

        self.assertEqual(
            self.get(url='/?foo=blah')['status'],
            200,
            'match arguments multiple rules 3',
        )

        self.assertEqual(
            self.get(url='/?foo=blah&foo=bar&foo=blah')['status'],
            200,
            'match arguments multiple rules 4',
        )

        self.assertEqual(
            self.get(url='/?foo=blah&foo=bar&foo=')['status'],
            404,
            'match arguments multiple rules 5',
        )

    def test_routes_match_arguments_array(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {
                        "arguments": [
                            {"var1": "val1*"},
                            {"var2": "val2"},
                            {"var3": ["foo", "bar"]},
                            {"var1": "bar", "var4": "foo"},
                        ]
                    },
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match arguments array configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match arguments array')
        self.assertEqual(
            self.get(url='/?var1=val123')['status'],
            200,
            'match arguments array 2',
        )
        self.assertEqual(
            self.get(url='/?var2=val2')['status'],
            200,
            'match arguments array 3',
        )
        self.assertEqual(
            self.get(url='/?var3=bar')['status'],
            200,
            'match arguments array 4',
        )
        self.assertEqual(
            self.get(url='/?var1=bar')['status'],
            404,
            'match arguments array 5',
        )
        self.assertEqual(
            self.get(url='/?var1=bar&var4=foo')['status'],
            200,
            'match arguments array 6',
        )

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/arguments/1'),
            'match arguments array configure 2',
        )

        self.assertEqual(
            self.get(url='/?var2=val2')['status'],
            404,
            'match arguments array 7',
        )
        self.assertEqual(
            self.get(url='/?var3=foo')['status'],
            200,
            'match arguments array 8',
        )

    def test_routes_match_cookies(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"cookies": {"foO": "bar"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookie configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match cookie')
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foO=bar',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['foO=bar', 'blah=blah'],
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies 3',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foO=bar; blah=blah',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies 4',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'Foo=bar',
                    'Connection': 'close',
                },
            )['status'],
            404,
            'match cookies case sensitive',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foO=Bar',
                    'Connection': 'close',
                },
            )['status'],
            404,
            'match cookies case sensitive 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foO=bar1',
                    'Connection': 'close',
                },
            )['status'],
            404,
            'match cookies exact',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': '1foO=bar;',
                    'Connection': 'close',
                },
            )['status'],
            404,
            'match cookies exact 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foO=bar;1',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies exact 3',
        )

    def test_routes_match_cookies_empty(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"cookies": {}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies empty configure',
        )

        self.assertEqual(self.get()['status'], 200, 'match cookies empty')

        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"cookies": []},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies empty configure 2',
        )

        self.assertEqual(self.get()['status'], 200, 'match cookies empty 2')

    def test_routes_match_cookies_invalid(self):
        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"cookies": ["var"]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies invalid',
        )

        self.assertIn(
            'error',
            self.route(
                {
                    "match": {"cookies": [{"foo": {}}]},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies invalid 2',
        )

    def test_routes_match_cookies_multiple(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"cookies": {"foo": "bar", "blah": "blah"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies multiple configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match cookies multiple')

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'foo=bar; blah=blah',
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple 2',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['foo=bar', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple 3',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['foo=bar; blah', 'blah'],
                    'Connection': 'close',
                }
            )['status'],
            404,
            'match cookies multiple 4',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['foo=bar; blah=test', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            404,
            'match cookies multiple 5',
        )

    def test_routes_match_cookies_multiple_values(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"cookies": {"blah": "blah"}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies multiple values configure',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['blah=blah', 'blah=blah', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match headers multiple values',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['blah=blah', 'blah=test', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            404,
            'match cookies multiple values 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['blah=blah; blah=', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            404,
            'match cookies multiple values 3',
        )

    def test_routes_match_cookies_multiple_rules(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {"cookies": {"blah": ["test", "blah"]}},
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies multiple rules configure',
        )

        self.assertEqual(
            self.get()['status'], 404, 'match cookies multiple rules'
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'blah=test',
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple rules 2',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'blah=blah',
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple rules 3',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['blah=blah', 'blah=test', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple rules 4',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['blah=blah; blah=test', 'blah=blah'],
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple rules 5',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['blah=blah', 'blah'], # invalid cookie
                    'Connection': 'close',
                }
            )['status'],
            200,
            'match cookies multiple rules 6',
        )

    def test_routes_match_cookies_array(self):
        self.assertIn(
            'success',
            self.route(
                {
                    "match": {
                        "cookies": [
                            {"var1": "val1*"},
                            {"var2": "val2"},
                            {"var3": ["foo", "bar"]},
                            {"var1": "bar", "var4": "foo"},
                        ]
                    },
                    "action": {"pass": "applications/empty"},
                }
            ),
            'match cookies array configure',
        )

        self.assertEqual(self.get()['status'], 404, 'match cookies array')
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var1=val123',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 2',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var2=val2',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 3',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var3=bar',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 4',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var3=bar;',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 5',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var1=bar',
                    'Connection': 'close',
                },
            )['status'],
            404,
            'match cookies array 6',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var1=bar; var4=foo;',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 7',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': ['var1=bar', 'var4=foo'],
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 8',
        )

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/cookies/1'),
            'match cookies array configure 2',
        )

        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var2=val2',
                    'Connection': 'close',
                },
            )['status'],
            404,
            'match cookies array 9',
        )
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': 'var3=foo',
                    'Connection': 'close',
                },
            )['status'],
            200,
            'match cookies array 10',
        )

if __name__ == '__main__':
    TestRouting.main()
