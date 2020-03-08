import unittest
from unit.applications.proto import TestApplicationProto


class TestRouting(TestApplicationProto):
    prerequisites = {'modules': ['python']}

    def setUp(self):
        super().setUp()

        self.assertIn(
            'success',
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
            ),
            'routing configure',
        )

    def route(self, route):
        return self.conf([route], 'routes')

    def route_match(self, match):
        self.assertIn(
            'success',
            self.route(
                {"match": match, "action": {"pass": "applications/empty"}}
            ),
            'route match configure',
        )

    def route_match_invalid(self, match):
        self.assertIn(
            'error',
            self.route(
                {"match": match, "action": {"pass": "applications/empty"}}
            ),
            'route match configure invalid',
        )

    def host(self, host, status):
        self.assertEqual(
            self.get(headers={'Host': host, 'Connection': 'close'})[
                'status'
            ],
            status,
            'match host',
        )

    def cookie(self, cookie, status):
        self.assertEqual(
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': cookie,
                    'Connection': 'close',
                },
            )['status'],
            status,
            'match cookie',
        )

    def test_routes_match_method_positive(self):
        self.assertEqual(self.get()['status'], 200, 'GET')
        self.assertEqual(self.post()['status'], 404, 'POST')

    def test_routes_match_method_positive_many(self):
        self.route_match({"method": ["GET", "POST"]})

        self.assertEqual(self.get()['status'], 200, 'GET')
        self.assertEqual(self.post()['status'], 200, 'POST')
        self.assertEqual(self.delete()['status'], 404, 'DELETE')

    def test_routes_match_method_negative(self):
        self.route_match({"method": "!GET"})

        self.assertEqual(self.get()['status'], 404, 'GET')
        self.assertEqual(self.post()['status'], 200, 'POST')

    def test_routes_match_method_negative_many(self):
        self.route_match({"method": ["!GET", "!POST"]})

        self.assertEqual(self.get()['status'], 404, 'GET')
        self.assertEqual(self.post()['status'], 404, 'POST')
        self.assertEqual(self.delete()['status'], 200, 'DELETE')

    def test_routes_match_method_wildcard_left(self):
        self.route_match({"method": "*ET"})

        self.assertEqual(self.get()['status'], 200, 'GET')
        self.assertEqual(self.post()['status'], 404, 'POST')

    def test_routes_match_method_wildcard_right(self):
        self.route_match({"method": "GE*"})

        self.assertEqual(self.get()['status'], 200, 'GET')
        self.assertEqual(self.post()['status'], 404, 'POST')

    def test_routes_match_method_wildcard_left_right(self):
        self.route_match({"method": "*GET*"})

        self.assertEqual(self.get()['status'], 200, 'GET')
        self.assertEqual(self.post()['status'], 404, 'POST')

    def test_routes_match_method_wildcard(self):
        self.route_match({"method": "*"})

        self.assertEqual(self.get()['status'], 200, 'GET')

    def test_routes_match_invalid(self):
        self.route_match_invalid({"method": "**"})
        self.route_match_invalid({"method": "blah**"})
        self.route_match_invalid({"host": "*blah*blah"})
        self.route_match_invalid({"host": "blah*blah*blah"})
        self.route_match_invalid({"host": "blah*blah*"})

    def test_routes_match_wildcard_middle(self):
        self.route_match({"host": "ex*le"})

        self.host('example', 200)
        self.host('www.example', 404)
        self.host('example.com', 404)
        self.host('exampl', 404)

    def test_routes_match_method_case_insensitive(self):
        self.route_match({"method": "get"})

        self.assertEqual(self.get()['status'], 200, 'GET')

    def test_routes_match_wildcard_left_case_insensitive(self):
        self.route_match({"method": "*get"})
        self.assertEqual(self.get()['status'], 200, 'GET')

        self.route_match({"method": "*et"})
        self.assertEqual(self.get()['status'], 200, 'GET')

    def test_routes_match_wildcard_middle_case_insensitive(self):
        self.route_match({"method": "g*t"})

        self.assertEqual(self.get()['status'], 200, 'GET')

    def test_routes_match_wildcard_right_case_insensitive(self):
        self.route_match({"method": "get*"})
        self.assertEqual(self.get()['status'], 200, 'GET')

        self.route_match({"method": "ge*"})
        self.assertEqual(self.get()['status'], 200, 'GET')

    def test_routes_match_wildcard_substring_case_insensitive(self):
        self.route_match({"method": "*et*"})

        self.assertEqual(self.get()['status'], 200, 'GET')

    def test_routes_match_wildcard_left_case_sensitive(self):
        self.route_match({"uri": "*blah"})

        self.assertEqual(self.get(url='/blah')['status'], 200, '/blah')
        self.assertEqual(self.get(url='/BLAH')['status'], 404, '/BLAH')

    def test_routes_match_wildcard_middle_case_sensitive(self):
        self.route_match({"uri": "/b*h"})

        self.assertEqual(self.get(url='/blah')['status'], 200, '/blah')
        self.assertEqual(self.get(url='/BLAH')['status'], 404, '/BLAH')

    def test_routes_match_wildcard_right_case_sensitive(self):
        self.route_match({"uri": "/bla*"})

        self.assertEqual(self.get(url='/blah')['status'], 200, '/blah')
        self.assertEqual(self.get(url='/BLAH')['status'], 404, '/BLAH')

    def test_routes_match_wildcard_substring_case_sensitive(self):
        self.route_match({"uri": "*bla*"})

        self.assertEqual(self.get(url='/blah')['status'], 200, '/blah')
        self.assertEqual(self.get(url='/BLAH')['status'], 404, '/BLAH')

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
        self.assertIn(
            'error',
            self.conf([{"match": {"method": "GET"}, "action": {}}], 'routes'),
            'route pass absent configure',
        )

    def test_routes_action_unique(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "routes"},
                        "*:7081": {"pass": "applications/app"},
                    },
                    "routes": [{"action": {"proxy": "http://127.0.0.1:7081"}}],
                    "applications": {
                        "app": {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": "/app",
                            "module": "wsgi",
                        }
                    },
                }
            ),
        )

        self.assertIn(
            'error',
            self.conf(
                {"proxy": "http://127.0.0.1:7081", "share": self.testdir},
                'routes/0/action',
            ),
            'proxy share',
        )
        self.assertIn(
            'error',
            self.conf(
                {
                    "proxy": "http://127.0.0.1:7081",
                    "pass": "applications/app",
                },
                'routes/0/action',
            ),
            'proxy pass',
        )
        self.assertIn(
            'error',
            self.conf(
                {"share": self.testdir, "pass": "applications/app"},
                'routes/0/action',
            ),
            'share pass',
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
        self.route_match({"host": "localhost"})

        self.assertEqual(self.get()['status'], 200, 'localhost')
        self.host('localhost.', 200)
        self.host('localhost.', 200)
        self.host('.localhost', 404)
        self.host('www.localhost', 404)
        self.host('localhost1', 404)

    @unittest.skip('not yet')
    def test_routes_match_host_absent(self):
        self.route_match({"host": "localhost"})

        self.assertEqual(
            self.get(headers={'Connection': 'close'})['status'],
            400,
            'match host absent',
        )

    def test_routes_match_host_ipv4(self):
        self.route_match({"host": "127.0.0.1"})

        self.host('127.0.0.1', 200)
        self.host('127.0.0.1:7080', 200)

    def test_routes_match_host_ipv6(self):
        self.route_match({"host": "[::1]"})

        self.host('[::1]', 200)
        self.host('[::1]:7080', 200)

    def test_routes_match_host_positive_many(self):
        self.route_match({"host": ["localhost", "example.com"]})

        self.assertEqual(self.get()['status'], 200, 'localhost')
        self.host('example.com', 200)

    def test_routes_match_host_positive_and_negative(self):
        self.route_match({"host": ["*example.com", "!www.example.com"]})

        self.assertEqual(self.get()['status'], 404, 'localhost')
        self.host('example.com', 200)
        self.host('www.example.com', 404)
        self.host('!www.example.com', 200)

    def test_routes_match_host_positive_and_negative_wildcard(self):
        self.route_match({"host": ["*example*", "!www.example*"]})

        self.host('example.com', 200)
        self.host('www.example.com', 404)

    def test_routes_match_host_case_insensitive(self):
        self.route_match({"host": "Example.com"})

        self.host('example.com', 200)
        self.host('EXAMPLE.COM', 200)

    def test_routes_match_host_port(self):
        self.route_match({"host": "example.com"})

        self.host('example.com:7080', 200)

    def test_routes_match_host_empty(self):
        self.route_match({"host": ""})

        self.host('', 200)
        self.assertEqual(
            self.get(http_10=True, headers={})['status'],
            200,
            'match host empty 2',
        )
        self.assertEqual(self.get()['status'], 404, 'match host empty 3')

    def test_routes_match_uri_positive(self):
        self.route_match({"uri": ["/blah", "/slash/"]})

        self.assertEqual(self.get()['status'], 404, '/')
        self.assertEqual(self.get(url='/blah')['status'], 200, '/blah')
        self.assertEqual(self.get(url='/blah#foo')['status'], 200, '/blah#foo')
        self.assertEqual(self.get(url='/blah?var')['status'], 200, '/blah?var')
        self.assertEqual(self.get(url='//blah')['status'], 200, '//blah')
        self.assertEqual(
            self.get(url='/slash/foo/../')['status'], 200, 'relative'
        )
        self.assertEqual(self.get(url='/slash/./')['status'], 200, '/slash/./')
        self.assertEqual(
            self.get(url='/slash//.//')['status'], 200, 'adjacent slashes'
        )
        self.assertEqual(self.get(url='/%')['status'], 400, 'percent')
        self.assertEqual(self.get(url='/%1')['status'], 400, 'percent digit')
        self.assertEqual(self.get(url='/%A')['status'], 400, 'percent letter')
        self.assertEqual(
            self.get(url='/slash/.?args')['status'], 200, 'dot args'
        )
        self.assertEqual(
            self.get(url='/slash/.#frag')['status'], 200, 'dot frag'
        )
        self.assertEqual(
            self.get(url='/slash/foo/..?args')['status'],
            200,
            'dot dot args',
        )
        self.assertEqual(
            self.get(url='/slash/foo/..#frag')['status'],
            200,
            'dot dot frag',
        )
        self.assertEqual(
            self.get(url='/slash/.')['status'], 200, 'trailing dot'
        )
        self.assertEqual(
            self.get(url='/slash/foo/..')['status'],
            200,
            'trailing dot dot',
        )

    def test_routes_match_uri_case_sensitive(self):
        self.route_match({"uri": "/BLAH"})

        self.assertEqual(self.get(url='/blah')['status'], 404, '/blah')
        self.assertEqual(self.get(url='/BlaH')['status'], 404, '/BlaH')
        self.assertEqual(self.get(url='/BLAH')['status'], 200, '/BLAH')

    def test_routes_match_uri_normalize(self):
        self.route_match({"uri": "/blah"})

        self.assertEqual(
            self.get(url='/%62%6c%61%68')['status'], 200, 'normalize'
        )

    def test_routes_match_empty_array(self):
        self.route_match({"uri": []})

        self.assertEqual(self.get(url='/blah')['status'], 200, 'empty array')

    def test_routes_reconfigure(self):
        self.assertIn('success', self.conf([], 'routes'), 'redefine')
        self.assertEqual(self.get()['status'], 404, 'redefine request')

        self.assertIn(
            'success',
            self.conf([{"action": {"pass": "applications/empty"}}], 'routes'),
            'redefine 2',
        )
        self.assertEqual(self.get()['status'], 200, 'redefine request 2')

        self.assertIn('success', self.conf([], 'routes'), 'redefine 3')
        self.assertEqual(self.get()['status'], 404, 'redefine request 3')

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
            'redefine 4',
        )
        self.assertEqual(self.get()['status'], 200, 'redefine request 4')

        self.assertIn(
            'success', self.conf_delete('routes/main/0'), 'redefine 5'
        )
        self.assertEqual(self.get()['status'], 404, 'redefine request 5')

        self.assertIn(
            'success',
            self.conf_post(
                {"action": {"pass": "applications/empty"}}, 'routes/main'
            ),
            'redefine 6',
        )
        self.assertEqual(self.get()['status'], 200, 'redefine request 6')

        self.assertIn(
            'error',
            self.conf(
                {"action": {"pass": "applications/empty"}}, 'routes/main/2'
            ),
            'redefine 7',
        )
        self.assertIn(
            'success',
            self.conf(
                {"action": {"pass": "applications/empty"}}, 'routes/main/1'
            ),
            'redefine 8',
        )

        self.assertEqual(
            len(self.conf_get('routes/main')), 2, 'redefine conf 8'
        )
        self.assertEqual(self.get()['status'], 200, 'redefine request 8')

    def test_routes_edit(self):
        self.route_match({"method": "GET"})

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

        self.route_match({"method": ["GET", "POST"]})

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
        self.route_match({"method": "GET", "host": "localhost", "uri": "/"})

        self.assertEqual(self.get()['status'], 200, 'routes match rules')

    def test_routes_loop(self):
        self.assertIn(
            'success',
            self.route({"match": {"uri": "/"}, "action": {"pass": "routes"}}),
            'routes loop configure',
        )

        self.assertEqual(self.get()['status'], 500, 'routes loop')

    def test_routes_match_headers(self):
        self.route_match({"headers": {"host": "localhost"}})

        self.assertEqual(self.get()['status'], 200, 'match headers')
        self.host('Localhost', 200)
        self.host('localhost.com', 404)
        self.host('llocalhost', 404)
        self.host('host', 404)

    def test_routes_match_headers_multiple(self):
        self.route_match({"headers": {"host": "localhost", "x-blah": "test"}})

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
        self.route_match({"headers": {"x-blah": "test"}})

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
        self.route_match({"headers": {"x-blah": ["test", "blah"]}})

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
        self.route_match({"headers": {"X-BLAH": "TEST"}})

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
        self.route_match_invalid({"headers": ["blah"]})
        self.route_match_invalid({"headers": {"foo": ["bar", {}]}})
        self.route_match_invalid({"headers": {"": "blah"}})

    def test_routes_match_headers_empty_rule(self):
        self.route_match({"headers": {"host": ""}})

        self.assertEqual(self.get()['status'], 404, 'localhost')
        self.host('', 200)

    def test_routes_match_headers_empty(self):
        self.route_match({"headers": {}})
        self.assertEqual(self.get()['status'], 200, 'empty')

        self.route_match({"headers": []})
        self.assertEqual(self.get()['status'], 200, 'empty 2')

    def test_routes_match_headers_rule_array_empty(self):
        self.route_match({"headers": {"blah": []}})

        self.assertEqual(self.get()['status'], 404, 'array empty')
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
        self.route_match(
            {
                "headers": [
                    {"x-header1": "foo*"},
                    {"x-header2": "bar"},
                    {"x-header3": ["foo", "bar"]},
                    {"x-header1": "bar", "x-header4": "foo"},
                ]
            }
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
        self.route_match({"arguments": {"foo": "bar"}})

        self.assertEqual(self.get()['status'], 404, 'args')
        self.assertEqual(self.get(url='/?foo=bar')['status'], 200, 'args 2')
        self.assertEqual(self.get(url='/?foo=bar1')['status'], 404, 'args 3')
        self.assertEqual(self.get(url='/?1foo=bar')['status'], 404, 'args 4')
        self.assertEqual(self.get(url='/?Foo=bar')['status'], 404, 'case')
        self.assertEqual(self.get(url='/?foo=Bar')['status'], 404, 'case 2')

    def test_routes_match_arguments_empty(self):
        self.route_match({"arguments": {}})
        self.assertEqual(self.get()['status'], 200, 'arguments empty')

        self.route_match({"arguments": []})
        self.assertEqual(self.get()['status'], 200, 'arguments empty 2')

    def test_routes_match_arguments_invalid(self):
        self.route_match_invalid({"arguments": ["var"]})
        self.route_match_invalid({"arguments": [{"var1": {}}]})
        self.route_match_invalid({"arguments": {"": "bar"}})

    @unittest.skip('not yet')
    def test_routes_match_arguments_space(self):
        self.route_match({"arguments": {"foo": "bar "}})

        self.assertEqual(self.get(url='/?foo=bar &')['status'], 200, 'sp')
        # FAIL
        self.assertEqual(self.get(url='/?foo=bar+&')['status'], 200, 'sp 2')
        # FAIL
        self.assertEqual(self.get(url='/?foo=bar%20&')['status'], 200, 'sp 3')

    @unittest.skip('not yet')
    def test_routes_match_arguments_plus(self):
        self.route_match({"arguments": [{"foo": "bar+"}]})

        self.assertEqual(self.get(url='/?foo=bar+&')['status'], 200, 'plus')
        # FAIL
        self.assertEqual(
            self.get(url='/?foo=bar%2B&')['status'], 200, 'plus 2'
        )

    @unittest.skip('not yet')
    def test_routes_match_arguments_hex(self):
        self.route_match({"arguments": [{"foo": "bar"}]})

        self.assertEqual(
            self.get(url='/?%66%6F%6f=%62%61%72&')['status'], 200, 'hex'
        )

    def test_routes_match_arguments_chars(self):
        self.route_match({"arguments": {"foo": "-._()[],;"}})

        self.assertEqual(self.get(url='/?foo=-._()[],;')['status'], 200, 'chs')

    def test_routes_match_arguments_complex(self):
        self.route_match({"arguments": {"foo": ""}})

        self.assertEqual(self.get(url='/?foo')['status'], 200, 'complex')
        self.assertEqual(
            self.get(url='/?blah=blah&foo=')['status'], 200, 'complex 2'
        )
        self.assertEqual(
            self.get(url='/?&&&foo&&&')['status'], 200, 'complex 3'
        )
        self.assertEqual(
            self.get(url='/?foo&foo=bar&foo')['status'], 404, 'complex 4'
        )
        self.assertEqual(
            self.get(url='/?foo=&foo')['status'], 200, 'complex 5'
        )
        self.assertEqual(
            self.get(url='/?&=&foo&==&')['status'], 200, 'complex 6'
        )
        self.assertEqual(
            self.get(url='/?&=&bar&==&')['status'], 404, 'complex 7'
        )

    def test_routes_match_arguments_multiple(self):
        self.route_match({"arguments": {"foo": "bar", "blah": "test"}})

        self.assertEqual(self.get()['status'], 404, 'multiple')
        self.assertEqual(
            self.get(url='/?foo=bar&blah=test')['status'], 200, 'multiple 2'
        )
        self.assertEqual(
            self.get(url='/?foo=bar&blah')['status'], 404, 'multiple 3'
        )

    def test_routes_match_arguments_multiple_rules(self):
        self.route_match({"arguments": {"foo": ["bar", "blah"]}})

        self.assertEqual(self.get()['status'], 404, 'rules')
        self.assertEqual(self.get(url='/?foo=bar')['status'], 200, 'rules 2')
        self.assertEqual(self.get(url='/?foo=blah')['status'], 200, 'rules 3')
        self.assertEqual(
            self.get(url='/?foo=blah&foo=bar&foo=blah')['status'],
            200,
            'rules 4',
        )
        self.assertEqual(
            self.get(url='/?foo=blah&foo=bar&foo=')['status'], 404, 'rules 5'
        )

    def test_routes_match_arguments_array(self):
        self.route_match(
            {
                "arguments": [
                    {"var1": "val1*"},
                    {"var2": "val2"},
                    {"var3": ["foo", "bar"]},
                    {"var1": "bar", "var4": "foo"},
                ]
            }
        )

        self.assertEqual(self.get()['status'], 404, 'arr')
        self.assertEqual(self.get(url='/?var1=val123')['status'], 200, 'arr 2')
        self.assertEqual(self.get(url='/?var2=val2')['status'], 200, 'arr 3')
        self.assertEqual(self.get(url='/?var3=bar')['status'], 200, 'arr 4')
        self.assertEqual(self.get(url='/?var1=bar')['status'], 404, 'arr 5')
        self.assertEqual(
            self.get(url='/?var1=bar&var4=foo')['status'], 200, 'arr 6'
        )

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/arguments/1'),
            'match arguments array configure 2',
        )

        self.assertEqual(self.get(url='/?var2=val2')['status'], 404, 'arr 7')
        self.assertEqual(self.get(url='/?var3=foo')['status'], 200, 'arr 8')

    def test_routes_match_cookies(self):
        self.route_match({"cookies": {"foO": "bar"}})

        self.assertEqual(self.get()['status'], 404, 'cookie')
        self.cookie('foO=bar', 200)
        self.cookie('foO=bar;1', 200)
        self.cookie(['foO=bar', 'blah=blah'], 200)
        self.cookie('foO=bar; blah=blah', 200)
        self.cookie('Foo=bar', 404)
        self.cookie('foO=Bar', 404)
        self.cookie('foO=bar1', 404)
        self.cookie('1foO=bar;', 404)

    def test_routes_match_cookies_empty(self):
        self.route_match({"cookies": {}})
        self.assertEqual(self.get()['status'], 200, 'cookies empty')

        self.route_match({"cookies": []})
        self.assertEqual(self.get()['status'], 200, 'cookies empty 2')

    def test_routes_match_cookies_invalid(self):
        self.route_match_invalid({"cookies": ["var"]})
        self.route_match_invalid({"cookies": [{"foo": {}}]})

    def test_routes_match_cookies_multiple(self):
        self.route_match({"cookies": {"foo": "bar", "blah": "blah"}})

        self.assertEqual(self.get()['status'], 404, 'multiple')
        self.cookie('foo=bar; blah=blah', 200)
        self.cookie(['foo=bar', 'blah=blah'], 200)
        self.cookie(['foo=bar; blah', 'blah'], 404)
        self.cookie(['foo=bar; blah=test', 'blah=blah'], 404)

    def test_routes_match_cookies_multiple_values(self):
        self.route_match({"cookies": {"blah": "blah"}})

        self.cookie(['blah=blah', 'blah=blah', 'blah=blah'], 200)
        self.cookie(['blah=blah', 'blah=test', 'blah=blah'], 404)
        self.cookie(['blah=blah; blah=', 'blah=blah'], 404)

    def test_routes_match_cookies_multiple_rules(self):
        self.route_match({"cookies": {"blah": ["test", "blah"]}})

        self.assertEqual(self.get()['status'], 404, 'multiple rules')
        self.cookie('blah=test', 200)
        self.cookie('blah=blah', 200)
        self.cookie(['blah=blah', 'blah=test', 'blah=blah'], 200)
        self.cookie(['blah=blah; blah=test', 'blah=blah'], 200)
        self.cookie(['blah=blah', 'blah'], 200) # invalid cookie

    def test_routes_match_cookies_array(self):
        self.route_match(
            {
                "cookies": [
                    {"var1": "val1*"},
                    {"var2": "val2"},
                    {"var3": ["foo", "bar"]},
                    {"var1": "bar", "var4": "foo"},
                ]
            }
        )

        self.assertEqual(self.get()['status'], 404, 'cookies array')
        self.cookie('var1=val123', 200)
        self.cookie('var2=val2', 200)
        self.cookie(' var2=val2 ', 200)
        self.cookie('var3=bar', 200)
        self.cookie('var3=bar;', 200)
        self.cookie('var1=bar', 404)
        self.cookie('var1=bar; var4=foo;', 200)
        self.cookie(['var1=bar', 'var4=foo'], 200)

        self.assertIn(
            'success',
            self.conf_delete('routes/0/match/cookies/1'),
            'match cookies array configure 2',
        )

        self.cookie('var2=val2', 404)
        self.cookie('var3=foo', 200)

    def test_routes_match_scheme(self):
        self.route_match({"scheme": "http"})
        self.route_match({"scheme": "https"})
        self.route_match({"scheme": "HtTp"})
        self.route_match({"scheme": "HtTpS"})

    def test_routes_match_scheme_invalid(self):
        self.route_match_invalid({"scheme": ["http"]})
        self.route_match_invalid({"scheme": "ftp"})
        self.route_match_invalid({"scheme": "ws"})
        self.route_match_invalid({"scheme": "*"})
        self.route_match_invalid({"scheme": ""})

    def test_routes_source_port(self):
        def sock_port():
            _, sock = self.http(b'', start=True, raw=True, no_recv=True)
            port = sock.getsockname()[1]
            return (sock, port)

        sock, port = sock_port()
        sock2, port2 = sock_port()

        self.route_match({"source": "127.0.0.1:" + str(port)})
        self.assertEqual(self.get(sock=sock)['status'], 200, 'exact')
        self.assertEqual(self.get(sock=sock2)['status'], 404, 'exact 2')

        sock, port = sock_port()
        sock2, port2 = sock_port()

        self.route_match({"source": "!127.0.0.1:" + str(port)})
        self.assertEqual(self.get(sock=sock)['status'], 404, 'negative')
        self.assertEqual(self.get(sock=sock2)['status'], 200, 'negative 2')

        sock, port = sock_port()
        sock2, port2 = sock_port()

        self.route_match(
            {"source": "127.0.0.1:" + str(port) + "-" + str(port)}
        )
        self.assertEqual(self.get(sock=sock)['status'], 200, 'range single')
        self.assertEqual(self.get(sock=sock2)['status'], 404, 'range single 2')

        socks = [
            sock_port(),
            sock_port(),
            sock_port(),
            sock_port(),
            sock_port(),
        ]
        socks.sort(key=lambda sock: sock[1])

        self.route_match(
            {
                "source": "127.0.0.1:"
                + str(socks[1][1])  # second port number
                + "-"
                + str(socks[3][1])  # fourth port number
            }
        )
        self.assertEqual(self.get(sock=socks[0][0])['status'], 404, 'range')
        self.assertEqual(self.get(sock=socks[1][0])['status'], 200, 'range 2')
        self.assertEqual(self.get(sock=socks[2][0])['status'], 200, 'range 3')
        self.assertEqual(self.get(sock=socks[3][0])['status'], 200, 'range 4')
        self.assertEqual(self.get(sock=socks[4][0])['status'], 404, 'range 5')

        socks = [
            sock_port(),
            sock_port(),
            sock_port(),
        ]
        socks.sort(key=lambda sock: sock[1])

        self.route_match(
            {
                "source": [
                    "127.0.0.1:" + str(socks[0][1]),
                    "127.0.0.1:" + str(socks[2][1]),
                ]
            }
        )
        self.assertEqual(self.get(sock=socks[0][0])['status'], 200, 'array')
        self.assertEqual(self.get(sock=socks[1][0])['status'], 404, 'array 2')
        self.assertEqual(self.get(sock=socks[2][0])['status'], 200, 'array 3')

    def test_routes_source_addr(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "routes"},
                    "[::1]:7081": {"pass": "routes"},
                },
                'listeners',
            ),
            'source listeners configure',
        )

        def get_ipv6():
            return self.get(sock_type='ipv6', port=7081)

        self.route_match({"source": "127.0.0.1"})
        self.assertEqual(self.get()['status'], 200, 'exact')
        self.assertEqual(get_ipv6()['status'], 404, 'exact ipv6')

        self.route_match({"source": ["127.0.0.1"]})
        self.assertEqual(self.get()['status'], 200, 'exact 2')
        self.assertEqual(get_ipv6()['status'], 404, 'exact 2 ipv6')

        self.route_match({"source": "!127.0.0.1"})
        self.assertEqual(self.get()['status'], 404, 'exact neg')
        self.assertEqual(get_ipv6()['status'], 200, 'exact neg ipv6')

        self.route_match({"source": "127.0.0.2"})
        self.assertEqual(self.get()['status'], 404, 'exact 3')
        self.assertEqual(get_ipv6()['status'], 404, 'exact 3 ipv6')

        self.route_match({"source": "127.0.0.1-127.0.0.1"})
        self.assertEqual(self.get()['status'], 200, 'range single')
        self.assertEqual(get_ipv6()['status'], 404, 'range single ipv6')

        self.route_match({"source": "127.0.0.2-127.0.0.2"})
        self.assertEqual(self.get()['status'], 404, 'range single 2')
        self.assertEqual(get_ipv6()['status'], 404, 'range single 2 ipv6')

        self.route_match({"source": "127.0.0.2-127.0.0.3"})
        self.assertEqual(self.get()['status'], 404, 'range')
        self.assertEqual(get_ipv6()['status'], 404, 'range ipv6')

        self.route_match({"source": "127.0.0.1-127.0.0.2"})
        self.assertEqual(self.get()['status'], 200, 'range 2')
        self.assertEqual(get_ipv6()['status'], 404, 'range 2 ipv6')

        self.route_match({"source": "127.0.0.0-127.0.0.2"})
        self.assertEqual(self.get()['status'], 200, 'range 3')
        self.assertEqual(get_ipv6()['status'], 404, 'range 3 ipv6')

        self.route_match({"source": "127.0.0.0-127.0.0.1"})
        self.assertEqual(self.get()['status'], 200, 'range 4')
        self.assertEqual(get_ipv6()['status'], 404, 'range 4 ipv6')

        self.route_match({"source": "126.0.0.0-127.0.0.0"})
        self.assertEqual(self.get()['status'], 404, 'range 5')
        self.assertEqual(get_ipv6()['status'], 404, 'range 5 ipv6')

        self.route_match({"source": "126.126.126.126-127.0.0.2"})
        self.assertEqual(self.get()['status'], 200, 'range 6')
        self.assertEqual(get_ipv6()['status'], 404, 'range 6 ipv6')

    def test_routes_source_ipv6(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "[::1]:7080": {"pass": "routes"},
                    "127.0.0.1:7081": {"pass": "routes"},
                },
                'listeners',
            ),
            'source listeners configure',
        )

        self.route_match({"source": "::1"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, 'exact')
        self.assertEqual(self.get(port=7081)['status'], 404, 'exact ipv4')

        self.route_match({"source": ["::1"]})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, 'exact 2')
        self.assertEqual(self.get(port=7081)['status'], 404, 'exact 2 ipv4')

        self.route_match({"source": "!::1"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 404, 'exact neg')
        self.assertEqual(self.get(port=7081)['status'], 200, 'exact neg ipv4')

        self.route_match({"source": "::2"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 404, 'exact 3')
        self.assertEqual(self.get(port=7081)['status'], 404, 'exact 3 ipv4')

        self.route_match({"source": "::1-::1"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, 'range')
        self.assertEqual(self.get(port=7081)['status'], 404, 'range ipv4')

        self.route_match({"source": "::2-::2"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 404, 'range 2')
        self.assertEqual(self.get(port=7081)['status'], 404, 'range 2 ipv4')

        self.route_match({"source": "::2-::3"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 404, 'range 3')
        self.assertEqual(self.get(port=7081)['status'], 404, 'range 3 ipv4')

        self.route_match({"source": "::1-::2"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, 'range 4')
        self.assertEqual(self.get(port=7081)['status'], 404, 'range 4 ipv4')

        self.route_match({"source": "::0-::2"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, 'range 5')
        self.assertEqual(self.get(port=7081)['status'], 404, 'range 5 ipv4')

        self.route_match({"source": "::0-::1"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, 'range 6')
        self.assertEqual(self.get(port=7081)['status'], 404, 'range 6 ipv4')

    def test_routes_source_cidr(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "*:7080": {"pass": "routes"},
                    "[::1]:7081": {"pass": "routes"},
                },
                'listeners',
            ),
            'source listeners configure',
        )

        def get_ipv6():
            return self.get(sock_type='ipv6', port=7081)

        self.route_match({"source": "127.0.0.1/32"})
        self.assertEqual(self.get()['status'], 200, '32')
        self.assertEqual(get_ipv6()['status'], 404, '32 ipv6')

        self.route_match({"source": "127.0.0.0/32"})
        self.assertEqual(self.get()['status'], 404, '32 2')
        self.assertEqual(get_ipv6()['status'], 404, '32 2 ipv6')

        self.route_match({"source": "127.0.0.0/31"})
        self.assertEqual(self.get()['status'], 200, '31')
        self.assertEqual(get_ipv6()['status'], 404, '31 ipv6')

        self.route_match({"source": "0.0.0.0/1"})
        self.assertEqual(self.get()['status'], 200, '1')
        self.assertEqual(get_ipv6()['status'], 404, '1 ipv6')

        self.route_match({"source": "0.0.0.0/0"})
        self.assertEqual(self.get()['status'], 200, '0')
        self.assertEqual(get_ipv6()['status'], 404, '0 ipv6')

    def test_routes_source_cidr_ipv6(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "[::1]:7080": {"pass": "routes"},
                    "127.0.0.1:7081": {"pass": "routes"},
                },
                'listeners',
            ),
            'source listeners configure',
        )

        self.route_match({"source": "::1/128"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, '128')
        self.assertEqual(self.get(port=7081)['status'], 404, '128 ipv4')

        self.route_match({"source": "::0/128"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 404, '128 2')
        self.assertEqual(self.get(port=7081)['status'], 404, '128 ipv4')

        self.route_match({"source": "::0/127"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, '127')
        self.assertEqual(self.get(port=7081)['status'], 404, '127 ipv4')

        self.route_match({"source": "::0/32"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, '32')
        self.assertEqual(self.get(port=7081)['status'], 404, '32 ipv4')

        self.route_match({"source": "::0/1"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, '1')
        self.assertEqual(self.get(port=7081)['status'], 404, '1 ipv4')

        self.route_match({"source": "::/0"})
        self.assertEqual(self.get(sock_type='ipv6')['status'], 200, '0')
        self.assertEqual(self.get(port=7081)['status'], 404, '0 ipv4')

    def test_routes_source_unix(self):
        addr = self.testdir + '/sock'

        self.assertIn(
            'success',
            self.conf({"unix:" + addr: {"pass": "routes"}}, 'listeners'),
            'source listeners configure',
        )

        self.route_match({"source": "!0.0.0.0/0"})
        self.assertEqual(
            self.get(sock_type='unix', addr=addr)['status'], 200, 'unix ipv4'
        )

        self.route_match({"source": "!::/0"})
        self.assertEqual(
            self.get(sock_type='unix', addr=addr)['status'], 200, 'unix ipv6'
        )

    def test_routes_match_source(self):
        self.route_match({"source": "::"})
        self.route_match(
            {
                "source": [
                    "127.0.0.1",
                    "192.168.0.10:8080",
                    "192.168.0.11:8080-8090",
                ]
            }
        )
        self.route_match(
            {
                "source": [
                    "10.0.0.0/8",
                    "10.0.0.0/7:1000",
                    "10.0.0.0/32:8080-8090",
                ]
            }
        )
        self.route_match(
            {
                "source": [
                    "10.0.0.0-10.0.0.1",
                    "10.0.0.0-11.0.0.0:1000",
                    "127.0.0.0-127.0.0.255:8080-8090",
                ]
            }
        )
        self.route_match(
            {"source": ["2001::", "[2002::]:8000", "[2003::]:8080-8090"]}
        )
        self.route_match(
            {
                "source": [
                    "2001::-200f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                    "[fe08::-feff::]:8000",
                    "[fff0::-fff0::10]:8080-8090",
                ]
            }
        )
        self.route_match(
            {
                "source": [
                    "2001::/16",
                    "[0ff::/64]:8000",
                    "[fff0:abcd:ffff:ffff:ffff::/128]:8080-8090",
                ]
            }
        )
        self.route_match({"source": "*:0-65535"})
        self.assertEqual(self.get()['status'], 200, 'source any')

    def test_routes_match_source_invalid(self):
        self.route_match_invalid({"source": "127"})
        self.route_match_invalid({"source": "256.0.0.1"})
        self.route_match_invalid({"source": "127.0.0."})
        self.route_match_invalid({"source": "127.0.0.1:"})
        self.route_match_invalid({"source": "127.0.0.1/"})
        self.route_match_invalid({"source": "11.0.0.0/33"})
        self.route_match_invalid({"source": "11.0.0.0/65536"})
        self.route_match_invalid({"source": "11.0.0.0-10.0.0.0"})
        self.route_match_invalid({"source": "11.0.0.0:3000-2000"})
        self.route_match_invalid({"source": ["11.0.0.0:3000-2000"]})
        self.route_match_invalid({"source": "[2001::]:3000-2000"})
        self.route_match_invalid({"source": "2001::-2000::"})
        self.route_match_invalid({"source": "2001::/129"})
        self.route_match_invalid({"source": "::FFFFF"})
        self.route_match_invalid({"source": "[::1]:"})
        self.route_match_invalid({"source": "[:::]:7080"})
        self.route_match_invalid({"source": "*:"})
        self.route_match_invalid({"source": "*:1-a"})
        self.route_match_invalid({"source": "*:65536"})

    def test_routes_match_destination(self):
        self.assertIn(
            'success',
            self.conf(
                {"*:7080": {"pass": "routes"}, "*:7081": {"pass": "routes"}},
                'listeners',
            ),
            'listeners configure',
        )

        self.route_match({"destination": "*:7080"})
        self.assertEqual(self.get()['status'], 200, 'dest')
        self.assertEqual(self.get(port=7081)['status'], 404, 'dest 2')

        self.route_match({"destination": ["127.0.0.1:7080"]})
        self.assertEqual(self.get()['status'], 200, 'dest 3')
        self.assertEqual(self.get(port=7081)['status'], 404, 'dest 4')

        self.route_match({"destination": "!*:7080"})
        self.assertEqual(self.get()['status'], 404, 'dest neg')
        self.assertEqual(self.get(port=7081)['status'], 200, 'dest neg 2')

    def test_routes_match_destination_proxy(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "listeners": {
                        "*:7080": {"pass": "routes/first"},
                        "*:7081": {"pass": "routes/second"},
                    },
                    "routes": {
                        "first": [
                            {"action": {"proxy": "http://127.0.0.1:7081"}}
                        ],
                        "second": [
                            {
                                "match": {"destination": ["127.0.0.1:7081"]},
                                "action": {"pass": "applications/empty"},
                            }
                        ],
                    },
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
            ),
            'proxy configure',
        )

        self.assertEqual(self.get()['status'], 200, 'proxy')

if __name__ == '__main__':
    TestRouting.main()
