# -*- coding: utf-8 -*-
import pytest

from unit.applications.proto import TestApplicationProto
from unit.option import option


class TestRouting(TestApplicationProto):
    prerequisites = {'modules': {'python': 'any'}}

    def setup_method(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {"match": {"method": "GET"}, "action": {"return": 200},}
                ],
                "applications": {},
            }
        ), 'routing configure'

    def route(self, route):
        return self.conf([route], 'routes')

    def route_match(self, match):
        assert 'success' in self.route(
            {"match": match, "action": {"return": 200}}
        ), 'route match configure'

    def route_match_invalid(self, match):
        assert 'error' in self.route(
            {"match": match, "action": {"return": 200}}
        ), 'route match configure invalid'

    def host(self, host, status):
        assert (
            self.get(headers={'Host': host, 'Connection': 'close'})['status']
            == status
        ), 'match host'

    def cookie(self, cookie, status):
        assert (
            self.get(
                headers={
                    'Host': 'localhost',
                    'Cookie': cookie,
                    'Connection': 'close',
                },
            )['status']
            == status
        ), 'match cookie'

    def test_routes_match_method_positive(self):
        assert self.get()['status'] == 200, 'GET'
        assert self.post()['status'] == 404, 'POST'

    def test_routes_match_method_positive_many(self):
        self.route_match({"method": ["GET", "POST"]})

        assert self.get()['status'] == 200, 'GET'
        assert self.post()['status'] == 200, 'POST'
        assert self.delete()['status'] == 404, 'DELETE'

    def test_routes_match_method_negative(self):
        self.route_match({"method": "!GET"})

        assert self.get()['status'] == 404, 'GET'
        assert self.post()['status'] == 200, 'POST'

    def test_routes_match_method_negative_many(self):
        self.route_match({"method": ["!GET", "!POST"]})

        assert self.get()['status'] == 404, 'GET'
        assert self.post()['status'] == 404, 'POST'
        assert self.delete()['status'] == 200, 'DELETE'

    def test_routes_match_method_wildcard_left(self):
        self.route_match({"method": "*ET"})

        assert self.get()['status'] == 200, 'GET'
        assert self.post()['status'] == 404, 'POST'

    def test_routes_match_method_wildcard_right(self):
        self.route_match({"method": "GE*"})

        assert self.get()['status'] == 200, 'GET'
        assert self.post()['status'] == 404, 'POST'

    def test_routes_match_method_wildcard_left_right(self):
        self.route_match({"method": "*GET*"})

        assert self.get()['status'] == 200, 'GET'
        assert self.post()['status'] == 404, 'POST'

    def test_routes_match_method_wildcard(self):
        self.route_match({"method": "*"})

        assert self.get()['status'] == 200, 'GET'

    def test_routes_match_invalid(self):
        self.route_match_invalid({"method": "**"})

    def test_routes_match_valid(self):
        self.route_match({"method": "blah*"})
        self.route_match({"host": "*blah*blah"})
        self.route_match({"host": "blah*blah*blah"})
        self.route_match({"host": "blah*blah*"})

    def test_routes_match_empty_exact(self):
        self.route_match({"uri": ""})
        assert self.get()['status'] == 404

        self.route_match({"uri": "/"})
        assert self.get()['status'] == 200
        assert self.get(url='/blah')['status'] == 404

    def test_routes_match_negative(self):
        self.route_match({"uri": "!"})
        assert self.get()['status'] == 200

        self.route_match({"uri": "!*"})
        assert self.get()['status'] == 404

        self.route_match({"uri": "!/"})
        assert self.get()['status'] == 404
        assert self.get(url='/blah')['status'] == 200

        self.route_match({"uri": "!*blah"})
        assert self.get()['status'] == 200
        assert self.get(url='/bla')['status'] == 200
        assert self.get(url='/blah')['status'] == 404
        assert self.get(url='/blah1')['status'] == 200

        self.route_match({"uri": "!/blah*1*"})
        assert self.get()['status'] == 200
        assert self.get(url='/blah')['status'] == 200
        assert self.get(url='/blah1')['status'] == 404
        assert self.get(url='/blah12')['status'] == 404
        assert self.get(url='/blah2')['status'] == 200

    def test_routes_match_wildcard_middle(self):
        self.route_match({"host": "ex*le"})

        self.host('example', 200)
        self.host('www.example', 404)
        self.host('example.com', 404)
        self.host('exampl', 404)

    def test_routes_match_method_case_insensitive(self):
        self.route_match({"method": "get"})

        assert self.get()['status'] == 200, 'GET'

    def test_routes_match_wildcard_left_case_insensitive(self):
        self.route_match({"method": "*get"})
        assert self.get()['status'] == 200, 'GET'

        self.route_match({"method": "*et"})
        assert self.get()['status'] == 200, 'GET'

    def test_routes_match_wildcard_middle_case_insensitive(self):
        self.route_match({"method": "g*t"})

        assert self.get()['status'] == 200, 'GET'

    def test_routes_match_wildcard_right_case_insensitive(self):
        self.route_match({"method": "get*"})
        assert self.get()['status'] == 200, 'GET'

        self.route_match({"method": "ge*"})
        assert self.get()['status'] == 200, 'GET'

    def test_routes_match_wildcard_substring_case_insensitive(self):
        self.route_match({"method": "*et*"})

        assert self.get()['status'] == 200, 'GET'

    def test_routes_match_wildcard_left_case_sensitive(self):
        self.route_match({"uri": "*blah"})

        assert self.get(url='/blah')['status'] == 200, '/blah'
        assert self.get(url='/BLAH')['status'] == 404, '/BLAH'

    def test_routes_match_wildcard_middle_case_sensitive(self):
        self.route_match({"uri": "/b*h"})

        assert self.get(url='/blah')['status'] == 200, '/blah'
        assert self.get(url='/BLAH')['status'] == 404, '/BLAH'

    def test_route_match_wildcards_ordered(self):
        self.route_match({"uri": "/a*x*y*"})

        assert self.get(url='/axy')['status'] == 200, '/axy'
        assert self.get(url='/ayx')['status'] == 404, '/ayx'

    def test_route_match_wildcards_adjust_start(self):
        self.route_match({"uri": "/bla*bla*"})

        assert self.get(url='/bla_foo')['status'] == 404, '/bla_foo'

    def test_route_match_wildcards_adjust_start_substr(self):
        self.route_match({"uri": "*bla*bla*"})

        assert self.get(url='/bla_foo')['status'] == 404, '/bla_foo'

    def test_route_match_wildcards_adjust_end(self):
        self.route_match({"uri": "/bla*bla"})

        assert self.get(url='/foo_bla')['status'] == 404, '/foo_bla'

    def test_routes_match_wildcard_right_case_sensitive(self):
        self.route_match({"uri": "/bla*"})

        assert self.get(url='/blah')['status'] == 200, '/blah'
        assert self.get(url='/BLAH')['status'] == 404, '/BLAH'

    def test_routes_match_wildcard_substring_case_sensitive(self):
        self.route_match({"uri": "*bla*"})

        assert self.get(url='/blah')['status'] == 200, '/blah'
        assert self.get(url='/BLAH')['status'] == 404, '/BLAH'

    def test_routes_match_many_wildcard_substrings_case_sensitive(self):
        self.route_match({"uri": "*a*B*c*"})

        assert self.get(url='/blah-a-B-c-blah')['status'] == 200
        assert self.get(url='/a-B-c')['status'] == 200
        assert self.get(url='/aBc')['status'] == 200
        assert self.get(url='/aBCaBbc')['status'] == 200
        assert self.get(url='/ABc')['status'] == 404

    def test_routes_empty_regex(self):
        if not option.available['modules']['regex']:
            pytest.skip('requires regex')

        self.route_match({"uri": "~"})
        assert self.get(url='/')['status'] == 200, 'empty regexp'
        assert self.get(url='/anything')['status'] == 200, '/anything'

        self.route_match({"uri": "!~"})
        assert self.get(url='/')['status'] == 404, 'empty regexp 2'
        assert self.get(url='/nothing')['status'] == 404, '/nothing'

    def test_routes_bad_regex(self):
        if not option.available['modules']['regex']:
            pytest.skip('requires regex')

        assert 'error' in self.route(
            {"match": {"uri": "~/bl[ah"}, "action": {"return": 200}}
        ), 'bad regex'

        status = self.route(
            {"match": {"uri": "~(?R)?z"}, "action": {"return": 200}}
        )
        if 'error' not in status:
            assert self.get(url='/nothing_z')['status'] == 500, '/nothing_z'

        status = self.route(
            {"match": {"uri": "~((?1)?z)"}, "action": {"return": 200}}
        )
        if 'error' not in status:
            assert self.get(url='/nothing_z')['status'] == 500, '/nothing_z'

    def test_routes_match_regex_case_sensitive(self):
        if not option.available['modules']['regex']:
            pytest.skip('requires regex')

        self.route_match({"uri": "~/bl[ah]"})

        assert self.get(url='/rlah')['status'] == 404, '/rlah'
        assert self.get(url='/blah')['status'] == 200, '/blah'
        assert self.get(url='/blh')['status'] == 200, '/blh'
        assert self.get(url='/BLAH')['status'] == 404, '/BLAH'

    def test_routes_match_regex_negative_case_sensitive(self):
        if not option.available['modules']['regex']:
            pytest.skip('requires regex')

        self.route_match({"uri": "!~/bl[ah]"})

        assert self.get(url='/rlah')['status'] == 200, '/rlah'
        assert self.get(url='/blah')['status'] == 404, '/blah'
        assert self.get(url='/blh')['status'] == 404, '/blh'
        assert self.get(url='/BLAH')['status'] == 200, '/BLAH'

    def test_routes_pass_encode(self):
        def check_pass(path, name):
            assert 'success' in self.conf(
                {
                    "listeners": {"*:7080": {"pass": "applications/" + path}},
                    "applications": {
                        name: {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": option.test_dir + '/python/empty',
                            "working_directory": option.test_dir
                            + '/python/empty',
                            "module": "wsgi",
                        }
                    },
                }
            )

            assert self.get()['status'] == 200

        check_pass("%25", "%")
        check_pass("blah%2Fblah", "blah/blah")
        check_pass("%2Fblah%2F%2Fblah%2F", "/blah//blah/")
        check_pass("%20blah%252Fblah%7E", " blah%2Fblah~")

        def check_pass_error(path, name):
            assert 'error' in self.conf(
                {
                    "listeners": {"*:7080": {"pass": "applications/" + path}},
                    "applications": {
                        name: {
                            "type": "python",
                            "processes": {"spare": 0},
                            "path": option.test_dir + '/python/empty',
                            "working_directory": option.test_dir
                            + '/python/empty',
                            "module": "wsgi",
                        }
                    },
                }
            )

        check_pass_error("%", "%")
        check_pass_error("%1", "%1")

    def test_routes_absent(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7081": {"pass": "applications/empty"}},
                "applications": {
                    "empty": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": option.test_dir + '/python/empty',
                        "working_directory": option.test_dir + '/python/empty',
                        "module": "wsgi",
                    }
                },
            }
        )

        assert self.get(port=7081)['status'] == 200, 'routes absent'

    def test_routes_pass_invalid(self):
        assert 'error' in self.conf(
            {"pass": "routes/blah"}, 'listeners/*:7080'
        ), 'routes invalid'

    def test_route_empty(self):
        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes/main"}},
                "routes": {"main": []},
                "applications": {},
            }
        ), 'route empty configure'

        assert self.get()['status'] == 404, 'route empty'

    def test_routes_route_empty(self):
        assert 'success' in self.conf(
            {}, 'listeners'
        ), 'routes empty listeners configure'

        assert 'success' in self.conf({}, 'routes'), 'routes empty configure'

    def test_routes_route_match_absent(self):
        assert 'success' in self.conf(
            [{"action": {"return": 200}}], 'routes'
        ), 'route match absent configure'

        assert self.get()['status'] == 200, 'route match absent'

    def test_routes_route_action_absent(self, skip_alert):
        skip_alert(r'failed to apply new conf')

        assert 'error' in self.conf(
            [{"match": {"method": "GET"}}], 'routes'
        ), 'route pass absent configure'

    def test_routes_route_pass(self):
        assert 'success' in self.conf(
            {
                "applications": {
                    "app": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": "/app",
                        "module": "wsgi",
                    }
                },
                "upstreams": {
                    "one": {
                        "servers": {
                            "127.0.0.1:7081": {},
                            "127.0.0.1:7082": {},
                        },
                    },
                    "two": {
                        "servers": {
                            "127.0.0.1:7081": {},
                            "127.0.0.1:7082": {},
                        },
                    },
                },
            }
        )

        assert 'success' in self.conf(
            [{"action": {"pass": "routes"}}], 'routes'
        )
        assert 'success' in self.conf(
            [{"action": {"pass": "applications/app"}}], 'routes'
        )
        assert 'success' in self.conf(
            [{"action": {"pass": "upstreams/one"}}], 'routes'
        )

    def test_routes_route_pass_absent(self):
        assert 'error' in self.conf(
            [{"match": {"method": "GET"}, "action": {}}], 'routes'
        ), 'route pass absent configure'

    def test_routes_route_pass_invalid(self):
        assert 'success' in self.conf(
            {
                "applications": {
                    "app": {
                        "type": "python",
                        "processes": {"spare": 0},
                        "path": "/app",
                        "module": "wsgi",
                    }
                },
                "upstreams": {
                    "one": {
                        "servers": {
                            "127.0.0.1:7081": {},
                            "127.0.0.1:7082": {},
                        },
                    },
                    "two": {
                        "servers": {
                            "127.0.0.1:7081": {},
                            "127.0.0.1:7082": {},
                        },
                    },
                },
            }
        )

        assert 'error' in self.conf(
            [{"action": {"pass": "blah"}}], 'routes'
        ), 'route pass invalid'
        assert 'error' in self.conf(
            [{"action": {"pass": "routes/blah"}}], 'routes'
        ), 'route pass routes invalid'
        assert 'error' in self.conf(
            [{"action": {"pass": "applications/blah"}}], 'routes'
        ), 'route pass applications invalid'
        assert 'error' in self.conf(
            [{"action": {"pass": "upstreams/blah"}}], 'routes'
        ), 'route pass upstreams invalid'

    def test_routes_action_unique(self, temp_dir):
        assert 'success' in self.conf(
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
        )

        assert 'error' in self.conf(
            {"proxy": "http://127.0.0.1:7081", "share": temp_dir},
            'routes/0/action',
        ), 'proxy share'
        assert 'error' in self.conf(
            {"proxy": "http://127.0.0.1:7081", "pass": "applications/app",},
            'routes/0/action',
        ), 'proxy pass'
        assert 'error' in self.conf(
            {"share": temp_dir, "pass": "applications/app"}, 'routes/0/action',
        ), 'share pass'

    def test_routes_rules_two(self):
        assert 'success' in self.conf(
            [
                {"match": {"method": "GET"}, "action": {"return": 200}},
                {"match": {"method": "POST"}, "action": {"return": 201}},
            ],
            'routes',
        ), 'rules two configure'

        assert self.get()['status'] == 200, 'rules two match first'
        assert self.post()['status'] == 201, 'rules two match second'

    def test_routes_two(self):
        assert 'success' in self.conf(
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
                            "action": {"return": 200},
                        }
                    ],
                },
                "applications": {},
            }
        ), 'routes two configure'

        assert self.get()['status'] == 200, 'routes two'

    def test_routes_match_host_positive(self):
        self.route_match({"host": "localhost"})

        assert self.get()['status'] == 200, 'localhost'
        self.host('localhost.', 200)
        self.host('localhost.', 200)
        self.host('.localhost', 404)
        self.host('www.localhost', 404)
        self.host('localhost1', 404)

    @pytest.mark.skip('not yet')
    def test_routes_match_host_absent(self):
        self.route_match({"host": "localhost"})

        assert (
            self.get(headers={'Connection': 'close'})['status'] == 400
        ), 'match host absent'

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

        assert self.get()['status'] == 200, 'localhost'
        self.host('example.com', 200)

    def test_routes_match_host_positive_and_negative(self):
        self.route_match({"host": ["*example.com", "!www.example.com"]})

        assert self.get()['status'] == 404, 'localhost'
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
        assert (
            self.get(http_10=True, headers={})['status'] == 200
        ), 'match host empty 2'
        assert self.get()['status'] == 404, 'match host empty 3'

    def test_routes_match_uri_positive(self):
        self.route_match({"uri": ["/blah", "/slash/"]})

        assert self.get()['status'] == 404, '/'
        assert self.get(url='/blah')['status'] == 200, '/blah'
        assert self.get(url='/blah#foo')['status'] == 200, '/blah#foo'
        assert self.get(url='/blah?var')['status'] == 200, '/blah?var'
        assert self.get(url='//blah')['status'] == 200, '//blah'
        assert self.get(url='/slash/foo/../')['status'] == 200, 'relative'
        assert self.get(url='/slash/./')['status'] == 200, '/slash/./'
        assert self.get(url='/slash//.//')['status'] == 200, 'adjacent slashes'
        assert self.get(url='/%')['status'] == 400, 'percent'
        assert self.get(url='/%1')['status'] == 400, 'percent digit'
        assert self.get(url='/%A')['status'] == 400, 'percent letter'
        assert self.get(url='/slash/.?args')['status'] == 200, 'dot args'
        assert self.get(url='/slash/.#frag')['status'] == 200, 'dot frag'
        assert (
            self.get(url='/slash/foo/..?args')['status'] == 200
        ), 'dot dot args'
        assert (
            self.get(url='/slash/foo/..#frag')['status'] == 200
        ), 'dot dot frag'
        assert self.get(url='/slash/.')['status'] == 200, 'trailing dot'
        assert (
            self.get(url='/slash/foo/..')['status'] == 200
        ), 'trailing dot dot'

    def test_routes_match_uri_case_sensitive(self):
        self.route_match({"uri": "/BLAH"})

        assert self.get(url='/blah')['status'] == 404, '/blah'
        assert self.get(url='/BlaH')['status'] == 404, '/BlaH'
        assert self.get(url='/BLAH')['status'] == 200, '/BLAH'

    def test_routes_match_uri_normalize(self):
        self.route_match({"uri": "/blah"})

        assert self.get(url='/%62%6c%61%68')['status'] == 200, 'normalize'

    def test_routes_match_empty_array(self):
        self.route_match({"uri": []})

        assert self.get(url='/blah')['status'] == 200, 'empty array'

    def test_routes_reconfigure(self):
        assert 'success' in self.conf([], 'routes'), 'redefine'
        assert self.get()['status'] == 404, 'redefine request'

        assert 'success' in self.conf(
            [{"action": {"return": 200}}], 'routes'
        ), 'redefine 2'
        assert self.get()['status'] == 200, 'redefine request 2'

        assert 'success' in self.conf([], 'routes'), 'redefine 3'
        assert self.get()['status'] == 404, 'redefine request 3'

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes/main"}},
                "routes": {"main": [{"action": {"return": 200}}]},
                "applications": {},
            }
        ), 'redefine 4'
        assert self.get()['status'] == 200, 'redefine request 4'

        assert 'success' in self.conf_delete('routes/main/0'), 'redefine 5'
        assert self.get()['status'] == 404, 'redefine request 5'

        assert 'success' in self.conf_post(
            {"action": {"return": 200}}, 'routes/main'
        ), 'redefine 6'
        assert self.get()['status'] == 200, 'redefine request 6'

        assert 'error' in self.conf(
            {"action": {"return": 200}}, 'routes/main/2'
        ), 'redefine 7'
        assert 'success' in self.conf(
            {"action": {"return": 201}}, 'routes/main/1'
        ), 'redefine 8'

        assert len(self.conf_get('routes/main')) == 2, 'redefine conf 8'
        assert self.get()['status'] == 200, 'redefine request 8'

    def test_routes_edit(self):
        self.route_match({"method": "GET"})

        assert self.get()['status'] == 200, 'routes edit GET'
        assert self.post()['status'] == 404, 'routes edit POST'

        assert 'success' in self.conf_post(
            {"match": {"method": "POST"}, "action": {"return": 200}}, 'routes',
        ), 'routes edit configure 2'
        assert 'GET' == self.conf_get(
            'routes/0/match/method'
        ), 'routes edit configure 2 check'
        assert 'POST' == self.conf_get(
            'routes/1/match/method'
        ), 'routes edit configure 2 check 2'

        assert self.get()['status'] == 200, 'routes edit GET 2'
        assert self.post()['status'] == 200, 'routes edit POST 2'

        assert 'success' in self.conf_delete(
            'routes/0'
        ), 'routes edit configure 3'

        assert self.get()['status'] == 404, 'routes edit GET 3'
        assert self.post()['status'] == 200, 'routes edit POST 3'

        assert 'error' in self.conf_delete(
            'routes/1'
        ), 'routes edit configure invalid'
        assert 'error' in self.conf_delete(
            'routes/-1'
        ), 'routes edit configure invalid 2'
        assert 'error' in self.conf_delete(
            'routes/blah'
        ), 'routes edit configure invalid 3'

        assert self.get()['status'] == 404, 'routes edit GET 4'
        assert self.post()['status'] == 200, 'routes edit POST 4'

        assert 'success' in self.conf_delete(
            'routes/0'
        ), 'routes edit configure 5'

        assert self.get()['status'] == 404, 'routes edit GET 5'
        assert self.post()['status'] == 404, 'routes edit POST 5'

        assert 'success' in self.conf_post(
            {"match": {"method": "POST"}, "action": {"return": 200}}, 'routes',
        ), 'routes edit configure 6'

        assert self.get()['status'] == 404, 'routes edit GET 6'
        assert self.post()['status'] == 200, 'routes edit POST 6'

        assert 'success' in self.conf(
            {
                "listeners": {"*:7080": {"pass": "routes/main"}},
                "routes": {"main": [{"action": {"return": 200}}]},
                "applications": {},
            }
        ), 'route edit configure 7'

        assert 'error' in self.conf_delete(
            'routes/0'
        ), 'routes edit configure invalid 4'
        assert 'error' in self.conf_delete(
            'routes/main'
        ), 'routes edit configure invalid 5'

        assert self.get()['status'] == 200, 'routes edit GET 7'

        assert 'success' in self.conf_delete(
            'listeners/*:7080'
        ), 'route edit configure 8'
        assert 'success' in self.conf_delete(
            'routes/main'
        ), 'route edit configure 9'

    def test_match_edit(self, skip_alert):
        skip_alert(r'failed to apply new conf')

        self.route_match({"method": ["GET", "POST"]})

        assert self.get()['status'] == 200, 'match edit GET'
        assert self.post()['status'] == 200, 'match edit POST'
        assert self.put()['status'] == 404, 'match edit PUT'

        assert 'success' in self.conf_post(
            '\"PUT\"', 'routes/0/match/method'
        ), 'match edit configure 2'
        assert ['GET', 'POST', 'PUT'] == self.conf_get(
            'routes/0/match/method'
        ), 'match edit configure 2 check'

        assert self.get()['status'] == 200, 'match edit GET 2'
        assert self.post()['status'] == 200, 'match edit POST 2'
        assert self.put()['status'] == 200, 'match edit PUT 2'

        assert 'success' in self.conf_delete(
            'routes/0/match/method/1'
        ), 'match edit configure 3'
        assert ['GET', 'PUT'] == self.conf_get(
            'routes/0/match/method'
        ), 'match edit configure 3 check'

        assert self.get()['status'] == 200, 'match edit GET 3'
        assert self.post()['status'] == 404, 'match edit POST 3'
        assert self.put()['status'] == 200, 'match edit PUT 3'

        assert 'success' in self.conf_delete(
            'routes/0/match/method/1'
        ), 'match edit configure 4'
        assert ['GET'] == self.conf_get(
            'routes/0/match/method'
        ), 'match edit configure 4 check'

        assert self.get()['status'] == 200, 'match edit GET 4'
        assert self.post()['status'] == 404, 'match edit POST 4'
        assert self.put()['status'] == 404, 'match edit PUT 4'

        assert 'error' in self.conf_delete(
            'routes/0/match/method/1'
        ), 'match edit configure invalid'
        assert 'error' in self.conf_delete(
            'routes/0/match/method/-1'
        ), 'match edit configure invalid 2'
        assert 'error' in self.conf_delete(
            'routes/0/match/method/blah'
        ), 'match edit configure invalid 3'
        assert ['GET'] == self.conf_get(
            'routes/0/match/method'
        ), 'match edit configure 5 check'

        assert self.get()['status'] == 200, 'match edit GET 5'
        assert self.post()['status'] == 404, 'match edit POST 5'
        assert self.put()['status'] == 404, 'match edit PUT 5'

        assert 'success' in self.conf_delete(
            'routes/0/match/method/0'
        ), 'match edit configure 6'
        assert [] == self.conf_get(
            'routes/0/match/method'
        ), 'match edit configure 6 check'

        assert self.get()['status'] == 200, 'match edit GET 6'
        assert self.post()['status'] == 200, 'match edit POST 6'
        assert self.put()['status'] == 200, 'match edit PUT 6'

        assert 'success' in self.conf(
            '"GET"', 'routes/0/match/method'
        ), 'match edit configure 7'

        assert self.get()['status'] == 200, 'match edit GET 7'
        assert self.post()['status'] == 404, 'match edit POST 7'
        assert self.put()['status'] == 404, 'match edit PUT 7'

        assert 'error' in self.conf_delete(
            'routes/0/match/method/0'
        ), 'match edit configure invalid 5'
        assert 'error' in self.conf(
            {}, 'routes/0/action'
        ), 'match edit configure invalid 6'

        assert 'success' in self.conf(
            {}, 'routes/0/match'
        ), 'match edit configure 8'

        assert self.get()['status'] == 200, 'match edit GET 8'

    def test_routes_match_rules(self):
        self.route_match({"method": "GET", "host": "localhost", "uri": "/"})

        assert self.get()['status'] == 200, 'routes match rules'

    def test_routes_loop(self):
        assert 'success' in self.route(
            {"match": {"uri": "/"}, "action": {"pass": "routes"}}
        ), 'routes loop configure'

        assert self.get()['status'] == 500, 'routes loop'

    def test_routes_match_headers(self):
        self.route_match({"headers": {"host": "localhost"}})

        assert self.get()['status'] == 200, 'match headers'
        self.host('Localhost', 200)
        self.host('localhost.com', 404)
        self.host('llocalhost', 404)
        self.host('host', 404)

    def test_routes_match_headers_multiple(self):
        self.route_match({"headers": {"host": "localhost", "x-blah": "test"}})

        assert self.get()['status'] == 404, 'match headers multiple'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "test",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers multiple 2'

        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "",
                    "Connection": "close",
                }
            )['status']
            == 404
        ), 'match headers multiple 3'

    def test_routes_match_headers_multiple_values(self):
        self.route_match({"headers": {"x-blah": "test"}})

        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "test", "test"],
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers multiple values'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "blah", "test"],
                    "Connection": "close",
                }
            )['status']
            == 404
        ), 'match headers multiple values 2'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "", "test"],
                    "Connection": "close",
                }
            )['status']
            == 404
        ), 'match headers multiple values 3'

    def test_routes_match_headers_multiple_rules(self):
        self.route_match({"headers": {"x-blah": ["test", "blah"]}})

        assert self.get()['status'] == 404, 'match headers multiple rules'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "test",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers multiple rules 2'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": "blah",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers multiple rules 3'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["test", "blah", "test"],
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers multiple rules 4'

        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "X-blah": ["blah", ""],
                    "Connection": "close",
                }
            )['status']
            == 404
        ), 'match headers multiple rules 5'

    def test_routes_match_headers_case_insensitive(self):
        self.route_match({"headers": {"X-BLAH": "TEST"}})

        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-blah": "test",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers case insensitive'

    def test_routes_match_headers_invalid(self):
        self.route_match_invalid({"headers": ["blah"]})
        self.route_match_invalid({"headers": {"foo": ["bar", {}]}})
        self.route_match_invalid({"headers": {"": "blah"}})

    def test_routes_match_headers_empty_rule(self):
        self.route_match({"headers": {"host": ""}})

        assert self.get()['status'] == 404, 'localhost'
        self.host('', 200)

    def test_routes_match_headers_empty(self):
        self.route_match({"headers": {}})
        assert self.get()['status'] == 200, 'empty'

        self.route_match({"headers": []})
        assert self.get()['status'] == 200, 'empty 2'

    def test_routes_match_headers_rule_array_empty(self):
        self.route_match({"headers": {"blah": []}})

        assert self.get()['status'] == 404, 'array empty'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "blah": "foo",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers rule array empty 2'

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

        assert self.get()['status'] == 404, 'match headers array'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header1": "foo123",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers array 2'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header2": "bar",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers array 3'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header3": "bar",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers array 4'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header1": "bar",
                    "Connection": "close",
                }
            )['status']
            == 404
        ), 'match headers array 5'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header1": "bar",
                    "x-header4": "foo",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers array 6'

        assert 'success' in self.conf_delete(
            'routes/0/match/headers/1'
        ), 'match headers array configure 2'

        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header2": "bar",
                    "Connection": "close",
                }
            )['status']
            == 404
        ), 'match headers array 7'
        assert (
            self.get(
                headers={
                    "Host": "localhost",
                    "x-header3": "foo",
                    "Connection": "close",
                }
            )['status']
            == 200
        ), 'match headers array 8'

    def test_routes_match_arguments(self):
        self.route_match({"arguments": {"foo": "bar"}})

        assert self.get()['status'] == 404, 'args'
        assert self.get(url='/?foo=bar')['status'] == 200, 'args 2'
        assert self.get(url='/?foo=bar1')['status'] == 404, 'args 3'
        assert self.get(url='/?1foo=bar')['status'] == 404, 'args 4'
        assert self.get(url='/?Foo=bar')['status'] == 404, 'case'
        assert self.get(url='/?foo=Bar')['status'] == 404, 'case 2'

    def test_routes_match_arguments_chars(self):
        chars = (
            " !\"%23$%25%26'()*%2B,-./0123456789:;<%3D>?@"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        )

        chars_enc = ""
        for h1 in ["2", "3", "4", "5", "6", "7"]:
            for h2 in [
                "0",
                "1",
                "2",
                "3",
                "4",
                "5",
                "6",
                "7",
                "8",
                "9",
                "A",
                "B",
                "C",
                "D",
                "E",
                "F",
            ]:
                chars_enc += "%" + h1 + h2
        chars_enc = chars_enc[:-3]

        def check_args(args, query):
            self.route_match({"arguments": args})
            assert self.get(url='/?' + query)['status'] == 200

        check_args({chars: chars}, chars + '=' + chars)
        check_args({chars: chars}, chars + '=' + chars_enc)
        check_args({chars: chars}, chars_enc + '=' + chars)
        check_args({chars: chars}, chars_enc + '=' + chars_enc)
        check_args({chars_enc: chars_enc}, chars + '=' + chars)
        check_args({chars_enc: chars_enc}, chars + '=' + chars_enc)
        check_args({chars_enc: chars_enc}, chars_enc + '=' + chars)
        check_args({chars_enc: chars_enc}, chars_enc + '=' + chars_enc)

    def test_routes_match_arguments_empty(self):
        self.route_match({"arguments": {}})
        assert self.get()['status'] == 200, 'arguments empty'

        self.route_match({"arguments": []})
        assert self.get()['status'] == 200, 'arguments empty 2'

    def test_routes_match_arguments_space(self):
        self.route_match({"arguments": {"+fo o%20": "%20b+a r"}})
        assert self.get(url='/? fo o = b a r&')['status'] == 200
        assert self.get(url='/?+fo+o+=+b+a+r&')['status'] == 200
        assert self.get(url='/?%20fo%20o%20=%20b%20a%20r&')['status'] == 200

        self.route_match({"arguments": {"%20foo": " bar"}})
        assert self.get(url='/? foo= bar')['status'] == 200
        assert self.get(url='/?+foo=+bar')['status'] == 200
        assert self.get(url='/?%20foo=%20bar')['status'] == 200
        assert self.get(url='/?+foo= bar')['status'] == 200
        assert self.get(url='/?%20foo=+bar')['status'] == 200

    def test_routes_match_arguments_equal(self):
        self.route_match({"arguments": {"=": "="}})
        assert self.get(url='/?%3D=%3D')['status'] == 200
        assert self.get(url='/?%3D==')['status'] == 200
        assert self.get(url='/?===')['status'] == 404
        assert self.get(url='/?%3D%3D%3D')['status'] == 404
        assert self.get(url='/?==%3D')['status'] == 404

    def test_routes_match_arguments_enc(self):
        self.route_match({"arguments": {"Ю": "н"}})
        assert self.get(url='/?%D0%AE=%D0%BD')['status'] == 200
        assert self.get(url='/?%d0%ae=%d0%Bd')['status'] == 200

    def test_routes_match_arguments_hash(self):
        self.route_match({"arguments": {"#": "#"}})
        assert self.get(url='/?%23=%23')['status'] == 200
        assert self.get(url='/?%23=%23#')['status'] == 200
        assert self.get(url='/?#=#')['status'] == 404
        assert self.get(url='/?%23=#')['status'] == 404

    def test_routes_match_arguments_wildcard(self):
        self.route_match({"arguments": {"foo": "*"}})
        assert self.get(url='/?foo')['status'] == 200
        assert self.get(url='/?foo=')['status'] == 200
        assert self.get(url='/?foo=blah')['status'] == 200
        assert self.get(url='/?blah=foo')['status'] == 404

        self.route_match({"arguments": {"foo": "%25*"}})
        assert self.get(url='/?foo=%xx')['status'] == 200

        self.route_match({"arguments": {"foo": "%2A*"}})
        assert self.get(url='/?foo=*xx')['status'] == 200
        assert self.get(url='/?foo=xx')['status'] == 404

        self.route_match({"arguments": {"foo": "*%2A"}})
        assert self.get(url='/?foo=xx*')['status'] == 200
        assert self.get(url='/?foo=xx*x')['status'] == 404

        self.route_match({"arguments": {"foo": "1*2"}})
        assert self.get(url='/?foo=12')['status'] == 200
        assert self.get(url='/?foo=1blah2')['status'] == 200
        assert self.get(url='/?foo=1%2A2')['status'] == 200
        assert self.get(url='/?foo=x12')['status'] == 404

        self.route_match({"arguments": {"foo": "bar*", "%25": "%25"}})
        assert self.get(url='/?foo=barxx&%=%')['status'] == 200
        assert self.get(url='/?foo=barxx&x%=%')['status'] == 404

    def test_routes_match_arguments_negative(self):
        self.route_match({"arguments": {"foo": "!"}})
        assert self.get(url='/?bar')['status'] == 404
        assert self.get(url='/?foo')['status'] == 404
        assert self.get(url='/?foo=')['status'] == 404
        assert self.get(url='/?foo=%25')['status'] == 200

        self.route_match({"arguments": {"foo": "!*"}})
        assert self.get(url='/?bar')['status'] == 404
        assert self.get(url='/?foo')['status'] == 404
        assert self.get(url='/?foo=')['status'] == 404
        assert self.get(url='/?foo=blah')['status'] == 404

        self.route_match({"arguments": {"foo": "!%25"}})
        assert self.get(url='/?foo=blah')['status'] == 200
        assert self.get(url='/?foo=%')['status'] == 404

        self.route_match({"arguments": {"foo": "%21blah"}})
        assert self.get(url='/?foo=%21blah')['status'] == 200
        assert self.get(url='/?foo=!blah')['status'] == 200
        assert self.get(url='/?foo=bar')['status'] == 404

        self.route_match({"arguments": {"foo": "!!%21*a"}})
        assert self.get(url='/?foo=blah')['status'] == 200
        assert self.get(url='/?foo=!blah')['status'] == 200
        assert self.get(url='/?foo=!!a')['status'] == 404
        assert self.get(url='/?foo=!!bla')['status'] == 404

    def test_routes_match_arguments_percent(self):
        self.route_match({"arguments": {"%25": "%25"}})
        assert self.get(url='/?%=%')['status'] == 200
        assert self.get(url='/?%25=%25')['status'] == 200
        assert self.get(url='/?%25=%')['status'] == 200

        self.route_match({"arguments": {"%251": "%252"}})
        assert self.get(url='/?%1=%2')['status'] == 200
        assert self.get(url='/?%251=%252')['status'] == 200
        assert self.get(url='/?%251=%2')['status'] == 200

        self.route_match({"arguments": {"%25%21%251": "%25%24%252"}})
        assert self.get(url='/?%!%1=%$%2')['status'] == 200
        assert self.get(url='/?%25!%251=%25$%252')['status'] == 200
        assert self.get(url='/?%25!%1=%$%2')['status'] == 200

    def test_routes_match_arguments_ampersand(self):
        self.route_match({"arguments": {"foo": "&"}})
        assert self.get(url='/?foo=%26')['status'] == 200
        assert self.get(url='/?foo=%26&')['status'] == 200
        assert self.get(url='/?foo=%26%26')['status'] == 404
        assert self.get(url='/?foo=&')['status'] == 404

        self.route_match({"arguments": {"&": ""}})
        assert self.get(url='/?%26=')['status'] == 200
        assert self.get(url='/?%26=&')['status'] == 200
        assert self.get(url='/?%26=%26')['status'] == 404
        assert self.get(url='/?&=')['status'] == 404

    def test_routes_match_arguments_complex(self):
        self.route_match({"arguments": {"foo": ""}})

        assert self.get(url='/?foo')['status'] == 200, 'complex'
        assert self.get(url='/?blah=blah&foo=')['status'] == 200, 'complex 2'
        assert self.get(url='/?&&&foo&&&')['status'] == 200, 'complex 3'
        assert self.get(url='/?foo&foo=bar&foo')['status'] == 404, 'complex 4'
        assert self.get(url='/?foo=&foo')['status'] == 200, 'complex 5'
        assert self.get(url='/?&=&foo&==&')['status'] == 200, 'complex 6'
        assert self.get(url='/?&=&bar&==&')['status'] == 404, 'complex 7'

    def test_routes_match_arguments_multiple(self):
        self.route_match({"arguments": {"foo": "bar", "blah": "test"}})

        assert self.get()['status'] == 404, 'multiple'
        assert (
            self.get(url='/?foo=bar&blah=test')['status'] == 200
        ), 'multiple 2'
        assert self.get(url='/?foo=bar&blah')['status'] == 404, 'multiple 3'
        assert (
            self.get(url='/?foo=bar&blah=tes')['status'] == 404
        ), 'multiple 4'
        assert (
            self.get(url='/?foo=b%61r&bl%61h=t%65st')['status'] == 200
        ), 'multiple 5'

    def test_routes_match_arguments_multiple_rules(self):
        self.route_match({"arguments": {"foo": ["bar", "blah"]}})

        assert self.get()['status'] == 404, 'rules'
        assert self.get(url='/?foo=bar')['status'] == 200, 'rules 2'
        assert self.get(url='/?foo=blah')['status'] == 200, 'rules 3'
        assert (
            self.get(url='/?foo=blah&foo=bar&foo=blah')['status'] == 200
        ), 'rules 4'
        assert (
            self.get(url='/?foo=blah&foo=bar&foo=')['status'] == 404
        ), 'rules 5'

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

        assert self.get()['status'] == 404, 'arr'
        assert self.get(url='/?var1=val123')['status'] == 200, 'arr 2'
        assert self.get(url='/?var2=val2')['status'] == 200, 'arr 3'
        assert self.get(url='/?var3=bar')['status'] == 200, 'arr 4'
        assert self.get(url='/?var1=bar')['status'] == 404, 'arr 5'
        assert self.get(url='/?var1=bar&var4=foo')['status'] == 200, 'arr 6'

        assert 'success' in self.conf_delete(
            'routes/0/match/arguments/1'
        ), 'match arguments array configure 2'

        assert self.get(url='/?var2=val2')['status'] == 404, 'arr 7'
        assert self.get(url='/?var3=foo')['status'] == 200, 'arr 8'

    def test_routes_match_arguments_invalid(self):
        self.route_match_invalid({"arguments": ["var"]})
        self.route_match_invalid({"arguments": [{"var1": {}}]})
        self.route_match_invalid({"arguments": {"": "bar"}})
        self.route_match_invalid({"arguments": {"foo": "%"}})
        self.route_match_invalid({"arguments": {"foo": "%1G"}})
        self.route_match_invalid({"arguments": {"%": "bar"}})
        self.route_match_invalid({"arguments": {"foo": "%0"}})
        self.route_match_invalid({"arguments": {"foo": "%%1F"}})
        self.route_match_invalid({"arguments": {"%%1F": ""}})
        self.route_match_invalid({"arguments": {"%7%F": ""}})

    def test_routes_match_cookies(self):
        self.route_match({"cookies": {"foO": "bar"}})

        assert self.get()['status'] == 404, 'cookie'
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
        assert self.get()['status'] == 200, 'cookies empty'

        self.route_match({"cookies": []})
        assert self.get()['status'] == 200, 'cookies empty 2'

    def test_routes_match_cookies_invalid(self):
        self.route_match_invalid({"cookies": ["var"]})
        self.route_match_invalid({"cookies": [{"foo": {}}]})

    def test_routes_match_cookies_multiple(self):
        self.route_match({"cookies": {"foo": "bar", "blah": "blah"}})

        assert self.get()['status'] == 404, 'multiple'
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

        assert self.get()['status'] == 404, 'multiple rules'
        self.cookie('blah=test', 200)
        self.cookie('blah=blah', 200)
        self.cookie(['blah=blah', 'blah=test', 'blah=blah'], 200)
        self.cookie(['blah=blah; blah=test', 'blah=blah'], 200)
        self.cookie(['blah=blah', 'blah'], 200)  # invalid cookie

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

        assert self.get()['status'] == 404, 'cookies array'
        self.cookie('var1=val123', 200)
        self.cookie('var2=val2', 200)
        self.cookie(' var2=val2 ', 200)
        self.cookie('var3=bar', 200)
        self.cookie('var3=bar;', 200)
        self.cookie('var1=bar', 404)
        self.cookie('var1=bar; var4=foo;', 200)
        self.cookie(['var1=bar', 'var4=foo'], 200)

        assert 'success' in self.conf_delete(
            'routes/0/match/cookies/1'
        ), 'match cookies array configure 2'

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
        assert self.get(sock=sock)['status'] == 200, 'exact'
        assert self.get(sock=sock2)['status'] == 404, 'exact 2'

        sock, port = sock_port()
        sock2, port2 = sock_port()

        self.route_match({"source": "!127.0.0.1:" + str(port)})
        assert self.get(sock=sock)['status'] == 404, 'negative'
        assert self.get(sock=sock2)['status'] == 200, 'negative 2'

        sock, port = sock_port()
        sock2, port2 = sock_port()

        self.route_match({"source": ["*:" + str(port), "!127.0.0.1"]})
        assert self.get(sock=sock)['status'] == 404, 'negative 3'
        assert self.get(sock=sock2)['status'] == 404, 'negative 4'

        sock, port = sock_port()
        sock2, port2 = sock_port()

        self.route_match(
            {"source": "127.0.0.1:" + str(port) + "-" + str(port)}
        )
        assert self.get(sock=sock)['status'] == 200, 'range single'
        assert self.get(sock=sock2)['status'] == 404, 'range single 2'

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
        assert self.get(sock=socks[0][0])['status'] == 404, 'range'
        assert self.get(sock=socks[1][0])['status'] == 200, 'range 2'
        assert self.get(sock=socks[2][0])['status'] == 200, 'range 3'
        assert self.get(sock=socks[3][0])['status'] == 200, 'range 4'
        assert self.get(sock=socks[4][0])['status'] == 404, 'range 5'

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
        assert self.get(sock=socks[0][0])['status'] == 200, 'array'
        assert self.get(sock=socks[1][0])['status'] == 404, 'array 2'
        assert self.get(sock=socks[2][0])['status'] == 200, 'array 3'

    def test_routes_source_addr(self):
        assert 'success' in self.conf(
            {"*:7080": {"pass": "routes"}, "[::1]:7081": {"pass": "routes"},},
            'listeners',
        ), 'source listeners configure'

        def get_ipv6():
            return self.get(sock_type='ipv6', port=7081)

        self.route_match({"source": "127.0.0.1"})
        assert self.get()['status'] == 200, 'exact'
        assert get_ipv6()['status'] == 404, 'exact ipv6'

        self.route_match({"source": ["127.0.0.1"]})
        assert self.get()['status'] == 200, 'exact 2'
        assert get_ipv6()['status'] == 404, 'exact 2 ipv6'

        self.route_match({"source": "!127.0.0.1"})
        assert self.get()['status'] == 404, 'exact neg'
        assert get_ipv6()['status'] == 200, 'exact neg ipv6'

        self.route_match({"source": "127.0.0.2"})
        assert self.get()['status'] == 404, 'exact 3'
        assert get_ipv6()['status'] == 404, 'exact 3 ipv6'

        self.route_match({"source": "127.0.0.1-127.0.0.1"})
        assert self.get()['status'] == 200, 'range single'
        assert get_ipv6()['status'] == 404, 'range single ipv6'

        self.route_match({"source": "127.0.0.2-127.0.0.2"})
        assert self.get()['status'] == 404, 'range single 2'
        assert get_ipv6()['status'] == 404, 'range single 2 ipv6'

        self.route_match({"source": "127.0.0.2-127.0.0.3"})
        assert self.get()['status'] == 404, 'range'
        assert get_ipv6()['status'] == 404, 'range ipv6'

        self.route_match({"source": "127.0.0.1-127.0.0.2"})
        assert self.get()['status'] == 200, 'range 2'
        assert get_ipv6()['status'] == 404, 'range 2 ipv6'

        self.route_match({"source": "127.0.0.0-127.0.0.2"})
        assert self.get()['status'] == 200, 'range 3'
        assert get_ipv6()['status'] == 404, 'range 3 ipv6'

        self.route_match({"source": "127.0.0.0-127.0.0.1"})
        assert self.get()['status'] == 200, 'range 4'
        assert get_ipv6()['status'] == 404, 'range 4 ipv6'

        self.route_match({"source": "126.0.0.0-127.0.0.0"})
        assert self.get()['status'] == 404, 'range 5'
        assert get_ipv6()['status'] == 404, 'range 5 ipv6'

        self.route_match({"source": "126.126.126.126-127.0.0.2"})
        assert self.get()['status'] == 200, 'range 6'
        assert get_ipv6()['status'] == 404, 'range 6 ipv6'

    def test_routes_source_ipv6(self):
        assert 'success' in self.conf(
            {
                "[::1]:7080": {"pass": "routes"},
                "127.0.0.1:7081": {"pass": "routes"},
            },
            'listeners',
        ), 'source listeners configure'

        self.route_match({"source": "::1"})
        assert self.get(sock_type='ipv6')['status'] == 200, 'exact'
        assert self.get(port=7081)['status'] == 404, 'exact ipv4'

        self.route_match({"source": ["::1"]})
        assert self.get(sock_type='ipv6')['status'] == 200, 'exact 2'
        assert self.get(port=7081)['status'] == 404, 'exact 2 ipv4'

        self.route_match({"source": "!::1"})
        assert self.get(sock_type='ipv6')['status'] == 404, 'exact neg'
        assert self.get(port=7081)['status'] == 200, 'exact neg ipv4'

        self.route_match({"source": "::2"})
        assert self.get(sock_type='ipv6')['status'] == 404, 'exact 3'
        assert self.get(port=7081)['status'] == 404, 'exact 3 ipv4'

        self.route_match({"source": "::1-::1"})
        assert self.get(sock_type='ipv6')['status'] == 200, 'range'
        assert self.get(port=7081)['status'] == 404, 'range ipv4'

        self.route_match({"source": "::2-::2"})
        assert self.get(sock_type='ipv6')['status'] == 404, 'range 2'
        assert self.get(port=7081)['status'] == 404, 'range 2 ipv4'

        self.route_match({"source": "::2-::3"})
        assert self.get(sock_type='ipv6')['status'] == 404, 'range 3'
        assert self.get(port=7081)['status'] == 404, 'range 3 ipv4'

        self.route_match({"source": "::1-::2"})
        assert self.get(sock_type='ipv6')['status'] == 200, 'range 4'
        assert self.get(port=7081)['status'] == 404, 'range 4 ipv4'

        self.route_match({"source": "::0-::2"})
        assert self.get(sock_type='ipv6')['status'] == 200, 'range 5'
        assert self.get(port=7081)['status'] == 404, 'range 5 ipv4'

        self.route_match({"source": "::0-::1"})
        assert self.get(sock_type='ipv6')['status'] == 200, 'range 6'
        assert self.get(port=7081)['status'] == 404, 'range 6 ipv4'

    def test_routes_source_cidr(self):
        assert 'success' in self.conf(
            {"*:7080": {"pass": "routes"}, "[::1]:7081": {"pass": "routes"},},
            'listeners',
        ), 'source listeners configure'

        def get_ipv6():
            return self.get(sock_type='ipv6', port=7081)

        self.route_match({"source": "127.0.0.1/32"})
        assert self.get()['status'] == 200, '32'
        assert get_ipv6()['status'] == 404, '32 ipv6'

        self.route_match({"source": "127.0.0.0/32"})
        assert self.get()['status'] == 404, '32 2'
        assert get_ipv6()['status'] == 404, '32 2 ipv6'

        self.route_match({"source": "127.0.0.0/31"})
        assert self.get()['status'] == 200, '31'
        assert get_ipv6()['status'] == 404, '31 ipv6'

        self.route_match({"source": "0.0.0.0/1"})
        assert self.get()['status'] == 200, '1'
        assert get_ipv6()['status'] == 404, '1 ipv6'

        self.route_match({"source": "0.0.0.0/0"})
        assert self.get()['status'] == 200, '0'
        assert get_ipv6()['status'] == 404, '0 ipv6'

    def test_routes_source_cidr_ipv6(self):
        assert 'success' in self.conf(
            {
                "[::1]:7080": {"pass": "routes"},
                "127.0.0.1:7081": {"pass": "routes"},
            },
            'listeners',
        ), 'source listeners configure'

        self.route_match({"source": "::1/128"})
        assert self.get(sock_type='ipv6')['status'] == 200, '128'
        assert self.get(port=7081)['status'] == 404, '128 ipv4'

        self.route_match({"source": "::0/128"})
        assert self.get(sock_type='ipv6')['status'] == 404, '128 2'
        assert self.get(port=7081)['status'] == 404, '128 ipv4'

        self.route_match({"source": "::0/127"})
        assert self.get(sock_type='ipv6')['status'] == 200, '127'
        assert self.get(port=7081)['status'] == 404, '127 ipv4'

        self.route_match({"source": "::0/32"})
        assert self.get(sock_type='ipv6')['status'] == 200, '32'
        assert self.get(port=7081)['status'] == 404, '32 ipv4'

        self.route_match({"source": "::0/1"})
        assert self.get(sock_type='ipv6')['status'] == 200, '1'
        assert self.get(port=7081)['status'] == 404, '1 ipv4'

        self.route_match({"source": "::/0"})
        assert self.get(sock_type='ipv6')['status'] == 200, '0'
        assert self.get(port=7081)['status'] == 404, '0 ipv4'

    def test_routes_source_unix(self, temp_dir):
        addr = temp_dir + '/sock'

        assert 'success' in self.conf(
            {"unix:" + addr: {"pass": "routes"}}, 'listeners'
        ), 'source listeners configure'

        self.route_match({"source": "!0.0.0.0/0"})
        assert (
            self.get(sock_type='unix', addr=addr)['status'] == 200
        ), 'unix ipv4'

        self.route_match({"source": "!::/0"})
        assert (
            self.get(sock_type='unix', addr=addr)['status'] == 200
        ), 'unix ipv6'

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
        assert self.get()['status'] == 200, 'source any'

    def test_routes_match_source_invalid(self):
        self.route_match_invalid({"source": "127"})
        self.route_match_invalid({"source": "256.0.0.1"})
        self.route_match_invalid({"source": "127.0.0."})
        self.route_match_invalid({"source": " 127.0.0.1"})
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
        assert 'success' in self.conf(
            {"*:7080": {"pass": "routes"}, "*:7081": {"pass": "routes"}},
            'listeners',
        ), 'listeners configure'

        self.route_match({"destination": "*:7080"})
        assert self.get()['status'] == 200, 'dest'
        assert self.get(port=7081)['status'] == 404, 'dest 2'

        self.route_match({"destination": ["127.0.0.1:7080"]})
        assert self.get()['status'] == 200, 'dest 3'
        assert self.get(port=7081)['status'] == 404, 'dest 4'

        self.route_match({"destination": "!*:7080"})
        assert self.get()['status'] == 404, 'dest neg'
        assert self.get(port=7081)['status'] == 200, 'dest neg 2'

        self.route_match({"destination": ['!*:7080', '!*:7081']})
        assert self.get()['status'] == 404, 'dest neg 3'
        assert self.get(port=7081)['status'] == 404, 'dest neg 4'

        self.route_match({"destination": ['!*:7081', '!*:7082']})
        assert self.get()['status'] == 200, 'dest neg 5'

        self.route_match({"destination": ['*:7080', '!*:7080']})
        assert self.get()['status'] == 404, 'dest neg 6'

        self.route_match(
            {"destination": ['127.0.0.1:7080', '*:7081', '!*:7080']}
        )
        assert self.get()['status'] == 404, 'dest neg 7'
        assert self.get(port=7081)['status'] == 200, 'dest neg 8'

        self.route_match({"destination": ['!*:7081', '!*:7082', '*:7083']})
        assert self.get()['status'] == 404, 'dest neg 9'

        self.route_match(
            {"destination": ['*:7081', '!127.0.0.1:7080', '*:7080']}
        )
        assert self.get()['status'] == 404, 'dest neg 10'
        assert self.get(port=7081)['status'] == 200, 'dest neg 11'

        assert 'success' in self.conf_delete(
            'routes/0/match/destination/0'
        ), 'remove destination rule'
        assert self.get()['status'] == 404, 'dest neg 12'
        assert self.get(port=7081)['status'] == 404, 'dest neg 13'

        assert 'success' in self.conf_delete(
            'routes/0/match/destination/0'
        ), 'remove destination rule 2'
        assert self.get()['status'] == 200, 'dest neg 14'
        assert self.get(port=7081)['status'] == 404, 'dest neg 15'

        assert 'success' in self.conf_post(
            "\"!127.0.0.1\"", 'routes/0/match/destination'
        ), 'add destination rule'
        assert self.get()['status'] == 404, 'dest neg 16'
        assert self.get(port=7081)['status'] == 404, 'dest neg 17'

    def test_routes_match_destination_proxy(self):
        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {"pass": "routes/first"},
                    "*:7081": {"pass": "routes/second"},
                },
                "routes": {
                    "first": [{"action": {"proxy": "http://127.0.0.1:7081"}}],
                    "second": [
                        {
                            "match": {"destination": ["127.0.0.1:7081"]},
                            "action": {"return": 200},
                        }
                    ],
                },
                "applications": {},
            }
        ), 'proxy configure'

        assert self.get()['status'] == 200, 'proxy'
