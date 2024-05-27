# -*- coding: utf-8 -*-
import pytest

from unit.applications.lang.python import ApplicationPython
from unit.option import option

prerequisites = {'modules': {'python': 'any'}}

client = ApplicationPython()


@pytest.fixture(autouse=True)
def setup_method_fixture():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [
                {
                    "match": {"method": "GET"},
                    "action": {"return": 200},
                }
            ],
            "applications": {},
        }
    ), 'routing configure'


def route(conf_route):
    return client.conf([conf_route], 'routes')


def route_match(match):
    assert 'success' in route(
        {"match": match, "action": {"return": 200}}
    ), 'route match configure'


def route_match_invalid(match):
    assert 'error' in route(
        {"match": match, "action": {"return": 200}}
    ), 'route match configure invalid'


def host(host_header, status):
    assert (
        client.get(headers={'Host': host_header, 'Connection': 'close'})[
            'status'
        ]
        == status
    ), 'match host'


def cookie(cookie_header, status):
    assert (
        client.get(
            headers={
                'Host': 'localhost',
                'Cookie': cookie_header,
                'Connection': 'close',
            },
        )['status']
        == status
    ), 'match cookie'


def test_routes_match_method_positive():
    assert client.get()['status'] == 200, 'GET'
    assert client.post()['status'] == 404, 'POST'


def test_routes_match_method_positive_many():
    route_match({"method": ["GET", "POST"]})

    assert client.get()['status'] == 200, 'GET'
    assert client.post()['status'] == 200, 'POST'
    assert client.delete()['status'] == 404, 'DELETE'


def test_routes_match_method_negative():
    route_match({"method": "!GET"})

    assert client.get()['status'] == 404, 'GET'
    assert client.post()['status'] == 200, 'POST'


def test_routes_match_method_negative_many():
    route_match({"method": ["!GET", "!POST"]})

    assert client.get()['status'] == 404, 'GET'
    assert client.post()['status'] == 404, 'POST'
    assert client.delete()['status'] == 200, 'DELETE'


def test_routes_match_method_wildcard_left():
    route_match({"method": "*ET"})

    assert client.get()['status'] == 200, 'GET'
    assert client.post()['status'] == 404, 'POST'


def test_routes_match_method_wildcard_right():
    route_match({"method": "GE*"})

    assert client.get()['status'] == 200, 'GET'
    assert client.post()['status'] == 404, 'POST'


def test_routes_match_method_wildcard_left_right():
    route_match({"method": "*GET*"})

    assert client.get()['status'] == 200, 'GET'
    assert client.post()['status'] == 404, 'POST'


def test_routes_match_method_wildcard():
    route_match({"method": "*"})

    assert client.get()['status'] == 200, 'GET'


def test_routes_match_invalid():
    route_match_invalid({"method": "**"})


def test_routes_match_valid():
    route_match({"method": "blah*"})
    route_match({"host": "*blah*blah"})
    route_match({"host": "blah*blah*blah"})
    route_match({"host": "blah*blah*"})


def test_routes_match_empty_exact():
    route_match({"uri": ""})
    assert client.get()['status'] == 404

    route_match({"uri": "/"})
    assert client.get()['status'] == 200
    assert client.get(url='/blah')['status'] == 404


def test_routes_match_negative():
    route_match({"uri": "!"})
    assert client.get()['status'] == 200

    route_match({"uri": "!*"})
    assert client.get()['status'] == 404

    route_match({"uri": "!/"})
    assert client.get()['status'] == 404
    assert client.get(url='/blah')['status'] == 200

    route_match({"uri": "!*blah"})
    assert client.get()['status'] == 200
    assert client.get(url='/bla')['status'] == 200
    assert client.get(url='/blah')['status'] == 404
    assert client.get(url='/blah1')['status'] == 200

    route_match({"uri": "!/blah*1*"})
    assert client.get()['status'] == 200
    assert client.get(url='/blah')['status'] == 200
    assert client.get(url='/blah1')['status'] == 404
    assert client.get(url='/blah12')['status'] == 404
    assert client.get(url='/blah2')['status'] == 200


def test_routes_match_wildcard_middle():
    route_match({"host": "ex*le"})

    host('example', 200)
    host('www.example', 404)
    host('example.com', 404)
    host('exampl', 404)


def test_routes_match_method_case_insensitive():
    route_match({"method": "get"})

    assert client.get()['status'] == 200, 'GET'


def test_routes_match_wildcard_left_case_insensitive():
    route_match({"method": "*get"})
    assert client.get()['status'] == 200, 'GET'

    route_match({"method": "*et"})
    assert client.get()['status'] == 200, 'GET'


def test_routes_match_wildcard_middle_case_insensitive():
    route_match({"method": "g*t"})

    assert client.get()['status'] == 200, 'GET'


def test_routes_match_wildcard_right_case_insensitive():
    route_match({"method": "get*"})
    assert client.get()['status'] == 200, 'GET'

    route_match({"method": "ge*"})
    assert client.get()['status'] == 200, 'GET'


def test_routes_match_wildcard_substring_case_insensitive():
    route_match({"method": "*et*"})

    assert client.get()['status'] == 200, 'GET'


def test_routes_match_wildcard_left_case_sensitive():
    route_match({"uri": "*blah"})

    assert client.get(url='/blah')['status'] == 200, '/blah'
    assert client.get(url='/BLAH')['status'] == 404, '/BLAH'


def test_routes_match_wildcard_middle_case_sensitive():
    route_match({"uri": "/b*h"})

    assert client.get(url='/blah')['status'] == 200, '/blah'
    assert client.get(url='/BLAH')['status'] == 404, '/BLAH'


def test_route_match_wildcards_ordered():
    route_match({"uri": "/a*x*y*"})

    assert client.get(url='/axy')['status'] == 200, '/axy'
    assert client.get(url='/ayx')['status'] == 404, '/ayx'


def test_route_match_wildcards_adjust_start():
    route_match({"uri": "/bla*bla*"})

    assert client.get(url='/bla_foo')['status'] == 404, '/bla_foo'


def test_route_match_wildcards_adjust_start_substr():
    route_match({"uri": "*bla*bla*"})

    assert client.get(url='/bla_foo')['status'] == 404, '/bla_foo'


def test_route_match_wildcards_adjust_end():
    route_match({"uri": "/bla*bla"})

    assert client.get(url='/foo_bla')['status'] == 404, '/foo_bla'


def test_routes_match_wildcard_right_case_sensitive():
    route_match({"uri": "/bla*"})

    assert client.get(url='/blah')['status'] == 200, '/blah'
    assert client.get(url='/BLAH')['status'] == 404, '/BLAH'


def test_routes_match_wildcard_substring_case_sensitive():
    route_match({"uri": "*bla*"})

    assert client.get(url='/blah')['status'] == 200, '/blah'
    assert client.get(url='/BLAH')['status'] == 404, '/BLAH'


def test_routes_match_many_wildcard_substrings_case_sensitive():
    route_match({"uri": "*a*B*c*"})

    assert client.get(url='/blah-a-B-c-blah')['status'] == 200
    assert client.get(url='/a-B-c')['status'] == 200
    assert client.get(url='/aBc')['status'] == 200
    assert client.get(url='/aBCaBbc')['status'] == 200
    assert client.get(url='/ABc')['status'] == 404


def test_routes_empty_regex(require):
    require({'modules': {'regex': True}})

    route_match({"uri": "~"})
    assert client.get(url='/')['status'] == 200, 'empty regexp'
    assert client.get(url='/anything')['status'] == 200, '/anything'

    route_match({"uri": "!~"})
    assert client.get(url='/')['status'] == 404, 'empty regexp 2'
    assert client.get(url='/nothing')['status'] == 404, '/nothing'


def test_routes_bad_regex(require):
    require({'modules': {'regex': True}})

    assert 'error' in route(
        {"match": {"uri": "~/bl[ah"}, "action": {"return": 200}}
    ), 'bad regex'

    status = route({"match": {"uri": "~(?R)?z"}, "action": {"return": 200}})
    if 'error' not in status:
        assert client.get(url='/nothing_z')['status'] == 500, '/nothing_z'

    status = route({"match": {"uri": "~((?1)?z)"}, "action": {"return": 200}})
    if 'error' not in status:
        assert client.get(url='/nothing_z')['status'] == 500, '/nothing_z'


def test_routes_match_regex_case_sensitive(require):
    require({'modules': {'regex': True}})

    route_match({"uri": "~/bl[ah]"})

    assert client.get(url='/rlah')['status'] == 404, '/rlah'
    assert client.get(url='/blah')['status'] == 200, '/blah'
    assert client.get(url='/blh')['status'] == 200, '/blh'
    assert client.get(url='/BLAH')['status'] == 404, '/BLAH'


def test_routes_match_regex_negative_case_sensitive(require):
    require({'modules': {'regex': True}})

    route_match({"uri": "!~/bl[ah]"})

    assert client.get(url='/rlah')['status'] == 200, '/rlah'
    assert client.get(url='/blah')['status'] == 404, '/blah'
    assert client.get(url='/blh')['status'] == 404, '/blh'
    assert client.get(url='/BLAH')['status'] == 200, '/BLAH'


def test_routes_pass_encode():
    python_dir = f'{option.test_dir}/python'

    def check_pass(path, name):
        assert 'success' in client.conf(
            {
                "listeners": {"*:8080": {"pass": f'applications/{path}'}},
                "applications": {
                    name: {
                        "type": client.get_application_type(),
                        "processes": {"spare": 0},
                        "path": f'{python_dir}/empty',
                        "working_directory": f'{python_dir}/empty',
                        "module": "wsgi",
                    }
                },
            }
        )

        assert client.get()['status'] == 200

    check_pass("%25", "%")
    check_pass("blah%2Fblah", "blah/blah")
    check_pass("%2Fblah%2F%2Fblah%2F", "/blah//blah/")
    check_pass("%20blah%252Fblah%7E", " blah%2Fblah~")

    def check_pass_error(path, name):
        assert 'error' in client.conf(
            {
                "listeners": {"*:8080": {"pass": f'applications/{path}'}},
                "applications": {
                    name: {
                        "type": client.get_application_type(),
                        "processes": {"spare": 0},
                        "path": f'{python_dir}/empty',
                        "working_directory": f'{python_dir}/empty',
                        "module": "wsgi",
                    }
                },
            }
        )

    check_pass_error("%", "%")
    check_pass_error("%1", "%1")


def test_routes_absent():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8081": {"pass": "applications/empty"}},
            "applications": {
                "empty": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": f'{option.test_dir}/python/empty',
                    "working_directory": f'{option.test_dir}/python/empty',
                    "module": "wsgi",
                }
            },
        }
    )

    assert client.get(port=8081)['status'] == 200, 'routes absent'


def test_routes_pass_invalid():
    assert 'error' in client.conf(
        {"pass": "routes/blah"}, 'listeners/*:8080'
    ), 'routes invalid'


def test_route_empty():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes/main"}},
            "routes": {"main": []},
            "applications": {},
        }
    ), 'route empty configure'

    assert client.get()['status'] == 404, 'route empty'


def test_routes_route_empty():
    assert 'success' in client.conf(
        {}, 'listeners'
    ), 'routes empty listeners configure'

    assert 'success' in client.conf({}, 'routes'), 'routes empty configure'


def test_routes_route_match_absent():
    assert 'success' in client.conf(
        [{"action": {"return": 200}}], 'routes'
    ), 'route match absent configure'

    assert client.get()['status'] == 200, 'route match absent'


def test_routes_route_action_absent(skip_alert):
    skip_alert(r'failed to apply new conf')

    assert 'error' in client.conf(
        [{"match": {"method": "GET"}}], 'routes'
    ), 'route pass absent configure'


def test_routes_route_pass():
    assert 'success' in client.conf(
        {
            "applications": {
                "app": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
            },
            "upstreams": {
                "one": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
                "two": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
            },
        }
    )

    assert 'success' in client.conf([{"action": {"pass": "routes"}}], 'routes')
    assert 'success' in client.conf(
        [{"action": {"pass": "applications/app"}}], 'routes'
    )
    assert 'success' in client.conf(
        [{"action": {"pass": "upstreams/one"}}], 'routes'
    )


def test_routes_route_pass_absent():
    assert 'error' in client.conf(
        [{"match": {"method": "GET"}, "action": {}}], 'routes'
    ), 'route pass absent configure'


def test_routes_route_pass_invalid():
    assert 'success' in client.conf(
        {
            "applications": {
                "app": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
            },
            "upstreams": {
                "one": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
                "two": {
                    "servers": {
                        "127.0.0.1:8081": {},
                        "127.0.0.1:8082": {},
                    },
                },
            },
        }
    )

    assert 'error' in client.conf(
        [{"action": {"pass": "blah"}}], 'routes'
    ), 'route pass invalid'
    assert 'error' in client.conf(
        [{"action": {"pass": "routes/blah"}}], 'routes'
    ), 'route pass routes invalid'
    assert 'error' in client.conf(
        [{"action": {"pass": "applications/blah"}}], 'routes'
    ), 'route pass applications invalid'
    assert 'error' in client.conf(
        [{"action": {"pass": "upstreams/blah"}}], 'routes'
    ), 'route pass upstreams invalid'


def test_routes_action_unique(temp_dir):
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes"},
                "*:8081": {"pass": "applications/app"},
            },
            "routes": [{"action": {"proxy": "http://127.0.0.1:8081"}}],
            "applications": {
                "app": {
                    "type": client.get_application_type(),
                    "processes": {"spare": 0},
                    "path": "/app",
                    "module": "wsgi",
                }
            },
        }
    )

    assert 'error' in client.conf(
        {"proxy": "http://127.0.0.1:8081", "share": temp_dir},
        'routes/0/action',
    ), 'proxy share'
    assert 'error' in client.conf(
        {
            "proxy": "http://127.0.0.1:8081",
            "pass": "applications/app",
        },
        'routes/0/action',
    ), 'proxy pass'
    assert 'error' in client.conf(
        {"share": temp_dir, "pass": "applications/app"},
        'routes/0/action',
    ), 'share pass'


def test_routes_rules_two():
    assert 'success' in client.conf(
        [
            {"match": {"method": "GET"}, "action": {"return": 200}},
            {"match": {"method": "POST"}, "action": {"return": 201}},
        ],
        'routes',
    ), 'rules two configure'

    assert client.get()['status'] == 200, 'rules two match first'
    assert client.post()['status'] == 201, 'rules two match second'


def test_routes_two():
    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes/first"}},
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

    assert client.get()['status'] == 200, 'routes two'


def test_routes_match_host_positive():
    route_match({"host": "localhost"})

    assert client.get()['status'] == 200, 'localhost'
    host('localhost.', 200)
    host('localhost.', 200)
    host('.localhost', 404)
    host('www.localhost', 404)
    host('localhost1', 404)


@pytest.mark.skip('not yet')
def test_routes_match_host_absent():
    route_match({"host": "localhost"})

    assert (
        client.get(headers={'Connection': 'close'})['status'] == 400
    ), 'match host absent'


def test_routes_match_host_ipv4():
    route_match({"host": "127.0.0.1"})

    host('127.0.0.1', 200)
    host('127.0.0.1:8080', 200)


def test_routes_match_host_ipv6():
    route_match({"host": "[::1]"})

    host('[::1]', 200)
    host('[::1]:8080', 200)


def test_routes_match_host_positive_many():
    route_match({"host": ["localhost", "example.com"]})

    assert client.get()['status'] == 200, 'localhost'
    host('example.com', 200)


def test_routes_match_host_positive_and_negative():
    route_match({"host": ["*example.com", "!www.example.com"]})

    assert client.get()['status'] == 404, 'localhost'
    host('example.com', 200)
    host('www.example.com', 404)
    host('!www.example.com', 200)


def test_routes_match_host_positive_and_negative_wildcard():
    route_match({"host": ["*example*", "!www.example*"]})

    host('example.com', 200)
    host('www.example.com', 404)


def test_routes_match_host_case_insensitive():
    route_match({"host": "Example.com"})

    host('example.com', 200)
    host('EXAMPLE.COM', 200)


def test_routes_match_host_port():
    route_match({"host": "example.com"})

    host('example.com:8080', 200)


def test_routes_match_host_empty():
    route_match({"host": ""})

    host('', 200)
    assert (
        client.get(http_10=True, headers={})['status'] == 200
    ), 'match host empty 2'
    assert client.get()['status'] == 404, 'match host empty 3'


def test_routes_match_uri_positive():
    route_match({"uri": ["/blah", "/slash/"]})

    assert client.get()['status'] == 404, '/'
    assert client.get(url='/blah')['status'] == 200, '/blah'
    assert client.get(url='/blah#foo')['status'] == 200, '/blah#foo'
    assert client.get(url='/blah?var')['status'] == 200, '/blah?var'
    assert client.get(url='//blah')['status'] == 200, '//blah'
    assert client.get(url='/slash/foo/../')['status'] == 200, 'relative'
    assert client.get(url='/slash/./')['status'] == 200, '/slash/./'
    assert client.get(url='/slash//.//')['status'] == 200, 'adjacent slashes'
    assert client.get(url='/%')['status'] == 400, 'percent'
    assert client.get(url='/%1')['status'] == 400, 'percent digit'
    assert client.get(url='/%A')['status'] == 400, 'percent letter'
    assert client.get(url='/slash/.?args')['status'] == 200, 'dot args'
    assert client.get(url='/slash/.#frag')['status'] == 200, 'dot frag'
    assert client.get(url='/slash/foo/..?args')['status'] == 200, 'dot dot args'
    assert client.get(url='/slash/foo/..#frag')['status'] == 200, 'dot dot frag'
    assert client.get(url='/slash/.')['status'] == 200, 'trailing dot'
    assert client.get(url='/slash/foo/..')['status'] == 200, 'trailing dot dot'


def test_routes_match_uri_case_sensitive():
    route_match({"uri": "/BLAH"})

    assert client.get(url='/blah')['status'] == 404, '/blah'
    assert client.get(url='/BlaH')['status'] == 404, '/BlaH'
    assert client.get(url='/BLAH')['status'] == 200, '/BLAH'


def test_routes_match_uri_normalize():
    route_match({"uri": "/blah"})

    assert client.get(url='/%62%6c%61%68')['status'] == 200, 'normalize'


def test_routes_match_empty_array():
    route_match({"uri": []})

    assert client.get(url='/blah')['status'] == 200, 'empty array'


def test_routes_reconfigure():
    assert 'success' in client.conf([], 'routes'), 'redefine'
    assert client.get()['status'] == 404, 'redefine request'

    assert 'success' in client.conf(
        [{"action": {"return": 200}}], 'routes'
    ), 'redefine 2'
    assert client.get()['status'] == 200, 'redefine request 2'

    assert 'success' in client.conf([], 'routes'), 'redefine 3'
    assert client.get()['status'] == 404, 'redefine request 3'

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes/main"}},
            "routes": {"main": [{"action": {"return": 200}}]},
            "applications": {},
        }
    ), 'redefine 4'
    assert client.get()['status'] == 200, 'redefine request 4'

    assert 'success' in client.conf_delete('routes/main/0'), 'redefine 5'
    assert client.get()['status'] == 404, 'redefine request 5'

    assert 'success' in client.conf_post(
        {"action": {"return": 200}}, 'routes/main'
    ), 'redefine 6'
    assert client.get()['status'] == 200, 'redefine request 6'

    assert 'error' in client.conf(
        {"action": {"return": 200}}, 'routes/main/2'
    ), 'redefine 7'
    assert 'success' in client.conf(
        {"action": {"return": 201}}, 'routes/main/1'
    ), 'redefine 8'

    assert len(client.conf_get('routes/main')) == 2, 'redefine conf 8'
    assert client.get()['status'] == 200, 'redefine request 8'


def test_routes_edit():
    route_match({"method": "GET"})

    assert client.get()['status'] == 200, 'routes edit GET'
    assert client.post()['status'] == 404, 'routes edit POST'

    assert 'success' in client.conf_post(
        {"match": {"method": "POST"}, "action": {"return": 200}},
        'routes',
    ), 'routes edit configure 2'
    assert 'GET' == client.conf_get(
        'routes/0/match/method'
    ), 'routes edit configure 2 check'
    assert 'POST' == client.conf_get(
        'routes/1/match/method'
    ), 'routes edit configure 2 check 2'

    assert client.get()['status'] == 200, 'routes edit GET 2'
    assert client.post()['status'] == 200, 'routes edit POST 2'

    assert 'success' in client.conf_delete(
        'routes/0'
    ), 'routes edit configure 3'

    assert client.get()['status'] == 404, 'routes edit GET 3'
    assert client.post()['status'] == 200, 'routes edit POST 3'

    assert 'error' in client.conf_delete(
        'routes/1'
    ), 'routes edit configure invalid'
    assert 'error' in client.conf_delete(
        'routes/-1'
    ), 'routes edit configure invalid 2'
    assert 'error' in client.conf_delete(
        'routes/blah'
    ), 'routes edit configure invalid 3'

    assert client.get()['status'] == 404, 'routes edit GET 4'
    assert client.post()['status'] == 200, 'routes edit POST 4'

    assert 'success' in client.conf_delete(
        'routes/0'
    ), 'routes edit configure 5'

    assert client.get()['status'] == 404, 'routes edit GET 5'
    assert client.post()['status'] == 404, 'routes edit POST 5'

    assert 'success' in client.conf_post(
        {"match": {"method": "POST"}, "action": {"return": 200}},
        'routes',
    ), 'routes edit configure 6'

    assert client.get()['status'] == 404, 'routes edit GET 6'
    assert client.post()['status'] == 200, 'routes edit POST 6'

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes/main"}},
            "routes": {"main": [{"action": {"return": 200}}]},
            "applications": {},
        }
    ), 'route edit configure 7'

    assert 'error' in client.conf_delete(
        'routes/0'
    ), 'routes edit configure invalid 4'
    assert 'error' in client.conf_delete(
        'routes/main'
    ), 'routes edit configure invalid 5'

    assert client.get()['status'] == 200, 'routes edit GET 7'

    assert 'success' in client.conf_delete(
        'listeners/*:8080'
    ), 'route edit configure 8'
    assert 'success' in client.conf_delete(
        'routes/main'
    ), 'route edit configure 9'


def test_match_edit(skip_alert):
    skip_alert(r'failed to apply new conf')

    route_match({"method": ["GET", "POST"]})

    assert client.get()['status'] == 200, 'match edit GET'
    assert client.post()['status'] == 200, 'match edit POST'
    assert client.put()['status'] == 404, 'match edit PUT'

    assert 'success' in client.conf_post(
        '\"PUT\"', 'routes/0/match/method'
    ), 'match edit configure 2'
    assert ['GET', 'POST', 'PUT'] == client.conf_get(
        'routes/0/match/method'
    ), 'match edit configure 2 check'

    assert client.get()['status'] == 200, 'match edit GET 2'
    assert client.post()['status'] == 200, 'match edit POST 2'
    assert client.put()['status'] == 200, 'match edit PUT 2'

    assert 'success' in client.conf_delete(
        'routes/0/match/method/1'
    ), 'match edit configure 3'
    assert ['GET', 'PUT'] == client.conf_get(
        'routes/0/match/method'
    ), 'match edit configure 3 check'

    assert client.get()['status'] == 200, 'match edit GET 3'
    assert client.post()['status'] == 404, 'match edit POST 3'
    assert client.put()['status'] == 200, 'match edit PUT 3'

    assert 'success' in client.conf_delete(
        'routes/0/match/method/1'
    ), 'match edit configure 4'
    assert ['GET'] == client.conf_get(
        'routes/0/match/method'
    ), 'match edit configure 4 check'

    assert client.get()['status'] == 200, 'match edit GET 4'
    assert client.post()['status'] == 404, 'match edit POST 4'
    assert client.put()['status'] == 404, 'match edit PUT 4'

    assert 'error' in client.conf_delete(
        'routes/0/match/method/1'
    ), 'match edit configure invalid'
    assert 'error' in client.conf_delete(
        'routes/0/match/method/-1'
    ), 'match edit configure invalid 2'
    assert 'error' in client.conf_delete(
        'routes/0/match/method/blah'
    ), 'match edit configure invalid 3'
    assert ['GET'] == client.conf_get(
        'routes/0/match/method'
    ), 'match edit configure 5 check'

    assert client.get()['status'] == 200, 'match edit GET 5'
    assert client.post()['status'] == 404, 'match edit POST 5'
    assert client.put()['status'] == 404, 'match edit PUT 5'

    assert 'success' in client.conf_delete(
        'routes/0/match/method/0'
    ), 'match edit configure 6'
    assert [] == client.conf_get(
        'routes/0/match/method'
    ), 'match edit configure 6 check'

    assert client.get()['status'] == 200, 'match edit GET 6'
    assert client.post()['status'] == 200, 'match edit POST 6'
    assert client.put()['status'] == 200, 'match edit PUT 6'

    assert 'success' in client.conf(
        '"GET"', 'routes/0/match/method'
    ), 'match edit configure 7'

    assert client.get()['status'] == 200, 'match edit GET 7'
    assert client.post()['status'] == 404, 'match edit POST 7'
    assert client.put()['status'] == 404, 'match edit PUT 7'

    assert 'error' in client.conf_delete(
        'routes/0/match/method/0'
    ), 'match edit configure invalid 5'
    assert 'error' in client.conf(
        {}, 'routes/0/action'
    ), 'match edit configure invalid 6'

    assert 'success' in client.conf(
        {}, 'routes/0/match'
    ), 'match edit configure 8'

    assert client.get()['status'] == 200, 'match edit GET 8'


def test_routes_match_rules():
    route_match({"method": "GET", "host": "localhost", "uri": "/"})

    assert client.get()['status'] == 200, 'routes match rules'


def test_routes_loop():
    assert 'success' in route(
        {"match": {"uri": "/"}, "action": {"pass": "routes"}}
    ), 'routes loop configure'

    assert client.get()['status'] == 500, 'routes loop'


def test_routes_match_headers():
    route_match({"headers": {"host": "localhost"}})

    assert client.get()['status'] == 200, 'match headers'
    host('Localhost', 200)
    host('localhost.com', 404)
    host('llocalhost', 404)
    host('host', 404)


def test_routes_match_headers_multiple():
    route_match({"headers": {"host": "localhost", "x-blah": "test"}})

    assert client.get()['status'] == 404, 'match headers multiple'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": "test",
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers multiple 2'

    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": "",
                "Connection": "close",
            }
        )['status']
        == 404
    ), 'match headers multiple 3'


def test_routes_match_headers_multiple_values():
    route_match({"headers": {"x-blah": "test"}})

    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": ["test", "test", "test"],
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers multiple values'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": ["test", "blah", "test"],
                "Connection": "close",
            }
        )['status']
        == 404
    ), 'match headers multiple values 2'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": ["test", "", "test"],
                "Connection": "close",
            }
        )['status']
        == 404
    ), 'match headers multiple values 3'


def test_routes_match_headers_multiple_rules():
    route_match({"headers": {"x-blah": ["test", "blah"]}})

    assert client.get()['status'] == 404, 'match headers multiple rules'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": "test",
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers multiple rules 2'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": "blah",
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers multiple rules 3'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": ["test", "blah", "test"],
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers multiple rules 4'

    assert (
        client.get(
            headers={
                "Host": "localhost",
                "X-blah": ["blah", ""],
                "Connection": "close",
            }
        )['status']
        == 404
    ), 'match headers multiple rules 5'


def test_routes_match_headers_case_insensitive():
    route_match({"headers": {"X-BLAH": "TEST"}})

    assert (
        client.get(
            headers={
                "Host": "localhost",
                "x-blah": "test",
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers case insensitive'


def test_routes_match_headers_invalid():
    route_match_invalid({"headers": ["blah"]})
    route_match_invalid({"headers": {"foo": ["bar", {}]}})
    route_match_invalid({"headers": {"": "blah"}})


def test_routes_match_headers_empty_rule():
    route_match({"headers": {"host": ""}})

    assert client.get()['status'] == 404, 'localhost'
    host('', 200)


def test_routes_match_headers_empty():
    route_match({"headers": {}})
    assert client.get()['status'] == 200, 'empty'

    route_match({"headers": []})
    assert client.get()['status'] == 200, 'empty 2'


def test_routes_match_headers_rule_array_empty():
    route_match({"headers": {"blah": []}})

    assert client.get()['status'] == 404, 'array empty'
    assert (
        client.get(
            headers={
                "Host": "localhost",
                "blah": "foo",
                "Connection": "close",
            }
        )['status']
        == 200
    ), 'match headers rule array empty 2'


def test_routes_match_headers_array():
    route_match(
        {
            "headers": [
                {"x-header1": "foo*"},
                {"x-header2": "bar"},
                {"x-header3": ["foo", "bar"]},
                {"x-header1": "bar", "x-header4": "foo"},
            ]
        }
    )

    def check_headers(hds):
        hds = dict({"Host": "localhost", "Connection": "close"}, **hds)
        assert client.get(headers=hds)['status'] == 200, 'headers array match'

    def check_headers_404(hds):
        hds = dict({"Host": "localhost", "Connection": "close"}, **hds)
        assert (
            client.get(headers=hds)['status'] == 404
        ), 'headers array no match'

    assert client.get()['status'] == 404, 'match headers array'
    check_headers({"x-header1": "foo123"})
    check_headers({"x-header2": "bar"})
    check_headers({"x-header3": "bar"})
    check_headers_404({"x-header1": "bar"})
    check_headers({"x-header1": "bar", "x-header4": "foo"})

    assert 'success' in client.conf_delete(
        'routes/0/match/headers/1'
    ), 'match headers array configure 2'

    check_headers_404({"x-header2": "bar"})
    check_headers({"x-header3": "foo"})


def test_routes_match_arguments():
    route_match({"arguments": {"foo": "bar"}})

    assert client.get()['status'] == 404, 'args'
    assert client.get(url='/?foo=bar')['status'] == 200, 'args 2'
    assert client.get(url='/?foo=bar1')['status'] == 404, 'args 3'
    assert client.get(url='/?1foo=bar')['status'] == 404, 'args 4'
    assert client.get(url='/?Foo=bar')['status'] == 404, 'case'
    assert client.get(url='/?foo=Bar')['status'] == 404, 'case 2'


def test_routes_match_arguments_chars():
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
            chars_enc += f'%{h1}{h2}'
    chars_enc = chars_enc[:-3]

    def check_args(args, query):
        route_match({"arguments": args})
        assert client.get(url=f'/?{query}')['status'] == 200

    check_args({chars: chars}, f'{chars}={chars}')
    check_args({chars: chars}, f'{chars}={chars_enc}')
    check_args({chars: chars}, f'{chars_enc}={chars}')
    check_args({chars: chars}, f'{chars_enc}={chars_enc}')
    check_args({chars_enc: chars_enc}, f'{chars}={chars}')
    check_args({chars_enc: chars_enc}, f'{chars}={chars_enc}')
    check_args({chars_enc: chars_enc}, f'{chars_enc}={chars}')
    check_args({chars_enc: chars_enc}, f'{chars_enc}={chars_enc}')


def test_routes_match_arguments_empty():
    route_match({"arguments": {}})
    assert client.get()['status'] == 200, 'arguments empty'

    route_match({"arguments": []})
    assert client.get()['status'] == 200, 'arguments empty 2'


def test_routes_match_arguments_space():
    route_match({"arguments": {"+fo o%20": "%20b+a r"}})
    assert client.get(url='/? fo o = b a r&')['status'] == 200
    assert client.get(url='/?+fo+o+=+b+a+r&')['status'] == 200
    assert client.get(url='/?%20fo%20o%20=%20b%20a%20r&')['status'] == 200

    route_match({"arguments": {"%20foo": " bar"}})
    assert client.get(url='/? foo= bar')['status'] == 200
    assert client.get(url='/?+foo=+bar')['status'] == 200
    assert client.get(url='/?%20foo=%20bar')['status'] == 200
    assert client.get(url='/?+foo= bar')['status'] == 200
    assert client.get(url='/?%20foo=+bar')['status'] == 200


def test_routes_match_arguments_equal():
    route_match({"arguments": {"=": "="}})
    assert client.get(url='/?%3D=%3D')['status'] == 200
    assert client.get(url='/?%3D==')['status'] == 200
    assert client.get(url='/?===')['status'] == 404
    assert client.get(url='/?%3D%3D%3D')['status'] == 404
    assert client.get(url='/?==%3D')['status'] == 404


def test_routes_match_arguments_enc():
    route_match({"arguments": {"Ю": "н"}})
    assert client.get(url='/?%D0%AE=%D0%BD')['status'] == 200
    assert client.get(url='/?%d0%ae=%d0%Bd')['status'] == 200


def test_routes_match_arguments_hash():
    route_match({"arguments": {"#": "#"}})
    assert client.get(url='/?%23=%23')['status'] == 200
    assert client.get(url='/?%23=%23#')['status'] == 200
    assert client.get(url='/?#=#')['status'] == 404
    assert client.get(url='/?%23=#')['status'] == 404


def test_routes_match_arguments_wildcard():
    route_match({"arguments": {"foo": "*"}})
    assert client.get(url='/?foo')['status'] == 200
    assert client.get(url='/?foo=')['status'] == 200
    assert client.get(url='/?foo=blah')['status'] == 200
    assert client.get(url='/?blah=foo')['status'] == 404

    route_match({"arguments": {"foo": "%25*"}})
    assert client.get(url='/?foo=%xx')['status'] == 200

    route_match({"arguments": {"foo": "%2A*"}})
    assert client.get(url='/?foo=*xx')['status'] == 200
    assert client.get(url='/?foo=xx')['status'] == 404

    route_match({"arguments": {"foo": "*%2A"}})
    assert client.get(url='/?foo=xx*')['status'] == 200
    assert client.get(url='/?foo=xx*x')['status'] == 404

    route_match({"arguments": {"foo": "1*2"}})
    assert client.get(url='/?foo=12')['status'] == 200
    assert client.get(url='/?foo=1blah2')['status'] == 200
    assert client.get(url='/?foo=1%2A2')['status'] == 200
    assert client.get(url='/?foo=x12')['status'] == 404

    route_match({"arguments": {"foo": "bar*", "%25": "%25"}})
    assert client.get(url='/?foo=barxx&%=%')['status'] == 200
    assert client.get(url='/?foo=barxx&x%=%')['status'] == 404


def test_routes_match_arguments_negative():
    route_match({"arguments": {"foo": "!"}})
    assert client.get(url='/?bar')['status'] == 404
    assert client.get(url='/?foo')['status'] == 404
    assert client.get(url='/?foo=')['status'] == 404
    assert client.get(url='/?foo=%25')['status'] == 200

    route_match({"arguments": {"foo": "!*"}})
    assert client.get(url='/?bar')['status'] == 404
    assert client.get(url='/?foo')['status'] == 404
    assert client.get(url='/?foo=')['status'] == 404
    assert client.get(url='/?foo=blah')['status'] == 404

    route_match({"arguments": {"foo": "!%25"}})
    assert client.get(url='/?foo=blah')['status'] == 200
    assert client.get(url='/?foo=%')['status'] == 404

    route_match({"arguments": {"foo": "%21blah"}})
    assert client.get(url='/?foo=%21blah')['status'] == 200
    assert client.get(url='/?foo=!blah')['status'] == 200
    assert client.get(url='/?foo=bar')['status'] == 404

    route_match({"arguments": {"foo": "!!%21*a"}})
    assert client.get(url='/?foo=blah')['status'] == 200
    assert client.get(url='/?foo=!blah')['status'] == 200
    assert client.get(url='/?foo=!!a')['status'] == 404
    assert client.get(url='/?foo=!!bla')['status'] == 404


def test_routes_match_arguments_percent():
    route_match({"arguments": {"%25": "%25"}})
    assert client.get(url='/?%=%')['status'] == 200
    assert client.get(url='/?%25=%25')['status'] == 200
    assert client.get(url='/?%25=%')['status'] == 200

    route_match({"arguments": {"%251": "%252"}})
    assert client.get(url='/?%1=%2')['status'] == 200
    assert client.get(url='/?%251=%252')['status'] == 200
    assert client.get(url='/?%251=%2')['status'] == 200

    route_match({"arguments": {"%25%21%251": "%25%24%252"}})
    assert client.get(url='/?%!%1=%$%2')['status'] == 200
    assert client.get(url='/?%25!%251=%25$%252')['status'] == 200
    assert client.get(url='/?%25!%1=%$%2')['status'] == 200


def test_routes_match_arguments_ampersand():
    route_match({"arguments": {"foo": "&"}})
    assert client.get(url='/?foo=%26')['status'] == 200
    assert client.get(url='/?foo=%26&')['status'] == 200
    assert client.get(url='/?foo=%26%26')['status'] == 404
    assert client.get(url='/?foo=&')['status'] == 404

    route_match({"arguments": {"&": ""}})
    assert client.get(url='/?%26=')['status'] == 200
    assert client.get(url='/?%26=&')['status'] == 200
    assert client.get(url='/?%26=%26')['status'] == 404
    assert client.get(url='/?&=')['status'] == 404


def test_routes_match_arguments_complex():
    route_match({"arguments": {"foo": ""}})

    assert client.get(url='/?foo')['status'] == 200, 'complex'
    assert client.get(url='/?blah=blah&foo=')['status'] == 200, 'complex 2'
    assert client.get(url='/?&&&foo&&&')['status'] == 200, 'complex 3'
    assert client.get(url='/?foo&foo=bar&foo')['status'] == 404, 'complex 4'
    assert client.get(url='/?foo=&foo')['status'] == 200, 'complex 5'
    assert client.get(url='/?&=&foo&==&')['status'] == 200, 'complex 6'
    assert client.get(url='/?&=&bar&==&')['status'] == 404, 'complex 7'


def test_routes_match_arguments_multiple():
    route_match({"arguments": {"foo": "bar", "blah": "test"}})

    assert client.get()['status'] == 404, 'multiple'
    assert client.get(url='/?foo=bar&blah=test')['status'] == 200, 'multiple 2'
    assert client.get(url='/?foo=bar&blah')['status'] == 404, 'multiple 3'
    assert client.get(url='/?foo=bar&blah=tes')['status'] == 404, 'multiple 4'
    assert (
        client.get(url='/?foo=b%61r&bl%61h=t%65st')['status'] == 200
    ), 'multiple 5'


def test_routes_match_arguments_multiple_rules():
    route_match({"arguments": {"foo": ["bar", "blah"]}})

    assert client.get()['status'] == 404, 'rules'
    assert client.get(url='/?foo=bar')['status'] == 200, 'rules 2'
    assert client.get(url='/?foo=blah')['status'] == 200, 'rules 3'
    assert (
        client.get(url='/?foo=blah&foo=bar&foo=blah')['status'] == 200
    ), 'rules 4'
    assert client.get(url='/?foo=blah&foo=bar&foo=')['status'] == 404, 'rules 5'


def test_routes_match_arguments_array():
    route_match(
        {
            "arguments": [
                {"var1": "val1*"},
                {"var2": "val2"},
                {"var3": ["foo", "bar"]},
                {"var1": "bar", "var4": "foo"},
            ]
        }
    )

    assert client.get()['status'] == 404, 'arr'
    assert client.get(url='/?var1=val123')['status'] == 200, 'arr 2'
    assert client.get(url='/?var2=val2')['status'] == 200, 'arr 3'
    assert client.get(url='/?var3=bar')['status'] == 200, 'arr 4'
    assert client.get(url='/?var1=bar')['status'] == 404, 'arr 5'
    assert client.get(url='/?var1=bar&var4=foo')['status'] == 200, 'arr 6'

    assert 'success' in client.conf_delete(
        'routes/0/match/arguments/1'
    ), 'match arguments array configure 2'

    assert client.get(url='/?var2=val2')['status'] == 404, 'arr 7'
    assert client.get(url='/?var3=foo')['status'] == 200, 'arr 8'


def test_routes_match_arguments_invalid():
    route_match_invalid({"arguments": ["var"]})
    route_match_invalid({"arguments": [{"var1": {}}]})
    route_match_invalid({"arguments": {"": "bar"}})
    route_match_invalid({"arguments": {"foo": "%"}})
    route_match_invalid({"arguments": {"foo": "%1G"}})
    route_match_invalid({"arguments": {"%": "bar"}})
    route_match_invalid({"arguments": {"foo": "%0"}})
    route_match_invalid({"arguments": {"foo": "%%1F"}})
    route_match_invalid({"arguments": {"%%1F": ""}})
    route_match_invalid({"arguments": {"%7%F": ""}})


def test_routes_match_query():
    route_match({"query": "!"})
    assert client.get(url='/')['status'] == 404
    assert client.get(url='/?')['status'] == 404
    assert client.get(url='/?foo')['status'] == 200
    assert client.get(url='/?foo=')['status'] == 200
    assert client.get(url='/?foo=baz')['status'] == 200

    route_match({"query": "foo=%26"})
    assert client.get(url='/?foo=&')['status'] == 200

    route_match({"query": "a=b&c=d"})
    assert client.get(url='/?a=b&c=d')['status'] == 200

    route_match({"query": "a=b%26c%3Dd"})
    assert client.get(url='/?a=b%26c%3Dd')['status'] == 200
    assert client.get(url='/?a=b&c=d')['status'] == 200

    route_match({"query": "a=b%26c%3Dd+e"})
    assert client.get(url='/?a=b&c=d e')['status'] == 200


def test_routes_match_query_array():
    route_match({"query": ["foo", "bar"]})

    assert client.get()['status'] == 404, 'no args'
    assert client.get(url='/?foo')['status'] == 200, 'arg first'
    assert client.get(url='/?bar')['status'] == 200, 'arg second'

    assert 'success' in client.conf_delete(
        'routes/0/match/query/1'
    ), 'query array remove second'

    assert client.get(url='/?foo')['status'] == 200, 'still arg first'
    assert client.get(url='/?bar')['status'] == 404, 'no arg second'

    route_match({"query": ["!f", "foo"]})

    assert client.get(url='/?f')['status'] == 404, 'negative arg'
    assert client.get(url='/?fo')['status'] == 404, 'negative arg 2'
    assert client.get(url='/?foo')['status'] == 200, 'negative arg 3'

    route_match({"query": []})
    assert client.get()['status'] == 200, 'empty array'


def test_routes_match_query_invalid():
    route_match_invalid({"query": [1]})
    route_match_invalid({"query": "%"})
    route_match_invalid({"query": "%1G"})
    route_match_invalid({"query": "%0"})
    route_match_invalid({"query": "%%1F"})
    route_match_invalid({"query": ["foo", "%3D", "%%1F"]})


def test_routes_match_cookies():
    route_match({"cookies": {"foO": "bar"}})

    assert client.get()['status'] == 404, 'cookie'
    cookie('foO=bar', 200)
    cookie('foO=bar;1', 200)
    cookie(['foO=bar', 'blah=blah'], 200)
    cookie('foO=bar; blah=blah', 200)
    cookie('Foo=bar', 404)
    cookie('foO=Bar', 404)
    cookie('foO=bar1', 404)
    cookie('1foO=bar;', 404)


def test_routes_match_cookies_empty():
    route_match({"cookies": {}})
    assert client.get()['status'] == 200, 'cookies empty'

    route_match({"cookies": []})
    assert client.get()['status'] == 200, 'cookies empty 2'


def test_routes_match_cookies_invalid():
    route_match_invalid({"cookies": ["var"]})
    route_match_invalid({"cookies": [{"foo": {}}]})


def test_routes_match_cookies_complex():
    route_match({"cookies": {"foo": "bar=baz"}})
    cookie('foo=bar=baz', 200)
    cookie('   foo=bar=baz   ', 200)
    cookie('=foo=bar=baz', 404)

    route_match({"cookies": {"foo": ""}})
    cookie('foo=', 200)
    cookie('foo=;', 200)
    cookie('  foo=;', 200)
    cookie('foo', 404)
    cookie('', 404)
    cookie('=', 404)


def test_routes_match_cookies_multiple():
    route_match({"cookies": {"foo": "bar", "blah": "blah"}})

    assert client.get()['status'] == 404, 'multiple'
    cookie('foo=bar; blah=blah', 200)
    cookie(['foo=bar', 'blah=blah'], 200)
    cookie(['foo=bar; blah', 'blah'], 404)
    cookie(['foo=bar; blah=test', 'blah=blah'], 404)


def test_routes_match_cookies_multiple_values():
    route_match({"cookies": {"blah": "blah"}})

    cookie(['blah=blah', 'blah=blah', 'blah=blah'], 200)
    cookie(['blah=blah', 'blah=test', 'blah=blah'], 404)
    cookie(['blah=blah; blah=', 'blah=blah'], 404)


def test_routes_match_cookies_multiple_rules():
    route_match({"cookies": {"blah": ["test", "blah"]}})

    assert client.get()['status'] == 404, 'multiple rules'
    cookie('blah=test', 200)
    cookie('blah=blah', 200)
    cookie(['blah=blah', 'blah=test', 'blah=blah'], 200)
    cookie(['blah=blah; blah=test', 'blah=blah'], 200)
    cookie(['blah=blah', 'blah'], 200)  # invalid cookie


def test_routes_match_cookies_array():
    route_match(
        {
            "cookies": [
                {"var1": "val1*"},
                {"var2": "val2"},
                {"var3": ["foo", "bar"]},
                {"var1": "bar", "var4": "foo"},
            ]
        }
    )

    assert client.get()['status'] == 404, 'cookies array'
    cookie('var1=val123', 200)
    cookie('var2=val2', 200)
    cookie(' var2=val2 ', 200)
    cookie('var3=bar', 200)
    cookie('var3=bar;', 200)
    cookie('var1=bar', 404)
    cookie('var1=bar; var4=foo;', 200)
    cookie(['var1=bar', 'var4=foo'], 200)

    assert 'success' in client.conf_delete(
        'routes/0/match/cookies/1'
    ), 'match cookies array configure 2'

    cookie('var2=val2', 404)
    cookie('var3=foo', 200)


def test_routes_match_scheme():
    route_match({"scheme": "http"})
    route_match({"scheme": "https"})
    route_match({"scheme": "HtTp"})
    route_match({"scheme": "HtTpS"})


def test_routes_match_scheme_invalid():
    route_match_invalid({"scheme": ["http"]})
    route_match_invalid({"scheme": "ftp"})
    route_match_invalid({"scheme": "ws"})
    route_match_invalid({"scheme": "*"})
    route_match_invalid({"scheme": ""})


def test_routes_source_port():
    def sock_port():
        sock = client.http(b'', raw=True, no_recv=True)
        port = sock.getsockname()[1]
        return (sock, port)

    sock, port = sock_port()
    sock2, _ = sock_port()

    route_match({"source": f'127.0.0.1:{port}'})
    assert client.get(sock=sock)['status'] == 200, 'exact'
    assert client.get(sock=sock2)['status'] == 404, 'exact 2'

    sock, port = sock_port()
    sock2, _ = sock_port()

    route_match({"source": f'!127.0.0.1:{port}'})
    assert client.get(sock=sock)['status'] == 404, 'negative'
    assert client.get(sock=sock2)['status'] == 200, 'negative 2'

    sock, port = sock_port()
    sock2, _ = sock_port()

    route_match({"source": [f'*:{port}', "!127.0.0.1"]})
    assert client.get(sock=sock)['status'] == 404, 'negative 3'
    assert client.get(sock=sock2)['status'] == 404, 'negative 4'

    sock, port = sock_port()
    sock2, _ = sock_port()

    route_match({"source": f'127.0.0.1:{port}-{port}'})
    assert client.get(sock=sock)['status'] == 200, 'range single'
    assert client.get(sock=sock2)['status'] == 404, 'range single 2'

    socks = [
        sock_port(),
        sock_port(),
        sock_port(),
        sock_port(),
        sock_port(),
    ]
    socks.sort(key=lambda sock: sock[1])

    route_match({"source": f'127.0.0.1:{socks[1][1]}-{socks[3][1]}'})
    assert client.get(sock=socks[0][0])['status'] == 404, 'range'
    assert client.get(sock=socks[1][0])['status'] == 200, 'range 2'
    assert client.get(sock=socks[2][0])['status'] == 200, 'range 3'
    assert client.get(sock=socks[3][0])['status'] == 200, 'range 4'
    assert client.get(sock=socks[4][0])['status'] == 404, 'range 5'

    socks = [
        sock_port(),
        sock_port(),
        sock_port(),
    ]
    socks.sort(key=lambda sock: sock[1])

    route_match(
        {
            "source": [
                f'127.0.0.1:{socks[0][1]}',
                f'127.0.0.1:{socks[2][1]}',
            ]
        }
    )
    assert client.get(sock=socks[0][0])['status'] == 200, 'array'
    assert client.get(sock=socks[1][0])['status'] == 404, 'array 2'
    assert client.get(sock=socks[2][0])['status'] == 200, 'array 3'


def test_routes_source_addr():
    assert 'success' in client.conf(
        {
            "*:8080": {"pass": "routes"},
            "[::1]:8081": {"pass": "routes"},
        },
        'listeners',
    ), 'source listeners configure'

    def get_ipv6():
        return client.get(sock_type='ipv6', port=8081)

    route_match({"source": "127.0.0.1"})
    assert client.get()['status'] == 200, 'exact'
    assert get_ipv6()['status'] == 404, 'exact ipv6'

    route_match({"source": ["127.0.0.1"]})
    assert client.get()['status'] == 200, 'exact 2'
    assert get_ipv6()['status'] == 404, 'exact 2 ipv6'

    route_match({"source": "!127.0.0.1"})
    assert client.get()['status'] == 404, 'exact neg'
    assert get_ipv6()['status'] == 200, 'exact neg ipv6'

    route_match({"source": "127.0.0.2"})
    assert client.get()['status'] == 404, 'exact 3'
    assert get_ipv6()['status'] == 404, 'exact 3 ipv6'

    route_match({"source": "127.0.0.1-127.0.0.1"})
    assert client.get()['status'] == 200, 'range single'
    assert get_ipv6()['status'] == 404, 'range single ipv6'

    route_match({"source": "127.0.0.2-127.0.0.2"})
    assert client.get()['status'] == 404, 'range single 2'
    assert get_ipv6()['status'] == 404, 'range single 2 ipv6'

    route_match({"source": "127.0.0.2-127.0.0.3"})
    assert client.get()['status'] == 404, 'range'
    assert get_ipv6()['status'] == 404, 'range ipv6'

    route_match({"source": "127.0.0.1-127.0.0.2"})
    assert client.get()['status'] == 200, 'range 2'
    assert get_ipv6()['status'] == 404, 'range 2 ipv6'

    route_match({"source": "127.0.0.0-127.0.0.2"})
    assert client.get()['status'] == 200, 'range 3'
    assert get_ipv6()['status'] == 404, 'range 3 ipv6'

    route_match({"source": "127.0.0.0-127.0.0.1"})
    assert client.get()['status'] == 200, 'range 4'
    assert get_ipv6()['status'] == 404, 'range 4 ipv6'

    route_match({"source": "126.0.0.0-127.0.0.0"})
    assert client.get()['status'] == 404, 'range 5'
    assert get_ipv6()['status'] == 404, 'range 5 ipv6'

    route_match({"source": "126.126.126.126-127.0.0.2"})
    assert client.get()['status'] == 200, 'range 6'
    assert get_ipv6()['status'] == 404, 'range 6 ipv6'


def test_routes_source_ipv6():
    assert 'success' in client.conf(
        {
            "[::1]:8080": {"pass": "routes"},
            "127.0.0.1:8081": {"pass": "routes"},
        },
        'listeners',
    ), 'source listeners configure'

    route_match({"source": "::1"})
    assert client.get(sock_type='ipv6')['status'] == 200, 'exact'
    assert client.get(port=8081)['status'] == 404, 'exact ipv4'

    route_match({"source": ["::1"]})
    assert client.get(sock_type='ipv6')['status'] == 200, 'exact 2'
    assert client.get(port=8081)['status'] == 404, 'exact 2 ipv4'

    route_match({"source": "!::1"})
    assert client.get(sock_type='ipv6')['status'] == 404, 'exact neg'
    assert client.get(port=8081)['status'] == 200, 'exact neg ipv4'

    route_match({"source": "::2"})
    assert client.get(sock_type='ipv6')['status'] == 404, 'exact 3'
    assert client.get(port=8081)['status'] == 404, 'exact 3 ipv4'

    route_match({"source": "::1-::1"})
    assert client.get(sock_type='ipv6')['status'] == 200, 'range'
    assert client.get(port=8081)['status'] == 404, 'range ipv4'

    route_match({"source": "::2-::2"})
    assert client.get(sock_type='ipv6')['status'] == 404, 'range 2'
    assert client.get(port=8081)['status'] == 404, 'range 2 ipv4'

    route_match({"source": "::2-::3"})
    assert client.get(sock_type='ipv6')['status'] == 404, 'range 3'
    assert client.get(port=8081)['status'] == 404, 'range 3 ipv4'

    route_match({"source": "::1-::2"})
    assert client.get(sock_type='ipv6')['status'] == 200, 'range 4'
    assert client.get(port=8081)['status'] == 404, 'range 4 ipv4'

    route_match({"source": "::0-::2"})
    assert client.get(sock_type='ipv6')['status'] == 200, 'range 5'
    assert client.get(port=8081)['status'] == 404, 'range 5 ipv4'

    route_match({"source": "::0-::1"})
    assert client.get(sock_type='ipv6')['status'] == 200, 'range 6'
    assert client.get(port=8081)['status'] == 404, 'range 6 ipv4'


def test_routes_source_cidr():
    assert 'success' in client.conf(
        {
            "*:8080": {"pass": "routes"},
            "[::1]:8081": {"pass": "routes"},
        },
        'listeners',
    ), 'source listeners configure'

    def get_ipv6():
        return client.get(sock_type='ipv6', port=8081)

    route_match({"source": "127.0.0.1/32"})
    assert client.get()['status'] == 200, '32'
    assert get_ipv6()['status'] == 404, '32 ipv6'

    route_match({"source": "127.0.0.0/32"})
    assert client.get()['status'] == 404, '32 2'
    assert get_ipv6()['status'] == 404, '32 2 ipv6'

    route_match({"source": "127.0.0.0/31"})
    assert client.get()['status'] == 200, '31'
    assert get_ipv6()['status'] == 404, '31 ipv6'

    route_match({"source": "0.0.0.0/1"})
    assert client.get()['status'] == 200, '1'
    assert get_ipv6()['status'] == 404, '1 ipv6'

    route_match({"source": "0.0.0.0/0"})
    assert client.get()['status'] == 200, '0'
    assert get_ipv6()['status'] == 404, '0 ipv6'


def test_routes_source_cidr_ipv6():
    assert 'success' in client.conf(
        {
            "[::1]:8080": {"pass": "routes"},
            "127.0.0.1:8081": {"pass": "routes"},
        },
        'listeners',
    ), 'source listeners configure'

    route_match({"source": "::1/128"})
    assert client.get(sock_type='ipv6')['status'] == 200, '128'
    assert client.get(port=8081)['status'] == 404, '128 ipv4'

    route_match({"source": "::0/128"})
    assert client.get(sock_type='ipv6')['status'] == 404, '128 2'
    assert client.get(port=8081)['status'] == 404, '128 ipv4'

    route_match({"source": "::0/127"})
    assert client.get(sock_type='ipv6')['status'] == 200, '127'
    assert client.get(port=8081)['status'] == 404, '127 ipv4'

    route_match({"source": "::0/32"})
    assert client.get(sock_type='ipv6')['status'] == 200, '32'
    assert client.get(port=8081)['status'] == 404, '32 ipv4'

    route_match({"source": "::0/1"})
    assert client.get(sock_type='ipv6')['status'] == 200, '1'
    assert client.get(port=8081)['status'] == 404, '1 ipv4'

    route_match({"source": "::/0"})
    assert client.get(sock_type='ipv6')['status'] == 200, '0'
    assert client.get(port=8081)['status'] == 404, '0 ipv4'


def test_routes_source_unix(temp_dir):
    addr = f'{temp_dir}/sock'

    assert 'success' in client.conf(
        {
            "127.0.0.1:8081": {"pass": "routes"},
            f'unix:{addr}': {"pass": "routes"},
        },
        'listeners',
    ), 'source listeners configure'

    route_match({"source": "!0.0.0.0/0"})
    assert (
        client.get(sock_type='unix', addr=addr)['status'] == 200
    ), 'unix ipv4 neg'

    route_match({"source": "!::/0"})
    assert (
        client.get(sock_type='unix', addr=addr)['status'] == 200
    ), 'unix ipv6 neg'

    route_match({"source": "unix"})
    assert client.get(port=8081)['status'] == 404, 'unix ipv4'
    assert client.get(sock_type='unix', addr=addr)['status'] == 200, 'unix'


def test_routes_match_source():
    route_match({"source": "::"})
    route_match(
        {
            "source": [
                "127.0.0.1",
                "192.168.0.10:8080",
                "192.168.0.11:8080-8090",
            ]
        }
    )
    route_match(
        {
            "source": [
                "10.0.0.0/8",
                "10.0.0.0/7:1000",
                "10.0.0.0/32:8080-8090",
            ]
        }
    )
    route_match(
        {
            "source": [
                "10.0.0.0-10.0.0.1",
                "10.0.0.0-11.0.0.0:1000",
                "127.0.0.0-127.0.0.255:8080-8090",
            ]
        }
    )
    route_match({"source": ["2001::", "[2002::]:8000", "[2003::]:8080-8090"]})
    route_match(
        {
            "source": [
                "2001::-200f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "[fe08::-feff::]:8000",
                "[fff0::-fff0::10]:8080-8090",
            ]
        }
    )
    route_match(
        {
            "source": [
                "2001::/16",
                "[0ff::/64]:8000",
                "[fff0:abcd:ffff:ffff:ffff::/128]:8080-8090",
            ]
        }
    )
    route_match({"source": "*:0-65535"})
    assert client.get()['status'] == 200, 'source any'


def test_routes_match_source_invalid():
    route_match_invalid({"source": "127"})
    route_match_invalid({"source": "256.0.0.1"})
    route_match_invalid({"source": "127.0.0."})
    route_match_invalid({"source": " 127.0.0.1"})
    route_match_invalid({"source": "127.0.0.1:"})
    route_match_invalid({"source": "127.0.0.1/"})
    route_match_invalid({"source": "11.0.0.0/33"})
    route_match_invalid({"source": "11.0.0.0/65536"})
    route_match_invalid({"source": "11.0.0.0-10.0.0.0"})
    route_match_invalid({"source": "11.0.0.0:3000-2000"})
    route_match_invalid({"source": ["11.0.0.0:3000-2000"]})
    route_match_invalid({"source": "[2001::]:3000-2000"})
    route_match_invalid({"source": "2001::-2000::"})
    route_match_invalid({"source": "2001::/129"})
    route_match_invalid({"source": "::FFFFF"})
    route_match_invalid({"source": "[::1]:"})
    route_match_invalid({"source": "[:::]:8080"})
    route_match_invalid({"source": "*:"})
    route_match_invalid({"source": "*:1-a"})
    route_match_invalid({"source": "*:65536"})


def test_routes_match_source_none():
    route_match({"source": []})
    assert client.get()['status'] == 404, 'source none'


def test_routes_match_destination():
    assert 'success' in client.conf(
        {"*:8080": {"pass": "routes"}, "*:8081": {"pass": "routes"}},
        'listeners',
    ), 'listeners configure'

    route_match({"destination": "*:8080"})
    assert client.get()['status'] == 200, 'dest'
    assert client.get(port=8081)['status'] == 404, 'dest 2'

    route_match({"destination": ["127.0.0.1:8080"]})
    assert client.get()['status'] == 200, 'dest 3'
    assert client.get(port=8081)['status'] == 404, 'dest 4'

    route_match({"destination": "!*:8080"})
    assert client.get()['status'] == 404, 'dest neg'
    assert client.get(port=8081)['status'] == 200, 'dest neg 2'

    route_match({"destination": ['!*:8080', '!*:8081']})
    assert client.get()['status'] == 404, 'dest neg 3'
    assert client.get(port=8081)['status'] == 404, 'dest neg 4'

    route_match({"destination": ['!*:8081', '!*:8082']})
    assert client.get()['status'] == 200, 'dest neg 5'

    route_match({"destination": ['*:8080', '!*:8080']})
    assert client.get()['status'] == 404, 'dest neg 6'

    route_match({"destination": ['127.0.0.1:8080', '*:8081', '!*:8080']})
    assert client.get()['status'] == 404, 'dest neg 7'
    assert client.get(port=8081)['status'] == 200, 'dest neg 8'

    route_match({"destination": ['!*:8081', '!*:8082', '*:8083']})
    assert client.get()['status'] == 404, 'dest neg 9'

    route_match({"destination": ['*:8081', '!127.0.0.1:8080', '*:8080']})
    assert client.get()['status'] == 404, 'dest neg 10'
    assert client.get(port=8081)['status'] == 200, 'dest neg 11'

    assert 'success' in client.conf_delete(
        'routes/0/match/destination/0'
    ), 'remove destination rule'
    assert client.get()['status'] == 404, 'dest neg 12'
    assert client.get(port=8081)['status'] == 404, 'dest neg 13'

    assert 'success' in client.conf_delete(
        'routes/0/match/destination/0'
    ), 'remove destination rule 2'
    assert client.get()['status'] == 200, 'dest neg 14'
    assert client.get(port=8081)['status'] == 404, 'dest neg 15'

    assert 'success' in client.conf_post(
        "\"!127.0.0.1\"", 'routes/0/match/destination'
    ), 'add destination rule'
    assert client.get()['status'] == 404, 'dest neg 16'
    assert client.get(port=8081)['status'] == 404, 'dest neg 17'


def test_routes_match_destination_proxy():
    assert 'success' in client.conf(
        {
            "listeners": {
                "*:8080": {"pass": "routes/first"},
                "*:8081": {"pass": "routes/second"},
            },
            "routes": {
                "first": [{"action": {"proxy": "http://127.0.0.1:8081"}}],
                "second": [
                    {
                        "match": {"destination": ["127.0.0.1:8081"]},
                        "action": {"return": 200},
                    }
                ],
            },
            "applications": {},
        }
    ), 'proxy configure'

    assert client.get()['status'] == 200, 'proxy'
