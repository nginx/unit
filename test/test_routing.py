import unittest
import unit

class TestUnitRouting(unit.TestUnitApplicationProto):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def setUp(self):
        super().setUp()

        self.conf({
            "listeners": {
                "*:7080": {
                    "pass": "routes"
                }
            },
            "routes": [{
                "match": { "method": "GET" },
                "action": { "pass": "applications/empty" }
            }],
            "applications": {
                "empty": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/empty',
                    "working_directory": self.current_dir + '/python/empty',
                    "module": "wsgi"
                },
                "mirror": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/mirror',
                    "working_directory": self.current_dir + '/python/mirror',
                    "module": "wsgi"
                }
            }
        })

    def test_routes_match_method_positive(self):
        self.assertEqual(self.get()['status'], 200, 'method positive GET')
        self.assertEqual(self.post()['status'], 404, 'method positive POST')

    def test_routes_match_method_positive_many(self):
        self.assertIn('success', self.conf([{
            "match": { "method": ["GET", "POST"] },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method positive many configure')

        self.assertEqual(self.get()['status'], 200, 'method positive many GET')
        self.assertEqual(self.post()['status'], 200,
            'method positive many POST')
        self.assertEqual(self.delete()['status'], 404,
            'method positive many DELETE')

    def test_routes_match_method_negative(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "!GET" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method negative configure')

        self.assertEqual(self.get()['status'], 404, 'method negative GET')
        self.assertEqual(self.post()['status'], 200, 'method negative POST')

    def test_routes_match_method_negative_many(self):
        self.assertIn('success', self.conf([{
            "match": { "method": ["!GET", "!POST"] },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method negative many configure')

        self.assertEqual(self.get()['status'], 404, 'method negative many GET')
        self.assertEqual(self.post()['status'], 404,
            'method negative many POST')
        self.assertEqual(self.delete()['status'], 200,
            'method negative many DELETE')

    def test_routes_match_method_wildcard_left(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "*ET" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method wildcard left configure')

        self.assertEqual(self.get()['status'], 200, 'method wildcard left GET')
        self.assertEqual(self.post()['status'], 404,
            'method wildcard left POST')

    def test_routes_match_method_wildcard_right(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "GE*" },
            "action": { "pass": "applications/empty"}
        }], 'routes'), 'method wildcard right configure')

        self.assertEqual(self.get()['status'], 200,
            'method wildcard right GET')
        self.assertEqual(self.post()['status'], 404,
            'method wildcard right POST')

    def test_routes_match_method_wildcard_left_right(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "*GET*" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method wildcard left right configure')

        self.assertEqual(self.get()['status'], 200,
            'method wildcard right GET')
        self.assertEqual(self.post()['status'], 404,
            'method wildcard right POST')

    def test_routes_match_method_wildcard(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "*" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method wildcard configure')

        self.assertEqual(self.get()['status'], 200, 'method wildcard')

    def test_routes_match_method_case_insensitive(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "get" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'method case insensitive configure')

        self.assertEqual(self.get()['status'], 200, 'method case insensitive')

    def test_routes_absent(self):
        self.conf({
            "listeners": {
                "*:7081": {
                    "pass": "applications/empty"
                }
            },
            "applications": {
                "empty": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/empty',
                    "working_directory": self.current_dir + '/python/empty',
                    "module": "wsgi"
                }
            }
        })

        self.assertEqual(self.get(port=7081)['status'], 200, 'routes absent')

    def test_routes_pass_invalid(self):
        self.assertIn('error', self.conf({ "pass": "routes/blah" },
            'listeners/*:7080'), 'routes invalid')

    def test_route_empty(self):
        self.assertIn('success', self.conf({
            "listeners": {
                "*:7080": {
                    "pass": "routes/main"
                }
            },
            "routes": {"main": []},
            "applications": {
                "empty": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/empty',
                    "working_directory": self.current_dir + '/python/empty',
                    "module": "wsgi"
                },
                "mirror": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/mirror',
                    "working_directory": self.current_dir + '/python/mirror',
                    "module": "wsgi"
                }
            }
        }), 'route empty configure')

        self.assertEqual(self.get()['status'], 404, 'route empty')

    def test_routes_route_empty(self):
        self.assertIn('success', self.conf({}, 'listeners'),
            'routes empty listeners configure')

        self.assertIn('success', self.conf({}, 'routes'),
            'routes empty configure')

    def test_routes_route_match_absent(self):
        self.assertIn('success', self.conf([{
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'route match absent configure')

        self.assertEqual(self.get()['status'], 200, 'route match absent')

    def test_routes_route_action_absent(self):
        self.skip_alerts.append(r'failed to apply new conf')

        self.assertIn('error', self.conf([{
            "match": { "method": "GET" }
        }], 'routes'), 'route pass absent configure')

    def test_routes_route_pass_absent(self):
        self.skip_alerts.append(r'failed to apply new conf')

        self.assertIn('error', self.conf([{
            "match": { "method": "GET" },
            "action": {}
        }], 'routes'), 'route pass absent configure')

    def test_routes_rules_two(self):
        self.assertIn('success', self.conf([{
            "match": { "method": "GET" },
            "action": { "pass": "applications/empty" }
        },
        {
            "match": { "method": "POST" },
            "action": { "pass": "applications/mirror" }
        }], 'routes'), 'rules two configure')

        self.assertEqual(self.get()['status'], 200, 'rules two match first')
        self.assertEqual(self.post(headers={
            'Host': 'localhost',
            'Content-Type': 'text/html',
            'Connection': 'close'
        }, body='X')['status'], 200, 'rules two match second')

    def test_routes_two(self):
        self.assertIn('success', self.conf({
            "listeners": {
                "*:7080": {
                    "pass": "routes/first"
                }
            },
            "routes": {
                "first": [{
                    "match": { "method": "GET" },
                    "action": { "pass": "routes/second" }
                }],
                "second": [{
                    "match": { "host": "localhost" },
                    "action": { "pass": "applications/empty" }
                }],
            },
            "applications": {
                "empty": {
                    "type": "python",
                    "processes": { "spare": 0 },
                    "path": self.current_dir + '/python/empty',
                    "working_directory": self.current_dir + '/python/empty',
                    "module": "wsgi"
                }
            }
        }), 'routes two configure')

        self.assertEqual(self.get()['status'], 200, 'routes two')

    def test_routes_match_host_positive(self):
        self.assertIn('success', self.conf([{
            "match": { "host": "localhost" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host positive configure')

        self.assertEqual(self.get()['status'], 200,
            'match host positive localhost')

        self.assertEqual(self.get(headers={'Connection': 'close'})['status'],
            404, 'match host positive empty')

        self.assertEqual(self.get(headers={
            'Host': 'localhost.',
            'Connection': 'close'
        })['status'], 200, 'match host positive trailing dot')

        self.assertEqual(self.get(headers={
            'Host': 'www.localhost',
            'Connection': 'close'
        })['status'], 404, 'match host positive www.localhost')

        self.assertEqual(self.get(headers={
            'Host': 'localhost1',
            'Connection': 'close'
        })['status'], 404, 'match host positive localhost1')

        self.assertEqual(self.get(headers={
            'Host': 'example.com',
            'Connection': 'close'
        })['status'], 404, 'match host positive example.com')

    def test_routes_match_host_ipv4(self):
        self.assertIn('success', self.conf([{
            "match": { "host": "127.0.0.1" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host ipv4 configure')

        self.assertEqual(self.get(headers={
            'Host': '127.0.0.1',
            'Connection': 'close'
        })['status'], 200, 'match host ipv4')

    def test_routes_match_host_ipv6(self):
        self.assertIn('success', self.conf([{
            "match": { "host": "[::1]" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host ipv6 configure')

        self.assertEqual(self.get(headers={
            'Host': '[::1]',
            'Connection': 'close'
        })['status'], 200, 'match host ipv6')

        self.assertEqual(self.get(headers={
            'Host': '[::1]:7080',
            'Connection': 'close'
        })['status'], 200, 'match host ipv6 port')

    def test_routes_match_host_positive_many(self):
        self.assertIn('success', self.conf([{
            "match": { "host": ["localhost", "example.com"] },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host positive many configure')

        self.assertEqual(self.get()['status'], 200,
            'match host positive many localhost')

        self.assertEqual(self.get(headers={
            'Host': 'example.com',
            'Connection': 'close'
        })['status'], 200, 'match host positive many example.com')

    def test_routes_match_host_positive_and_negative(self):
        self.assertIn('success', self.conf([{
            "match": { "host": ["*example.com", "!www.example.com"] },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host positive and negative configure')

        self.assertEqual(self.get()['status'], 404,
            'match host positive and negative localhost')

        self.assertEqual(self.get(headers={
            'Host': 'example.com',
            'Connection': 'close'
        })['status'], 200, 'match host positive and negative example.com')

        self.assertEqual(self.get(headers={
            'Host': 'www.example.com',
            'Connection': 'close'
        })['status'], 404, 'match host positive and negative www.example.com')

        self.assertEqual(self.get(headers={
            'Host': '!www.example.com',
            'Connection': 'close'
        })['status'], 200, 'match host positive and negative !www.example.com')

    def test_routes_match_host_positive_and_negative_wildcard(self):
        self.assertIn('success', self.conf([{
            "match": { "host": ["*example*", "!www.example*"] },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host positive and negative wildcard configure')

        self.assertEqual(self.get(headers={
            'Host': 'example.com',
            'Connection': 'close'
        })['status'], 200,
            'match host positive and negative wildcard example.com')

        self.assertEqual(self.get(headers={
            'Host': 'www.example.com',
            'Connection': 'close'
        })['status'], 404,
            'match host positive and negative wildcard www.example.com')

    def test_routes_match_host_case_insensitive(self):
        self.assertIn('success', self.conf([{
            "match": { "host": "Example.com" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'host case insensitive configure')

        self.assertEqual(self.get(headers={
            'Host': 'example.com',
            'Connection': 'close'
        })['status'], 200, 'host case insensitive example.com')

        self.assertEqual(self.get(headers={
            'Host': 'EXAMPLE.COM',
            'Connection': 'close'
        })['status'], 200, 'host case insensitive EXAMPLE.COM')

    def test_routes_match_host_port(self):
        self.assertIn('success', self.conf([{
            "match": { "host": "example.com" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match host port configure')

        self.assertEqual(self.get(headers={
            'Host': 'example.com:7080',
            'Connection': 'close'
        })['status'], 200, 'match host port')

    def test_routes_match_uri_positive(self):
        self.assertIn('success', self.conf([{
            "match": { "uri": "/" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match uri positive configure')

        self.assertEqual(self.get()['status'], 200, 'match uri positive')
        self.assertEqual(self.get(url='/blah')['status'], 404,
            'match uri positive blah')
        self.assertEqual(self.get(url='/#blah')['status'], 200,
            'match uri positive #blah')
        self.assertEqual(self.get(url='/?var')['status'], 200,
            'match uri params')
        self.assertEqual(self.get(url='//')['status'], 200,
            'match uri adjacent slashes')
        self.assertEqual(self.get(url='/blah/../')['status'], 200,
            'match uri relative path')
        self.assertEqual(self.get(url='/./')['status'], 200,
            'match uri relative path')

    def test_routes_match_uri_case_sensitive(self):
        self.assertIn('success', self.conf([{
            "match": { "uri": "/BLAH" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match uri case sensitive configure')

        self.assertEqual(self.get(url='/blah')['status'], 404,
            'match uri case sensitive blah')
        self.assertEqual(self.get(url='/BlaH')['status'], 404,
            'match uri case sensitive BlaH')
        self.assertEqual(self.get(url='/BLAH')['status'], 200,
            'match uri case sensitive BLAH')

    def test_routes_match_uri_normalize(self):
        self.assertIn('success', self.conf([{
            "match": { "uri": "/blah" },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'match uri normalize configure')

        self.assertEqual(self.get(url='/%62%6c%61%68')['status'], 200,
            'match uri normalize')

    def test_routes_match_rules(self):
        self.assertIn('success', self.conf([{
            "match": {
                "method": "GET",
                "host": "localhost",
                "uri": "/"
            },
            "action": { "pass": "applications/empty" }
        }], 'routes'), 'routes match rules configure')

        self.assertEqual(self.get()['status'], 200, 'routes match rules')

    def test_routes_loop(self):
        self.assertIn('success', self.conf([{
            "match": { "uri": "/" },
            "action": { "pass": "routes" }
        }], 'routes'), 'routes loop configure')

        self.assertEqual(self.get()['status'], 500, 'routes loop')

if __name__ == '__main__':
    TestUnitRouting.main()
